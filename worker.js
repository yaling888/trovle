/**
// client: https://github.com/yaling888/clash
proxies:
  - name: cf-trojan-443
    type: trojan
    server: csgo.com
    port: 443
    password: 880426bb-1879-426d-85d7-5a597525be08
    sni: xx.xx // your CF Worker custom domain
    udp: false
    network: ws
    ws-opts:
      path: /

  - name: cf-vless-443
    type: vless
    server: csgo.com
    port: 443
    uuid: 880426bb-1879-426d-85d7-5a597525be08
    tls: true
    udp: false
    network: ws
    ws-opts:
      path: /api
      headers: { Host: xx.xx } // your CF Worker custom domain
*/

import { connect } from 'cloudflare:sockets';

const configs = {
    inbounds: [
        {
            type: 'trojan',
            // generate sha-224 hex password
            // use shell cmd: echo -n "your_password" | openssl dgst -sha224
            // or use online tools
            password: 'd5fd445e20906261ac83c17fc4e8faec760df05ca34cd66246951d6d', // change password before deploy worker
            path: '/',
        },
        {
            type: 'vless',
            // use online tools
            uuid: '880426bb-1879-426d-85d7-5a597525be08', // change uuid before deploy worker
            path: '/api',
        },
    ],
    debug: false,
};

export default {
    async fetch(request, env) {
        return handleRequest(request, env);
    }
}

async function handleRequest(request, env) {
    try {
        if (request.headers.get("Upgrade") !== "websocket") {
            return new Response("404 Not Found", { status: 404 });
        }
        return await handleWebSocket(request, env);
    } catch (err) {
        if (configs.debug) {
            console.log(err.stack);
        }
        return new Response("404 Not Found", { status: 404 });
    }
}

async function handleWebSocket(request, env) {
    const inbound = selectInbound(request.url);
    const pair = new WebSocketPair();
    const ws = streamifyWebSocket(pair[1]);
    const conn = createDestinationEndpoint(request, ws, inbound);

    // relay data (client <--> cf <--> destination)
    conn
        .then(ep => Promise.all([ws.readable.pipeTo(ep.writable), ep.readable.pipeTo(ws.writable)]))
        .catch(err => {
            if (configs.debug) {
                console.log(err.stack);
            }
            pair[1].close(1000);
        });

    return new Response(null, {
        status: 101,
        webSocket: pair[0],
    });
}

function selectInbound(url) {
    const uri = new URL(url);
    const key = configs.inbounds.find(e => e.path === uri.pathname);
    if (key === undefined) {
        throw new Error("Invalid path");
    }
    const inbound = inbounds.get(key);
    if (inbound === undefined) {
        throw new Error("Invalid path");
    }
    return inbound;
}

function streamifyWebSocket(ws) {
    ws.accept();
    ws.binaryType = "arraybuffer";

    return {
        readable: new ReadableStream(new WebSocketSource(ws)),
        writable: new WritableStream(new WebSocketSink(ws))
    };
}

async function createDestinationEndpoint(req, ws, transport) {
    const reader = ws.readable.getReader();
    const { value, done } = await reader.read();
    reader.releaseLock();
    if (done) {
        throw new Error("The stream was already closed!");
    }

    const { network, dstAddr, dstPort, data, dataBack } = transport.unmarshalHeader(value);
    if (network !== 'tcp') {
        // supports TCP only for now, depends on Cloudflare Workers runtime API.
        throw new Error("Unsupported network: " + network);
    }

    const conn = connect({ hostname: dstAddr, port: dstPort });

    if (configs.debug) {
        console.log(`[TCP] connected ${req.headers.get('x-real-ip')} --> ${dstAddr}:${dstPort}`);
    }

    if (dataBack) {
        const writer = ws.writable.getWriter();
        await writer.write(dataBack);
        writer.releaseLock();
    }

    if (data) {
        const writer = conn.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
    }
    return conn;
}

class Trojan {
    constructor(password) {
        this.password = password;
        this.textDecoder = new TextDecoder();
    }

    unmarshalHeader(buf) {
        // minHeaderLength(68) = password sha-224-hex(56) + crlf(2) + command(1) + addrType(1) + addr(4) + port(2) + crlf(2)
        if (buf.byteLength < 68) {
            throw new Error("Invalid header length");
        }

        const passwordHex = this.textDecoder.decode(slice(buf, 0, 56));
        if (passwordHex !== this.password) {
            throw new Error("Invalid password");
        }

        const bufU8Arr = new Uint8Array(buf);
        const command = bufU8Arr[58];
        let network = '';
        switch (command) {
            case 1: {
                network = 'tcp';
                break;
            }
            case 3: {
                network = 'udp';
                break;
            }
            default:
                throw new Error("Invalid command");
        }

        let addrOffset = 60;
        let portOffset = 0;
        let address = '';
        const addrType = bufU8Arr[59];
        switch (addrType) {
            case 1: { // ipv4
                portOffset = addrOffset + 4;
                address = bufU8Arr.slice(addrOffset, portOffset).join('.');
                break;
            }
            case 3: { // domain name
                const domainLen = bufU8Arr[addrOffset];
                addrOffset++;
                portOffset = addrOffset + domainLen;
                address = this.textDecoder.decode(slice(buf, addrOffset, portOffset));
                break;
            }
            case 4: { // ipv6
                portOffset = addrOffset + 16;
                const ipView = new DataView(slice(buf, addrOffset, portOffset));
                const ipv6 = [0, 2, 4, 6, 8, 10, 12, 14]
                    .map(offset => ipView.getUint16(offset).toString(16))
                    .join(':');
                address = '[' + ipv6 + ']';
                break;
            }
            default:
                throw new Error("Invalid address type");
        }

        const port = new DataView(slice(buf, portOffset, portOffset + 2)).getUint16(0);
        if (port === 0) {
            throw new Error("Invalid port");
        }

        const headerLen = portOffset + 4;
        let data = null;
        if (buf.byteLength > headerLen) {
            data = buf.slice(headerLen);
        }

        return {
            network: network,
            dstAddr: address,
            dstPort: port,
            data: data,
            dataBack: null,
        };
    }
}

class VLESS {
    constructor(uuid) {
        this.uuid = uuid;
        this.textDecoder = new TextDecoder();
    }

    unmarshalHeader(buf) {
        // minHeaderLength(26) = version(1) + uuid(16) + addonLen(1) + command(1) + port(2) + addrType(1) + addr(4)
        if (buf.byteLength < 26) {
            throw new Error("Invalid header length");
        }

        const bufU8Arr = new Uint8Array(buf);
        const version = bufU8Arr[0];
        const uuidStr = [...bufU8Arr.slice(1, 17)]
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
            .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');

        if (uuidStr !== this.uuid) {
            throw new Error("Invalid password");
        }

        const addonLen = bufU8Arr[17];
        const cmdOffset = 18 + addonLen;
        const portOffset = cmdOffset + 1;
        const command = bufU8Arr[cmdOffset];
        let network = '';
        switch (command) {
            case 1: {
                network = 'tcp';
                break;
            }
            case 2: {
                network = 'udp';
                break;
            }
            default:
                throw new Error("Invalid command");
        }

        let addrOffset = portOffset + 2;
        const port = new DataView(slice(buf, portOffset, addrOffset)).getUint16(0);
        if (port === 0) {
            throw new Error("Invalid port");
        }

        let address = '';
        let headerLen = 0;
        const addrType = bufU8Arr[addrOffset];
        addrOffset++;
        switch (addrType) {
            case 1: { // ipv4
                headerLen = addrOffset + 4;
                address = bufU8Arr.slice(addrOffset, headerLen).join('.');
                break;
            }
            case 2: { // domain name
                const domainLen = bufU8Arr[addrOffset];
                addrOffset++;
                headerLen = addrOffset + domainLen;
                address = this.textDecoder.decode(slice(buf, addrOffset, headerLen));
                break;
            }
            case 3: { // ipv6
                headerLen = addrOffset + 16;
                const ipView = new DataView(slice(buf, addrOffset, headerLen));
                const ipv6 = [0, 2, 4, 6, 8, 10, 12, 14]
                    .map(offset => ipView.getUint16(offset).toString(16))
                    .join(':');
                address = '[' + ipv6 + ']';
                break;
            }
            default:
                throw new Error("Invalid address type");
        }

        let data = null;
        if (buf.byteLength > headerLen) {
            data = buf.slice(headerLen);
        }

        return {
            network: network,
            dstAddr: address,
            dstPort: port,
            data: data,
            dataBack: Uint8Array.of(version, 0).buffer,
        };
    }
}

class WebSocketSource {
    constructor(ws) {
        this._ws = ws;
    }

    start(controller) {
        this._ws.onmessage = event => controller.enqueue(event.data);
        this._ws.onclose = () => controller.close();
        this._ws.onerror = () => controller.error(new Error("The WebSocket errored!"));
    }

    cancel() {
        this._ws.close();
    }
}

class WebSocketSink {
    constructor(ws) {
        this._ws = ws;
    }

    start(controller) {
        this._ws.onclose = () => controller.error(new Error("The server closed the connection unexpectedly!"));
        this._ws.onerror = () => {
            controller.error(new Error("The WebSocket errored!"));
            this._ws.onclose = null;
        };
    }

    write(chunk) {
        this._ws.send(chunk);
    }

    close() {
        return this._closeWS(1000);
    }

    abort(reason) {
        return this._closeWS(4000, reason && reason.message);
    }

    _closeWS(code, reasonString) {
        return new Promise((resolve, reject) => {
            this._ws.onclose = e => {
                if (e.wasClean) {
                    resolve();
                } else {
                    reject(new Error("The connection was not closed cleanly"));
                }
            };
            this._ws.close(code, reasonString);
        });
    }
}

function slice(buf, begin, end) {
    if (buf.byteLength < end || begin >= end) {
        throw new Error("Invalid buf length");
    }
    return buf.slice(begin, end);
}

const inbounds = new Map();

(function init() {
    configs.inbounds.forEach(e => {
        switch (e.type) {
            case 'trojan': {
                if (e.password) {
                    inbounds.set(e, new Trojan(e.password));
                }
                break;
            }
            case 'vless': {
                if (e.uuid) {
                    inbounds.set(e, new VLESS(e.uuid));
                }
                break;
            }
        }
    });
}());
