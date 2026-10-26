// Wisp protocol server (v1 + v2) for Cloudflare Workers.
// Spec: https://github.com/MercuryWorkshop/wisp-protocol
//
// Limitations imposed by the Workers runtime:
// - UDP streams are not supported (connect() is TCP only), so the UDP extension is never advertised.
// - Outbound connections to port 25 and to Cloudflare's own IP ranges are refused by the platform.
// - Each Worker invocation (one websocket) can hold a limited number of open outbound sockets at once.

import { connect } from "cloudflare:sockets";

const BUFFER_SIZE = 128;

const PACKET = { CONNECT: 0x01, DATA: 0x02, CONTINUE: 0x03, CLOSE: 0x04, INFO: 0x05 };
const STREAM_TYPE = { TCP: 0x01, UDP: 0x02 };
const REASON = {
  VOLUNTARY: 0x02,
  NETWORK_ERROR: 0x03,
  INCOMPATIBLE_EXTENSIONS: 0x04,
  INVALID_INFO: 0x41,
  UNREACHABLE_HOST: 0x42,
  NO_RESPONSE: 0x43,
  CONN_REFUSED: 0x44,
  HOST_BLOCKED: 0x48,
  THROTTLED: 0x49,
};
const EXTENSION = { MOTD: 0x04, STREAM_CONFIRMATION: 0x05 };

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function encodePacket(type, streamId, payload) {
  const bytes = new Uint8Array(5 + payload.length);
  const view = new DataView(bytes.buffer);
  view.setUint8(0, type);
  view.setUint32(1, streamId, true);
  bytes.set(payload, 5);
  return bytes;
}

function uint32(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

function encodeExtension(id, payload = new Uint8Array(0)) {
  const bytes = new Uint8Array(5 + payload.length);
  bytes[0] = id;
  bytes.set(uint32(payload.length), 1);
  bytes.set(payload, 5);
  return bytes;
}

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((size, a) => size + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

// Map a connect() failure onto the closest Wisp close reason.
function connectErrorReason(error) {
  const message = String(error?.message ?? error).toLowerCase();
  if (message.includes("blocked")) return REASON.HOST_BLOCKED;
  if (message.includes("refused")) return REASON.CONN_REFUSED;
  if (message.includes("timed out") || message.includes("timeout")) return REASON.NO_RESPONSE;
  // the runtime reports DNS failures, refused connections and Cloudflare-owned IPs with this same message
  if (message.includes("cannot connect") || message.includes("dns") || message.includes("resolve")) {
    return REASON.UNREACHABLE_HOST;
  }
  return REASON.NETWORK_ERROR;
}

class WispStream {
  constructor(conn, id, hostname, port) {
    this.conn = conn;
    this.id = id;
    this.queue = [];
    this.pumping = false;
    this.packetsWritten = 0;
    this.closed = false;

    this.socket = connect({ hostname, port });
    this.writer = this.socket.writable.getWriter();
    this.socket.opened.then(
      () => {
        if (this.closed) return;
        if (this.conn.confirmStreams) this.conn.sendContinue(this.id, BUFFER_SIZE - this.queue.length);
        this.readLoop();
      },
      (error) => this.close(connectErrorReason(error)),
    );
  }

  push(data) {
    if (this.closed) return;
    // packets in flight when a CONTINUE is sent can briefly overshoot BUFFER_SIZE, so only
    // cut off clients that are clearly ignoring flow control
    if (this.queue.length >= BUFFER_SIZE * 4) {
      this.close(REASON.THROTTLED);
      return;
    }
    this.queue.push(data);
    if (!this.pumping) this.pump();
  }

  // Drain the per-stream FIFO into the TCP socket, granting more buffer to the client as we go.
  async pump() {
    this.pumping = true;
    try {
      await this.socket.opened;
      while (this.queue.length && !this.closed) {
        await this.writer.write(this.queue.shift());
        this.packetsWritten++;
        if (this.packetsWritten % (BUFFER_SIZE / 2) === 0) {
          this.conn.sendContinue(this.id, BUFFER_SIZE - this.queue.length);
        }
      }
    } catch {
      // a connect failure has already closed the stream with a specific reason via the opened handler
      this.close(REASON.NETWORK_ERROR);
    } finally {
      this.pumping = false;
    }
  }

  async readLoop() {
    const reader = this.socket.readable.getReader();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done || this.closed) break;
        this.conn.send(PACKET.DATA, this.id, value);
      }
      this.close(REASON.VOLUNTARY);
    } catch {
      this.close(REASON.NETWORK_ERROR);
    }
  }

  // Pass a reason to notify the client; omit it when the client initiated the close.
  close(reason) {
    if (this.closed) return;
    this.closed = true;
    this.queue = [];
    this.conn.streams.delete(this.id);
    this.socket.close().catch(() => {});
    if (reason !== undefined) this.conn.send(PACKET.CLOSE, this.id, Uint8Array.of(reason));
  }
}

class WispConnection {
  constructor(ws, version, env) {
    this.ws = ws;
    this.version = version;
    this.env = env;
    this.streams = new Map();
    this.handshakeDone = version === 1;
    this.confirmStreams = false;
  }

  start() {
    this.ws.addEventListener("message", (event) => {
      try {
        this.onMessage(event.data);
      } catch (error) {
        console.warn("failed to handle wisp packet:", error);
      }
    });
    this.ws.addEventListener("close", () => this.cleanup());
    this.ws.addEventListener("error", () => this.cleanup());

    if (this.version === 2) {
      this.send(PACKET.INFO, 0, concat(Uint8Array.of(2, 0), this.serverExtensions()));
    } else {
      this.sendContinue(0, BUFFER_SIZE);
    }
  }

  serverExtensions() {
    const extensions = [encodeExtension(EXTENSION.STREAM_CONFIRMATION)];
    if (this.env.WISP_MOTD) extensions.push(encodeExtension(EXTENSION.MOTD, encoder.encode(this.env.WISP_MOTD)));
    return concat(...extensions);
  }

  send(type, streamId, payload) {
    try {
      this.ws.send(encodePacket(type, streamId, payload));
    } catch {
      // websocket already closed
    }
  }

  sendContinue(streamId, remaining) {
    this.send(PACKET.CONTINUE, streamId, uint32(remaining));
  }

  onMessage(data) {
    if (typeof data === "string") return;
    const bytes = new Uint8Array(data);
    if (bytes.length < 5) return;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const type = view.getUint8(0);
    const streamId = view.getUint32(1, true);
    const payload = bytes.subarray(5);

    if (!this.handshakeDone) {
      this.onClientInfo(type, payload);
      return;
    }

    switch (type) {
      case PACKET.CONNECT:
        this.onConnect(streamId, payload);
        break;
      case PACKET.DATA:
        // copy, since the underlying buffer may be reused once this handler returns
        this.streams.get(streamId)?.push(payload.slice());
        break;
      case PACKET.CLOSE:
        this.streams.get(streamId)?.close();
        break;
    }
  }

  onClientInfo(type, payload) {
    if (type !== PACKET.INFO || payload.length < 2) {
      this.send(PACKET.CLOSE, 0, Uint8Array.of(REASON.INCOMPATIBLE_EXTENSIONS));
      this.ws.close(1002, "expected wisp INFO packet");
      return;
    }

    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const clientExtensions = new Set();
    for (let i = 2; i + 5 <= payload.length; ) {
      clientExtensions.add(payload[i]);
      i += 5 + view.getUint32(i + 1, true);
    }
    this.confirmStreams = clientExtensions.has(EXTENSION.STREAM_CONFIRMATION);

    this.handshakeDone = true;
    this.sendContinue(0, BUFFER_SIZE);
  }

  onConnect(streamId, payload) {
    if (streamId === 0 || this.streams.has(streamId)) return;

    const reject = (reason) => this.send(PACKET.CLOSE, streamId, Uint8Array.of(reason));
    if (payload.length < 4) return reject(REASON.INVALID_INFO);

    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const streamType = view.getUint8(0);
    const port = view.getUint16(1, true);
    const hostname = decoder.decode(payload.subarray(3)).trim();

    if (streamType !== STREAM_TYPE.TCP) return reject(REASON.INVALID_INFO);
    if (!hostname || port === 0) return reject(REASON.INVALID_INFO);
    if (port === 25) return reject(REASON.HOST_BLOCKED);

    try {
      this.streams.set(streamId, new WispStream(this, streamId, hostname, port));
    } catch (error) {
      this.streams.delete(streamId);
      reject(connectErrorReason(error));
    }
  }

  cleanup() {
    for (const stream of [...this.streams.values()]) stream.close();
  }
}

export default {
  async fetch(request, env) {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Wisp server. Connect with a websocket to a path ending in '/'.\n", { status: 426 });
    }
    if (!new URL(request.url).pathname.endsWith("/")) {
      return new Response("Wisp endpoints must end with '/'.\n", { status: 404 });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    // newer compatibility dates deliver binary frames as Blobs by default
    server.binaryType = "arraybuffer";
    server.accept();

    // Wisp v2 is used only when the client sends Sec-WebSocket-Protocol; browsers require it echoed back.
    const headers = new Headers();
    const protocols = request.headers.get("Sec-WebSocket-Protocol");
    if (protocols) headers.set("Sec-WebSocket-Protocol", protocols.split(",")[0].trim());

    new WispConnection(server, protocols ? 2 : 1, env).start();
    return new Response(null, { status: 101, webSocket: client, headers });
  },
};
