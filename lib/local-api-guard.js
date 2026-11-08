/**
 * Loopback control-plane gate.
 *
 * A bearer that any caller can fetch is not used. Browsers already attach
 * Origin and Host; those are checked even when the TCP peer is loopback.
 * On Linux the socket uid is read from /proc/net/tcp so another local account
 * is not treated as the operator. This does not verify DSH's own session
 * cookie: that verifier is not in this package.
 */
import fs from "node:fs";

export const TEST_PEER_UID = Symbol.for("dsh-purge.localApiTestPeerUid");

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function header(request, name) {
  const headers = request?.headers;
  if (!headers) return "";
  const value = headers[name] ?? headers[String(name).toLowerCase()];
  if (Array.isArray(value)) return String(value[0] || "");
  return String(value || "");
}

export function isLoopbackAddress(value) {
  const host = String(value || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  return host === "127.0.0.1" || host === "::1" || host === "localhost" || host === "::ffff:127.0.0.1";
}

export function hostIsLoopback(value) {
  let host = String(value || "").trim().toLowerCase();
  if (!host) return false;
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    host = end > 0 ? host.slice(1, end) : host;
  } else {
    host = host.replace(/:\d+$/, "");
  }
  return isLoopbackAddress(host);
}

function normalizeIp(value) {
  const host = String(value || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host);
  return mapped ? mapped[1] : host;
}

function ipv4Proc(address) {
  const parts = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(address);
  if (!parts) return "";
  const bytes = parts.slice(1).map((part) => Number(part));
  if (bytes.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return "";
  return Buffer.from(bytes).reverse().toString("hex").toUpperCase();
}

function expandIpv6(address) {
  const lower = address.toLowerCase();
  const halves = lower.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if ([...left, ...right].some((part) => !/^[0-9a-f]{0,4}$/.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right].map((part) => part || "0");
  if (groups.length !== 8) return null;
  return groups.map((part) => Number.parseInt(part, 16));
}

function ipv6Proc(address) {
  const groups = expandIpv6(address);
  if (!groups) return "";
  let hex = "";
  for (let i = 0; i < 8; i += 2) {
    const word = ((groups[i] << 16) | groups[i + 1]) >>> 0;
    hex += word.toString(16).padStart(8, "0").match(/../g).reverse().join("");
  }
  return hex.toUpperCase();
}

function endpointHex(address, port) {
  const ip = normalizeIp(address);
  const hex = ip.includes(":") ? ipv6Proc(ip) : ipv4Proc(ip);
  const portHex = Number(port).toString(16).toUpperCase().padStart(4, "0");
  if (!hex || !Number.isInteger(Number(port)) || Number(port) <= 0) return "";
  return `${hex}:${portHex}`;
}

/** Pure parser. `text` is a /proc/net/tcp or tcp6 table, not a live secret. */
export function matchProcPeerUid(text, endpoints) {
  const local = endpointHex(endpoints.localAddress, endpoints.localPort);
  const remote = endpointHex(endpoints.remoteAddress, endpoints.remotePort);
  if (!local || !remote) return null;
  for (const line of String(text || "").split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 8 || !fields[0].endsWith(":")) continue;
    if (fields[1].toUpperCase() !== local || fields[2].toUpperCase() !== remote) continue;
    const uid = Number(fields[7]);
    return Number.isInteger(uid) ? uid : null;
  }
  return null;
}

function readProc(socket) {
  const remote = normalizeIp(socket.remoteAddress);
  const names = remote.includes(":") ? ["/proc/net/tcp6", "/proc/net/tcp"] : ["/proc/net/tcp", "/proc/net/tcp6"];
  let saw = false;
  for (const name of names) {
    let text = "";
    try { text = fs.readFileSync(name, "utf8"); }
    catch (error) {
      if (error.code !== "ENOENT" && error.code !== "EACCES") throw error;
      continue;
    }
    saw = true;
    const uid = matchProcPeerUid(text, socket);
    if (uid !== null) return { available: true, uid };
  }
  return { available: saw, uid: null };
}

function peerDecision(socket) {
  if (!socket || !isLoopbackAddress(socket.remoteAddress)) {
    return { ok: false, error: "local api accepts loopback peers only" };
  }
  if (Object.prototype.hasOwnProperty.call(socket, TEST_PEER_UID)) {
    const uid = socket[TEST_PEER_UID];
    if (uid !== process.getuid?.()) return { ok: false, error: "local api peer uid does not match this process" };
    return { ok: true };
  }
  if (process.platform !== "linux" || typeof process.getuid !== "function") return { ok: true, unverifiedUid: true };
  const found = readProc(socket);
  if (!found.available) return { ok: true, unverifiedUid: true };
  if (found.uid !== process.getuid()) return { ok: false, error: "local api peer uid does not match this process" };
  return { ok: true };
}

function originDecision(request) {
  const origin = header(request, "origin").trim();
  const host = header(request, "host").trim();
  const site = header(request, "sec-fetch-site").trim().toLowerCase();
  const method = String(request?.method || "GET").toUpperCase();
  if (!hostIsLoopback(host)) return { ok: false, error: "local api host is not loopback" };
  if (site === "cross-site" && !/^app:/i.test(origin) && !/^file:/i.test(origin)) {
    return { ok: false, error: "cross-site request rejected" };
  }
  if (!origin) {
    if (MUTATING.has(method)) return { ok: false, error: "mutating local api request requires Origin" };
    return { ok: true };
  }
  if (origin === "null") {
    if (site === "cross-site") return { ok: false, error: "opaque cross-site origin rejected" };
    return { ok: true };
  }
  if (/^app:/i.test(origin) || /^file:/i.test(origin)) return { ok: true };
  let originHost = "";
  try { originHost = new URL(origin).host.toLowerCase(); }
  catch { return { ok: false, error: "local api origin is invalid" }; }
  if (originHost !== host.toLowerCase()) return { ok: false, error: "local api origin does not match host" };
  return { ok: true };
}

export function authorizeLocalApi(request) {
  const peer = peerDecision(request?.socket);
  if (!peer.ok) return { ok: false, status: 403, error: peer.error };
  const origin = originDecision(request);
  if (!origin.ok) return { ok: false, status: 403, error: origin.error };
  return { ok: true, unverifiedUid: peer.unverifiedUid === true };
}

/** Request shape for in-process tests. HTTP clients cannot set the uid symbol. */
export function loopbackTestRequest(init = {}) {
  const headers = Object.assign({
    host: "127.0.0.1:9",
    origin: "http://127.0.0.1:9",
  }, init.headers || {});
  return Object.assign({}, init, {
    method: init.method || "GET",
    headers,
    socket: Object.assign({
      remoteAddress: "127.0.0.1",
      remotePort: 40000,
      localAddress: "127.0.0.1",
      localPort: 9,
    }, init.socket || {}, { [TEST_PEER_UID]: process.getuid?.() ?? 0 }),
  });
}
