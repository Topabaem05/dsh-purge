import { test } from "node:test";
import assert from "node:assert/strict";
import { authorizeLocalApi, loopbackTestRequest, matchProcPeerUid, TEST_PEER_UID } from "../lib/local-api-guard.js";

test("proc table matches little-endian ipv4 endpoints and ignores other rows", () => {
  const text = [
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
    "   0: 0100007F:1F90 0200007F:C1E6 01 00000000:00000000 00:00000000 00000000  1000        0 10 1 0000000000000000 100 0 0 10 0",
    "   1: 0100007F:0050 0100007F:9C40 01 00000000:00000000 00:00000000 00000000    42        0 11 1 0000000000000000 100 0 0 10 0",
  ].join("\n");
  assert.equal(matchProcPeerUid(text, {
    localAddress: "127.0.0.1", localPort: 8080, remoteAddress: "127.0.0.2", remotePort: 49638,
  }), 1000);
  assert.equal(matchProcPeerUid(text, {
    localAddress: "127.0.0.1", localPort: 80, remoteAddress: "::ffff:127.0.0.1", remotePort: 40000,
  }), 42);
  assert.equal(matchProcPeerUid(text, {
    localAddress: "127.0.0.1", localPort: 9, remoteAddress: "127.0.0.1", remotePort: 1,
  }), null);
});

test("loopback control plane rejects remote peers, rebinding, and cross-site browser requests", () => {
  const ok = authorizeLocalApi(loopbackTestRequest());
  assert.equal(ok.ok, true);
  assert.equal(JSON.stringify(ok).includes("token"), false);

  const remote = loopbackTestRequest();
  remote.socket.remoteAddress = "203.0.113.10";
  assert.equal(authorizeLocalApi(remote).ok, false);

  const rebound = loopbackTestRequest({ headers: { host: "evil.example", origin: "http://evil.example" } });
  assert.match(authorizeLocalApi(rebound).error, /host/);

  const browser = loopbackTestRequest({
    method: "POST",
    headers: { host: "127.0.0.1:9", origin: "https://evil.example", "sec-fetch-site": "cross-site" },
  });
  assert.match(authorizeLocalApi(browser).error, /cross-site/);

  const post = loopbackTestRequest({ method: "POST", headers: { host: "127.0.0.1:9", origin: "" } });
  assert.match(authorizeLocalApi(post).error, /Origin/);

  const otherUid = loopbackTestRequest();
  otherUid.socket[TEST_PEER_UID] = (process.getuid?.() ?? 0) + 1;
  assert.match(authorizeLocalApi(otherUid).error, /uid/);

  const desktop = loopbackTestRequest({
    method: "POST",
    headers: { host: "127.0.0.1:43120", origin: "app://desktop", "sec-fetch-site": "cross-site" },
  });
  assert.equal(authorizeLocalApi(desktop).ok, true);

  const filePage = loopbackTestRequest({ method: "GET", headers: { host: "[::1]:9", origin: "null" } });
  filePage.socket.remoteAddress = "::1";
  assert.equal(authorizeLocalApi(filePage).ok, true);

  const opaqueCross = loopbackTestRequest({
    method: "POST",
    headers: { host: "127.0.0.1:9", origin: "null", "sec-fetch-site": "cross-site" },
  });
  assert.equal(authorizeLocalApi(opaqueCross).ok, false);

  assert.equal(authorizeLocalApi({ method: "GET", headers: { host: "127.0.0.1" } }).ok, false);
});
