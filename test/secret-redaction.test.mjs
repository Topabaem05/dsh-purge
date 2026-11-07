import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mergeEnvKeepingSecrets, redactEnv, redactProxyUrl } from "../lib/secret-redaction.js";
import { platformSummary, savePlatformConfig } from "../lib/redteam/platform-config.js";

const DUMMY_FOFA = "fofa-dummy-not-a-real-key";
const DUMMY_PROXY = "http://dummy-user:dummy-pass@127.0.0.1:9";

test("proxy userinfo and secret env values do not survive redaction", () => {
  assert.equal(redactProxyUrl(DUMMY_PROXY).includes("dummy-user"), false);
  assert.equal(redactProxyUrl(DUMMY_PROXY).includes("dummy-pass"), false);
  assert.match(redactProxyUrl(DUMMY_PROXY), /127\.0\.0\.1:9/);
  assert.equal(redactProxyUrl("not a url"), "(configured)");
  const shown = redactEnv({ FOFA_KEY: DUMMY_FOFA, REDTEAM_VPS_HOST: "user@example", REDTEAM_VPS_KEY: "/tmp/dummy-key" });
  assert.equal(shown.env.FOFA_KEY, "");
  assert.equal(shown.env.REDTEAM_VPS_KEY, "");
  assert.equal(shown.env.REDTEAM_VPS_HOST, "user@example");
  assert.equal(shown.configured.FOFA_KEY, true);
  assert.equal(JSON.stringify(shown).includes(DUMMY_FOFA), false);
});

test("blank secret fields keep the stored dummy and summaries omit it", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "purge-redact-"));
  const previous = {
    HTTP_PROXY: process.env.HTTP_PROXY,
    http_proxy: process.env.http_proxy,
    HTTPS_PROXY: process.env.HTTPS_PROXY,
    https_proxy: process.env.https_proxy,
    ALL_PROXY: process.env.ALL_PROXY,
    all_proxy: process.env.all_proxy,
  };
  process.env.HTTP_PROXY = DUMMY_PROXY;
  delete process.env.http_proxy;
  try {
    savePlatformConfig({ env: { FOFA_KEY: DUMMY_FOFA, REDTEAM_VPS_HOST: "203.0.113.5" } }, root);
    const kept = savePlatformConfig({ env: { FOFA_KEY: "", REDTEAM_VPS_HOST: "203.0.113.5" } }, root);
    assert.equal(kept.env.FOFA_KEY, DUMMY_FOFA);
    const summary = platformSummary(root);
    const body = JSON.stringify(summary);
    assert.equal(body.includes(DUMMY_FOFA), false);
    assert.equal(body.includes("dummy-user"), false);
    assert.equal(body.includes("dummy-pass"), false);
    assert.equal(summary.config.envConfigured.FOFA_KEY, true);
    assert.equal(summary.config.env.REDTEAM_VPS_HOST, "203.0.113.5");
    assert.match(summary.egress.http_proxy, /127\.0\.0\.1:9/);
    const mode = fs.statSync(path.join(root, "config.json")).mode & 0o777;
    assert.equal(mode, 0o600);
    assert.equal(fs.statSync(root).mode & 0o777, 0o700);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("merge keeps a non-empty replacement and a cleared non-secret", () => {
  const next = mergeEnvKeepingSecrets(
    { FOFA_KEY: DUMMY_FOFA, REDTEAM_VPS_HOST: "old" },
    { FOFA_KEY: "replacement-dummy", REDTEAM_VPS_HOST: "" },
  );
  assert.equal(next.FOFA_KEY, "replacement-dummy");
  assert.equal(next.REDTEAM_VPS_HOST, "");
});
