import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  assertAutoInstallKeepsSecurityPatch,
  autoInstallWouldDropSecurityPatch,
} from "../lib/security-patch.js";

const local = { purgeSecurity: { localApiAuth: 1 } };

test("automatic publisher install stops only when a real archive drops the local marker", async () => {
  assert.equal(autoInstallWouldDropSecurityPatch(local, {}), true);
  assert.equal(autoInstallWouldDropSecurityPatch(local, { purgeSecurity: { localApiAuth: 1 } }), false);
  assert.equal(autoInstallWouldDropSecurityPatch({}, {}), false);
  await assertAutoInstallKeepsSecurityPatch(local, path.join(os.tmpdir(), "purge-missing-archive.tgz"));

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "purge-sec-tar-"));
  try {
    const pkgDir = path.join(dir, "package");
    fs.mkdirSync(pkgDir);
    fs.writeFileSync(path.join(pkgDir, "package.json"), JSON.stringify({ name: "dsh-purge-community", version: "9.9.9" }));
    const archive = path.join(dir, "drop.tgz");
    execFileSync("tar", ["-czf", archive, "package"], { cwd: dir });
    await assert.rejects(assertAutoInstallKeepsSecurityPatch(local, archive), /purgeSecurity\.localApiAuth/);
    const kept = path.join(dir, "keep.tgz");
    fs.writeFileSync(path.join(pkgDir, "package.json"), JSON.stringify({ name: "dsh-purge-community", version: "9.9.9", purgeSecurity: { localApiAuth: 1 } }));
    execFileSync("tar", ["-czf", kept, "package"], { cwd: dir });
    await assertAutoInstallKeepsSecurityPatch(local, kept);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
