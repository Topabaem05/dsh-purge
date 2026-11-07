import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { RedteamStore } from "../lib/redteam/store-core.js";
import { protectSqliteFamily, writePrivateAtomic } from "../lib/private-paths.js";

function mode(file) {
  return fs.statSync(file).mode & 0o777;
}

test("sqlite family and atomic secret files are owner-only", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "purge-private-"));
  try {
    fs.chmodSync(root, 0o755);
    const store = new RedteamStore(root);
    const opened = store.openEngagement("fixture");
    const dbPath = store.dbPathOf(opened.id);
    assert.equal(fs.statSync(dbPath).isFile(), true);
    assert.equal(mode(dbPath), 0o600);
    assert.equal(mode(path.dirname(dbPath)), 0o700);
    assert.equal(mode(root), 0o700);
    store.kb();
    assert.equal(mode(store.knowledgePath()), 0o600);

    const loose = path.join(root, "existing.db");
    fs.writeFileSync(loose, "");
    fs.chmodSync(loose, 0o644);
    const db = new DatabaseSync(loose);
    db.exec("create table t(x)");
    db.close();
    fs.writeFileSync(loose + "-wal", "");
    fs.chmodSync(loose + "-wal", 0o644);
    protectSqliteFamily(loose);
    assert.equal(mode(loose), 0o600);
    assert.equal(mode(loose + "-wal"), 0o600);

    const secret = path.join(root, "note.txt");
    writePrivateAtomic(secret, "dummy-secret");
    assert.equal(mode(secret), 0o600);
    assert.equal(fs.readFileSync(secret, "utf8"), "dummy-secret");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
