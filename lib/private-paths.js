/** Owner-only files and directories for operator secrets. */
import fs from "node:fs";
import path from "node:path";
import { protectSecretDirectory, protectSecretFile } from "./update-secrets.js";

function signature(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.uid, stat.gid].join(":");
}

const seen = new Map();

function remember(target) {
  seen.set(target, signature(fs.lstatSync(target)));
}

function unchanged(target) {
  let stat;
  try { stat = fs.lstatSync(target); }
  catch { return false; }
  return seen.get(target) === signature(stat);
}

export function ensurePrivateDir(dir) {
  if (!dir) throw new Error("private directory is missing");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("private directory is not a real directory");
  if (unchanged(dir)) return dir;
  if (process.platform === "win32") protectSecretDirectory(dir);
  else fs.chmodSync(dir, 0o700);
  remember(dir);
  return dir;
}

export function protectPrivateFile(file) {
  if (!file || !fs.existsSync(file)) return;
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("private file is not a regular file");
  if (unchanged(file)) return;
  protectSecretFile(file);
  remember(file);
}

export function protectSqliteFamily(dbPath) {
  const dir = path.dirname(dbPath);
  if (fs.existsSync(dir)) ensurePrivateDir(dir);
  for (const suffix of ["", "-wal", "-shm", "-journal"]) protectPrivateFile(dbPath + suffix);
}

export function writePrivateAtomic(file, text) {
  ensurePrivateDir(path.dirname(file));
  const tmp = `${file}.tmp-${process.pid}-${Date.now().toString(36)}`;
  let fd;
  try {
    fd = fs.openSync(tmp, "w", 0o600);
    fs.writeFileSync(fd, text);
    try { fs.fsyncSync(fd); } catch { /* some filesystems do not support it */ }
    fs.closeSync(fd);
    fd = undefined;
    protectPrivateFile(tmp);
    fs.renameSync(tmp, file);
    protectPrivateFile(file);
  } catch (error) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw error;
  }
}
