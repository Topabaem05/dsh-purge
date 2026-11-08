/**
 * Local security fixes must not be replaced by an automatic publisher install
 * that does not carry the same marker. The publisher URL is unchanged.
 * Manual install still proceeds. A missing archive (tests, unreadable path)
 * does not invent a pass: auto-install is skipped only when a real archive
 * lacks the marker.
 */
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);

export function localApiAuthLevel(pkg) {
  const level = Number(pkg?.purgeSecurity?.localApiAuth);
  return Number.isInteger(level) && level > 0 ? level : 0;
}

export function autoInstallWouldDropSecurityPatch(localPkg, incomingPkg) {
  const local = localApiAuthLevel(localPkg);
  if (!local) return false;
  return localApiAuthLevel(incomingPkg) < local;
}

export async function readTarballPackageJson(file) {
  const tar = process.platform === "win32"
    ? path.join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe")
    : "tar";
  const { stdout } = await exec(tar, ["-xOzf", file, "package/package.json"], {
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  return JSON.parse(stdout);
}

export async function assertAutoInstallKeepsSecurityPatch(localPkg, archiveFile) {
  if (!localApiAuthLevel(localPkg)) return;
  if (typeof archiveFile !== "string" || !fs.existsSync(archiveFile)) return;
  let incoming;
  try {
    incoming = await readTarballPackageJson(archiveFile);
  } catch {
    throw new Error("已跳过自动安装：无法确认发行包仍包含本地安全补丁 purgeSecurity.localApiAuth。发行源未改，可手动安装。");
  }
  if (autoInstallWouldDropSecurityPatch(localPkg, incoming)) {
    throw new Error("已跳过自动安装：该发行包没有当前的 purgeSecurity.localApiAuth。发行源未改。若确定要换成该发行包，请手动更新。");
  }
}
