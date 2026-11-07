import { writePrivateAtomic } from '../private-paths.js'

/**
 * 先写临时文件、fsync、再 rename。
 * 直接 writeFileSync 覆盖原文件时，写到一半崩溃会留下半截 JSON；读侧又会把解析错
 * 吞成默认值，用户的设置就无声消失了。
 */
export function atomicWriteFileSync(file, text) {
  writePrivateAtomic(file, text)
}
