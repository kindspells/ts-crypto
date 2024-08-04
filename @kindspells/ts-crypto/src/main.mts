export type { Hasher, HashFunction } from './hashes/hashes.mts'

// In this case, we consider that it is acceptable to have a barrel file here
// because splitting the library exports into multiple files could lead to
// accidental code duplication (post-compilation) due to shared utility
// functions that end up copied into multiple files.
//
// biome-ignore lint/performance/noBarrelFile: the trade-off is worth it
export { md5, md5Hasher } from './hashes/md5.mts'

export { fromHex, toHex } from './encoding/hex.mts'
