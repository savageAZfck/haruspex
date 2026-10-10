# haruspex spec (v0.1)

## Scope

Mach-O inspection for Apple platforms. PE/ELF are out of scope in v0.1.

## Guarantees

- `parse` accepts thin and fat 64-bit Mach-O. Big-endian and 32-bit
  binaries report `BadMagic`/`Malformed` rather than guessing.
- Every reported item carries evidence: a file offset or a slice offset
  a third party can re-check against the bytes.
- `strings` reports ASCII and UTF-16LE. A wide run only starts where
  the preceding byte is not printable ASCII (otherwise ASCII tails read
  as UTF-16).
- `audit` flags are advisory heuristics, not verdicts: they name what
  was seen and where. Import-name matching is substring-broad on
  purpose; read the evidence.
- `diff(a, b)` is symmetric set-delta over dylibs, imports,
  entitlements, urls and flag kinds, plus hash/size change.

## Dyld shared cache (v0.2)

- `SharedCache::open` reads every sibling file carrying the `dyld_v1 `
  magic; reads are positioned, never whole-file slurps.
- `enumerate_images` scans r-x mappings for page-aligned Mach-O headers
  and names each image from its own `LC_ID_DYLIB`. Index-free by design
  — Darwin keeps relocating the image table.
- `extract` repacks an image's file-backed segments contiguously in
  vmaddr order, rewrites segment `fileoff` and every `section.offset`
  (via `sec.addr - seg.vmaddr`), drops the cache-global `__LINKEDIT`,
  and zeroes symtab pointers that referenced it.
- Known limits: cached images have no symtab or embedded signature
  (both live in cache-local tables), and ObjC metadata is hoisted into
  the cache's shared ObjC region — per-image `objc_classes` will be
  empty on cache-carved binaries. Strings, sections and load commands
  are complete.

## Non-goals

- Disassembly / decompilation (that is Ghidra/Hopper territory).
- Runtime or dynamic analysis.
- Executing, injecting into, or modifying the target.
