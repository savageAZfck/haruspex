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

## Code analysis (v0.3)

- `scan_xrefs` decodes the AArch64 encoding directly: `ADRP`+`ADD`
  pointers, `ADRP`+`LDR`/`STR` memory refs, `LDR` literal, `B`/`BL`
  edges. No FFI on this path.
- `function_starts` decodes the `LC_FUNCTION_STARTS` ULEB128 delta
  table into function boundaries.
- `export_trie` walks `LC_DYLD_EXPORTS_TRIE` for named symbols;
  un-named functions are labelled `sub_<addr>`.
- `index_code` ties them together per-slice; `SharedCache::code_index`
  resolves the linkedit offsets into `.dyldlinkedit` automatically.
- `disasm_listing` renders instructions through bad64 (vendored C
  decoder, MIT — build-time only, no runtime dependency).
- Verified on ANECompiler: 122,829 functions, 140 exports, 1,162,369
  xrefs; the "exceeds the bss limit" check resolved to a single site —
  `ldr x8, [x19, #0x2e8]; cmn x8, #1; ccmp x24, x8, #4, ne` — showing
  the limit is a context field where -1 means unlimited.

## Non-goals

- Disassembly / decompilation (that is Ghidra/Hopper territory).
- Runtime or dynamic analysis.
- Executing, injecting into, or modifying the target.
