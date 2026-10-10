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

## Non-goals

- Disassembly / decompilation (that is Ghidra/Hopper territory).
- Runtime or dynamic analysis.
- Executing, injecting into, or modifying the target.
