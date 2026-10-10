# haruspex

Read the entrails of binaries. Named for the haruspices, the Roman
diviners who read the innards of sacrifices.

Pure-Rust Mach-O inspection with evidence: arch slices, load commands,
linked dylibs, symbol tables, embedded entitlements, and strings —
no `otool`, no `nm`, no external process, and the target is never
executed.

`cache` goes further: it opens the split dyld shared cache
(`/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`
on Darwin 27), scans executable mappings for page-aligned Mach-O
headers instead of trusting Apple's index format, and rebuilds any
image — private frameworks included — into a self-consistent file by
repacking segments and remapping every file offset. That is how the
organism reads `ANECompiler`, `MIL`, and the rest of the private
stack that ships no on-disk binary.

Built as the reverse-engineering organ of
[Bad Apple](https://github.com/savageAZfck/Bad_Apple) — the part of a
sovereign agent that can see inside the machine it lives on.

## What it reads

- fat and thin Mach-O, arm64/x86_64 (64-bit binaries)
- segments and sections with file offsets
- `LC_LOAD_*DYLIB` dependencies, `LC_RPATH`, `LC_ID_DYLIB` install names
- `LC_SYMTAB` — imports (undefined) and exports (defined externals)
- `LC_CODE_SIGNATURE` — presence flag plus embedded entitlements plist
  walked out of the superblob
- `LC_ENCRYPTION_INFO_64` cryptid (FairPlay detection)
- `LC_UUID`, `LC_MAIN` entry offset, build-version/min-OS platform info
- `__objc_classname` — Objective-C class inventory
- ASCII and UTF-16LE strings, each with its file offset

## API

```rust
let m = haruspex_macho::parse(&bytes)?;        // container -> slices
let s = haruspex_macho::strings(&bytes, 6);    // strings with offsets
let r = haruspex_macho::audit_file(path)?;     // full report + flags + sha256
let d = haruspex_macho::diff(&old, &new);      // what did that update change
```

`audit` folds everything into a `Report` whose `flags` carry evidence —
unsigned slices, executable stack, sensitive-API imports (keychain,
camera/mic, screen capture, task_for_pid, privileged helpers), embedded
URLs, attacker-writable rpaths. `diff` answers "what changed between
this binary and the one it replaced".

## Safety model

Read-only. The crate never spawns a process, never loads a dyld target,
never touches the network. Analysis of hostile input is bounded parsing
with explicit truncation checks everywhere.

License: MIT OR Apache-2.0.
