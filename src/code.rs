//! Code analysis: disassembly support, symbol recovery, and
//! cross-references. All of this is pure byte-math over the image —
//! the raw AArch64 encoding is decoded directly for xref extraction
//! (fast, no FFI) while `bad64` is used for human-readable listing.
//!
//! Two symbol sources are supported:
//!   * classic `LC_SYMTAB` nlist64 entries (normal on-disk Mach-O), and
//!   * the dyld-cache pair `LC_DYLD_EXPORTS_TRIE` + `LC_FUNCTION_STARTS`,
//!     whose offsets index the shared linkedit subcache file.
//!
//! Functions without a name get one synthesized as `sub_<addr>` so the
//! organ always has a stable handle.

use crate::{Error, Result};

/// A code→* reference extracted from the instruction stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    /// `ADRP` + `ADD` pair producing a data pointer (string, struct).
    AdrpAdd,
    /// `ADRP` + `LDR`/`STR` pair hitting memory at a fixed address.
    AdrpLdr,
    /// PC-relative literal `LDR` (loads a constant/pointer).
    LdrLiteral,
    /// Direct `B`/`BL`/`BLR` target (code→code).
    Branch { link: bool },
}

/// One cross-reference: an instruction at `site` references `target`.
#[derive(Debug, Clone, Copy)]
pub struct Xref {
    pub site: u64,
    pub target: u64,
    pub kind: RefKind,
}

/// A function boundary; `name` is `None` for anonymous locals.
#[derive(Debug, Clone)]
pub struct Function {
    pub addr: u64,
    pub end: u64,
    pub name: Option<String>,
}

impl Function {
    /// Display name: real symbol or synthesized `sub_` label.
    pub fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", self.addr))
    }
}

fn sx64(v: u64, bits: u32) -> i64 {
    let sh = 64 - bits;
    ((v << sh) as i64) >> sh
}

fn sx32(v: u32, bits: u32) -> i64 {
    sx64(v as u64, bits)
}

/// Scan `text` (mapped at `text_vmaddr`) for PC-relative references.
/// Returns one [`Xref`] per reference site, in address order.
///
/// What we look for, from the arm64 encoding:
///   * `ADRP Xd, imm` followed within 3 insns by `ADD Xd', Xd, #imm`
///     or `LDR`/`STR` on `Xd` — the canonical data-pointer sequence.
///   * `LDR Xt, literal` (PC + imm19<<2).
///   * `B` / `BL` (PC + imm26<<2) — code edges, used for call graphs.
pub fn scan_xrefs(text: &[u8], text_vmaddr: u64) -> Vec<Xref> {
    let mut out = Vec::new();
    let n = text.len() / 4;
    let word = |i: usize| u32::from_le_bytes(text[i * 4..i * 4 + 4].try_into().unwrap());
    for i in 0..n {
        let addr = text_vmaddr + (i as u64) * 4;
        let w = word(i);
        // ADRP Xd, #page   (bit31=1, bits[28:24]=10000)
        if w & 0x9f00_0000 == 0x9000_0000 {
            let rd = (w & 0x1f) as u64;
            let immlo = ((w >> 29) & 0x3) as u64;
            let immhi = ((w >> 5) & 0x7ffff) as u64;
            let imm = sx64((immhi << 2) | immlo, 21) << 12;
            let page = ((addr & !0xfffu64) as i64).wrapping_add(imm) as u64;
            // Look ahead for a consumer of Xd within the next 3 insns.
            for j in (i + 1)..(i + 4).min(n) {
                let w2 = word(j);
                let jaddr = text_vmaddr + (j as u64) * 4;
                let rn = ((w2 >> 5) & 0x1f) as u64;
                if rn != rd {
                    continue;
                }
                // ADD (immediate) Xd, Xn, #imm[,LSL#12]  64-bit: 0x91…..
                if w2 & 0xff00_0000 == 0x9100_0000 {
                    let sh = ((w2 >> 22) & 0x1) as u64;
                    let imm12 = (((w2 >> 10) & 0xfff) as u64) << (sh * 12);
                    out.push(Xref {
                        site: jaddr,
                        target: page.wrapping_add(imm12),
                        kind: RefKind::AdrpAdd,
                    });
                    break;
                }
                // LDR/STR unsigned offset (all GPR sizes): bits[29:24]=111001
                if w2 & 0x3b00_0000 == 0x3900_0000 {
                    let size_bits = ((w2 >> 30) & 0x3) as u64;
                    let imm12 = ((w2 >> 10) & 0xfff) as u64;
                    out.push(Xref {
                        site: jaddr,
                        target: page.wrapping_add(imm12 << size_bits),
                        kind: RefKind::AdrpLdr,
                    });
                    break;
                }
            }
            continue;
        }
        // LDR literal / PRFM literal: bits[29:24]=011000
        if w & 0x3b00_0000 == 0x1800_0000 {
            let imm = sx32((w >> 5) & 0x7ffff, 19) << 2;
            out.push(Xref {
                site: addr,
                target: (addr as i64).wrapping_add(imm) as u64,
                kind: RefKind::LdrLiteral,
            });
            continue;
        }
        // B / BL: bits[30:26]=000101
        if w & 0x7c00_0000 == 0x1400_0000 {
            let imm = sx32(w & 0x3ff_ffff, 26) << 2;
            out.push(Xref {
                site: addr,
                target: (addr as i64).wrapping_add(imm) as u64,
                kind: RefKind::Branch {
                    link: w & 0x8000_0000 != 0,
                },
            });
        }
    }
    out
}

/// ULEB128 decode starting at `bytes[*pos]`.
pub fn uleb(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    let mut v = 0u64;
    let mut sh = 0u32;
    loop {
        let b = *bytes
            .get(*pos)
            .ok_or(Error::Malformed("uleb128 ran off the end"))?;
        *pos += 1;
        v |= ((b & 0x7f) as u64) << sh;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        sh += 7;
        if sh > 63 {
            return Err(Error::Malformed("uleb128 overflow"));
        }
    }
}

/// `LC_FUNCTION_STARTS` payload: sorted ULEB128 delta list of function
/// start addresses, relative to the image's text base.
pub fn function_starts(bytes: &[u8], text_vmaddr: u64, text_end: u64) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut addr = text_vmaddr;
    while pos < bytes.len() {
        let d = uleb(bytes, &mut pos)?;
        if d == 0 {
            break;
        }
        addr = addr.wrapping_add(d);
        if addr >= text_end {
            break;
        }
        out.push(addr);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Parse a Mach-O export trie blob into `(vmaddr, name)` pairs.
/// `base` is the image's preferred load address (first __TEXT vmaddr).
pub fn export_trie(bytes: &[u8], base: u64) -> Result<Vec<(u64, String)>> {
    let mut out = Vec::new();
    const REEXPORT: u64 = 0x08;
    const STUB_AND_RESOLVER: u64 = 0x10;
    // Each frame is (node_offset, name prefix accumulated so far).
    let mut stack = vec![(0usize, String::new())];
    let mut visited = std::collections::HashSet::new();
    while let Some((off, prefix)) = stack.pop() {
        if !visited.insert(off) {
            continue; // cyclic node already expanded
        }
        let mut pos = off;
        let term = uleb(bytes, &mut pos)?;
        if term > 0 {
            let flags = uleb(bytes, &mut pos)?;
            if flags & REEXPORT != 0 {
                // reexport: ordinal uleb + optional imported-name string
                let _ord = uleb(bytes, &mut pos)?;
                if bytes.get(pos) != Some(&0) {
                    let end = bytes[pos..]
                        .iter()
                        .position(|&b| b == 0)
                        .ok_or(Error::Malformed("trie: bad reexport"))?;
                    pos += end + 1;
                } else {
                    pos += 1;
                }
            } else {
                let addr = uleb(bytes, &mut pos)?;
                out.push((base.wrapping_add(addr), prefix.clone()));
            }
            if flags & STUB_AND_RESOLVER != 0 {
                let _stub = uleb(bytes, &mut pos)?;
                let _resolver = uleb(bytes, &mut pos)?;
            }
        }
        let nkids = *bytes.get(pos).ok_or(Error::Malformed("trie: bad node"))?;
        pos += 1;
        for _ in 0..nkids {
            let end = bytes[pos..]
                .iter()
                .position(|&b| b == 0)
                .ok_or(Error::Malformed("trie: unterminated edge"))?;
            let label = std::str::from_utf8(&bytes[pos..pos + end])
                .map_err(|_| Error::Malformed("trie: non-utf8 edge"))?;
            pos += end + 1;
            let off = uleb(bytes, &mut pos)? as usize;
            stack.push((off, format!("{}{}", prefix, label)));
        }
    }
    Ok(out)
}

/// Classic `LC_SYMTAB` nlist64 decode. Returns `(vmaddr, name)` for
/// `N_SECT` symbols (real addresses), most useful on unstripped files.
pub fn nlist_symbols(symtab: &[u8], nsyms: usize, strtab: &[u8]) -> Vec<(u64, String)> {
    let mut out = Vec::with_capacity(nsyms);
    for i in 0..nsyms {
        let o = i * 16;
        if o + 16 > symtab.len() {
            break;
        }
        let strx = u32::from_le_bytes(symtab[o..o + 4].try_into().unwrap()) as usize;
        let n_type = symtab[o + 4];
        let n_value = u64::from_le_bytes(symtab[o + 8..o + 16].try_into().unwrap());
        // N_TYPE mask 0x0e: N_SECT only (skip undef/abs/debug)
        if n_type & 0x0e != 0x0e || strx == 0 || strx >= strtab.len() {
            continue;
        }
        let end = match strtab[strx..].iter().position(|&b| b == 0) {
            Some(e) => e,
            None => continue,
        };
        if let Ok(name) = std::str::from_utf8(&strtab[strx..strx + end]) {
            if !name.is_empty() {
                out.push((n_value, name.to_string()));
            }
        }
    }
    out
}

/// Build the function table for a slice: `starts` (sorted addrs) become
/// boundaries; `names` assigns symbols where we have them.
pub fn build_functions(starts: &[u64], names: &[(u64, String)], text_end: u64) -> Vec<Function> {
    let mut name_map: std::collections::HashMap<u64, String> = names.iter().cloned().collect();
    let mut out = Vec::with_capacity(starts.len());
    for (i, &a) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(text_end);
        out.push(Function {
            addr: a,
            end,
            name: name_map.remove(&a),
        });
    }
    out
}

/// Everything recovered about a slice's `__text`: function boundaries,
/// names where recoverable, and every PC-relative reference.
#[derive(Debug)]
pub struct CodeIndex {
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    /// Exported symbols (vmaddr, name), whether or not they are code.
    pub exports: Vec<(u64, String)>,
}

impl CodeIndex {
    /// Function containing `addr`, if the range is known.
    pub fn function_at(&self, addr: u64) -> Option<&Function> {
        self.functions
            .iter()
            .find(|f| f.addr <= addr && addr < f.end)
    }
}

/// Index the code of one slice of `image`.
///
/// `linkedit` resolves the raw byte ranges named by
/// `LC_FUNCTION_STARTS`/`LC_DYLD_EXPORTS_TRIE`: for a normal file it
/// reads `image` itself; for a cache-carved image it must read the
/// shared linkedit subcache (see [`crate::cache::SharedCache`]).
pub fn index_code(
    image: &[u8],
    slice: &crate::Slice,
    mut linkedit: impl FnMut(u64, u64) -> Result<Vec<u8>>,
) -> Result<CodeIndex> {
    let text = slice
        .sections
        .iter()
        .find(|s| s.sectname == "__text")
        .ok_or(Error::Malformed("no __text section"))?;
    let text_lo = text.fileoff as usize;
    let text_bytes = image
        .get(text_lo..text_lo + text.size as usize)
        .ok_or(Error::Malformed("__text outside file"))?;
    let text_end = text.addr + text.size;

    // Names from the export trie (cache and normal files alike).
    let mut names: Vec<(u64, String)> = Vec::new();
    if let Some((off, size)) = slice.exports_trie {
        if size > 0 {
            let blob = linkedit(off as u64, size as u64)?;
            names = export_trie(&blob, slice.image_base)?;
        }
    }
    let exports = names.clone();

    // Boundaries: LC_FUNCTION_STARTS first; export addrs are additional
    // starts (they can point at functions the delta table missed).
    let mut starts: Vec<u64> = Vec::new();
    if let Some((off, size)) = slice.function_starts {
        if size > 0 {
            let blob = linkedit(off as u64, size as u64)?;
            starts = function_starts(&blob, text.addr, text_end)?;
        }
    }
    starts.extend(
        names
            .iter()
            .map(|(a, _)| *a)
            .filter(|a| *a >= text.addr && *a < text_end),
    );
    // Entry point is always a function start.
    if let Some(e) = slice.entry_offset {
        let ea = slice.image_base + e;
        if ea >= text.addr && ea < text_end {
            starts.push(ea);
        }
    }
    starts.push(text.addr);
    starts.sort_unstable();
    starts.dedup();

    let functions = build_functions(&starts, &names, text_end);
    let xrefs = scan_xrefs(text_bytes, text.addr);
    Ok(CodeIndex {
        functions,
        xrefs,
        exports,
    })
}

/// Human-readable disassembly of `bytes` (mapped at `vmaddr`) through
/// bad64. One `"{addr}:  {mnemonic} {operands}"` line per instruction.
pub fn disasm_listing(bytes: &[u8], vmaddr: u64) -> Vec<String> {
    bad64::disasm(bytes, vmaddr)
        .map(|r| match r {
            Ok(i) => format!("{:x}:\t{}", i.address(), i),
            Err(e) => format!("{:x}:\t<{}>", e.address(), e),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hand-encode the three sequences we care about.
    // adrp x0, +0x1000 ; add x0, x0, #0x24 ; ldr x1, [x0]
    // then a literal ldr and a bl.
    fn code_words() -> Vec<u8> {
        let mut w: Vec<u32> = Vec::new();
        // adrp x0, page+0x1000 at addr 0x1000: imm = ((page-pc_page)>>12)
        // pc_page = 0x1000, target page 0x2000 -> imm=1
        w.push(0xB000_0000); // adrp x0, #0x1000 (immlo=1)
                             // add x0, x0, #0x24 : 0x91 (sf=1,op=0,S=0,sh=0,imm12=0x24,Rn=0,Rd=0)
        w.push(0x9100_9000);
        // ldr x8, [x0, #8] unsigned offset 64-bit: 0xF9400408
        w.push(0xF940_0408);
        // ldr literal x2, +0x40 at insn addr 0x100c: imm19 = 0x40/4 = 0x10
        w.push(0x5800_0202);
        // bl +0x100 at insn 0x1010: imm26 = 0x100/4 = 0x40
        w.push(0x9400_0040);
        w.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    #[test]
    fn adrp_add_pair_resolves() {
        let code = code_words();
        let x = scan_xrefs(&code, 0x1000);
        let add = x
            .iter()
            .find(|x| x.kind == RefKind::AdrpAdd)
            .expect("missing adrp+add");
        // page 0x1000 + 0x1000 = 0x2000; +0x24 = 0x2024
        assert_eq!(add.target, 0x2024);
        assert_eq!(add.site, 0x1004);
        let lit = x
            .iter()
            .find(|x| x.kind == RefKind::LdrLiteral)
            .expect("missing ldr literal");
        assert_eq!(lit.target, 0x100c + 0x40);
        let bl = x
            .iter()
            .find(|x| matches!(x.kind, RefKind::Branch { link: true }))
            .expect("missing bl");
        assert_eq!(bl.target, 0x1010 + 0x100);
    }

    #[test]
    fn adrp_ldr_pair_resolves() {
        // adrp x9, +0x3000 at 0x1000 ; ldr x1, [x9, #0x28]
        let mut w: Vec<u32> = vec![0xF000_0009, 0xF940_1521];
        w.extend([0xd503_201f]); // nop
        let code: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
        let x = scan_xrefs(&code, 0x1000);
        let l = x
            .iter()
            .find(|x| x.kind == RefKind::AdrpLdr)
            .expect("missing adrp+ldr");
        assert_eq!(l.target, 0x4000 + 0x28); // page 0x1000+0x3000
    }

    #[test]
    fn uleb_and_funcstarts() {
        // deltas: 4, 8, 4 -> funcs at base+4, +12, +16
        let blob = [0x04u8, 0x08, 0x04];
        let f = function_starts(&blob, 0x1000, 0x2000).unwrap();
        assert_eq!(f, vec![0x1004, 0x100c, 0x1010]);
    }

    #[test]
    fn trie_exports_named_function() {
        // Hand-built trie: root node term=0, one child edge "_foo" -> node
        // at offset N; that node has terminal: flags=0, addr=0x1234.
        // root: [0x00][0x01][" _foo \0"][uleb node_off]
        // node at 9: [0x02][flags=0][addr uleb 0x1234 = b4 24][0x00]
        let mut blob = vec![0x00, 0x01];
        blob.extend_from_slice(b"_foo\x00");
        blob.push(0x09); // child node offset = 9? position after this byte
                         // compute: root node = [size][nkids][label\0][off]
                         // bytes: 0:00 1:01 2-6:"_foo\0" 7:09? then node@8:
                         // actually node offset is absolute; put node at 8
                         // fix: offset byte = 8
        *blob.last_mut().unwrap() = 0x08;
        // node at 8: terminal size=2 -> [0x02][flags 0x00][addr 0x1234 uleb = 0xb4 0x24][nkids 0x00]
        blob.extend_from_slice(&[0x02, 0x00, 0xb4, 0x24, 0x00]);
        let ex = export_trie(&blob, 0x100000).unwrap();
        assert_eq!(ex, vec![(0x101234, "_foo".to_string())]);
    }

    #[test]
    fn build_functions_names_and_bounds() {
        let starts = vec![0x1000u64, 0x1010, 0x1080];
        let names = vec![(0x1010u64, "_bar".to_string())];
        let f = build_functions(&starts, &names, 0x2000);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].end, 0x1010);
        assert_eq!(f[1].name.as_deref(), Some("_bar"));
        assert_eq!(f[2].end, 0x2000);
        assert_eq!(f[2].label(), "sub_1080");
    }
}
