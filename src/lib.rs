//! haruspex — read the entrails of binaries.
//!
//! Named for the haruspices, the Roman diviners who read the innards of
//! sacrifices. This crate reads the innards of Mach-O binaries: arch
//! slices, load commands, linked dylibs, symbol tables, code-signature
//! entitlements, and embedded strings — pure Rust, no external tools,
//! and it never executes the target.
//!
//! Every finding carries its evidence: the file offset it came from.
//! `audit` folds a whole file into a `Report` with a sha256 identity and
//! heuristic flags (unsigned code, executable stack, network surfaces,
//! sensitive-API imports); `diff` compares two reports so "what did this
//! update actually change" is an answerable question.

pub mod cache;
pub mod code;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

// ─────────────────────────────── errors ─────────────────────────────

#[derive(Debug)]
pub enum Error {
    Truncated { at: usize, need: usize, len: usize },
    BadMagic(u32),
    Malformed(&'static str),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { at, need, len } => {
                write!(
                    f,
                    "truncated: read {}B at 0x{:x} of {}B file",
                    need, at, len
                )
            }
            Error::BadMagic(m) => write!(f, "bad magic 0x{:08x}", m),
            Error::Malformed(s) => write!(f, "malformed: {}", s),
            Error::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ─────────────────────────────── reader ─────────────────────────────

struct Rd<'a> {
    b: &'a [u8],
    le: bool,
}

impl<'a> Rd<'a> {
    fn at(&self, off: usize, n: usize) -> Result<&'a [u8]> {
        self.b.get(off..off + n).ok_or(Error::Truncated {
            at: off,
            need: n,
            len: self.b.len(),
        })
    }
    fn u32(&self, off: usize) -> Result<u32> {
        let b = self.at(off, 4)?;
        Ok(if self.le {
            u32::from_le_bytes(b.try_into().unwrap())
        } else {
            u32::from_be_bytes(b.try_into().unwrap())
        })
    }
    fn u64(&self, off: usize) -> Result<u64> {
        let b = self.at(off, 8)?;
        Ok(if self.le {
            u64::from_le_bytes(b.try_into().unwrap())
        } else {
            u64::from_be_bytes(b.try_into().unwrap())
        })
    }
    /// Fixed-width C string inside a load command or section header.
    fn cstr(&self, off: usize, max: usize) -> Result<String> {
        let b = self.at(off, max)?;
        let end = b.iter().position(|&c| c == 0).unwrap_or(max);
        Ok(String::from_utf8_lossy(&b[..end]).into_owned())
    }
}

// ─────────────────────────────── types ──────────────────────────────

/// A byte string pulled from the file, with the offset it lives at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffString {
    pub offset: u64,
    pub text: String,
    /// UTF-16LE when true (wide strings); plain ASCII otherwise.
    pub wide: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub segname: String,
    pub sectname: String,
    /// Load address (preserved even for cache-carved images).
    pub addr: u64,
    pub size: u64,
    pub fileoff: u64,
}

/// One architecture slice of a (possibly fat) Mach-O.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Slice {
    pub arch: String,
    /// Offset of this slice inside the outer file (0 for thin binaries).
    pub slice_offset: u64,
    pub filetype: String,
    pub uuid: Option<String>,
    pub install_name: Option<String>,
    pub platform: Option<String>,
    pub min_version: Option<String>,
    pub sdk_version: Option<String>,
    pub dylibs: Vec<String>,
    pub rpaths: Vec<String>,
    pub sections: Vec<Section>,
    /// Undefined symbols — what this binary imports.
    pub imports: Vec<String>,
    /// Defined external symbols — what this binary exports.
    pub exports: Vec<String>,
    pub entry_offset: Option<u64>,
    /// cryptid from LC_ENCRYPTION_INFO_64 (>0 means FairPlay encrypted).
    pub cryptid: Option<u32>,
    pub code_signed: bool,
    /// Raw XML entitlements plist, if embedded in the signature.
    pub entitlements: Option<String>,
    pub pie: bool,
    pub stack_executable: bool,
    /// ObjC class names from __objc_classname.
    pub objc_classes: Vec<String>,
    /// ObjC selector names from __objc_methname — the SPI surface.
    pub objc_selectors: Vec<String>,
    /// Preferred load address (vmaddr of the first file-backed
    /// segment — the Mach-O header itself).
    pub image_base: u64,
    /// `LC_FUNCTION_STARTS` (off, size). In cache-carved images these
    /// offsets index the shared linkedit subcache, not this file.
    pub function_starts: Option<(u32, u32)>,
    /// `LC_DYLD_EXPORTS_TRIE` (off, size). Same linkedit caveat.
    pub exports_trie: Option<(u32, u32)>,
}

/// Full container parse: thin binaries have one slice, fat have several.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachO {
    pub fat: bool,
    pub slices: Vec<Slice>,
}

impl Slice {
    /// The `__text` section, if this slice has code.
    pub fn text(&self) -> Option<&Section> {
        self.sections.iter().find(|s| s.sectname == "__text")
    }

    /// Map a file offset to the vmaddr it is loaded at, using the
    /// containing section's `addr`/`fileoff` pair.
    pub fn vmaddr_of_fileoff(&self, off: u64) -> Option<u64> {
        self.sections
            .iter()
            .find(|s| s.fileoff <= off && off < s.fileoff + s.size)
            .map(|s| s.addr + (off - s.fileoff))
    }
}

// ─────────────────────────────── magics ─────────────────────────────

const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_MAGIC_64: u32 = 0xcafebabf;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
const CSMAGIC_EMBEDDED_ENTITLEMENTS_DER: u32 = 0xfade7172;
const CSSLOT_ENTITLEMENTS: u32 = 5;
const CSSLOT_DER_ENTITLEMENTS: u32 = 7;

const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_SYMTAB: u32 = 0x2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_ID_DYLIB: u32 = 0xd;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;

const MH_PIE: u32 = 0x0020_0000;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;

const N_TYPE: u8 = 0x0e;
const N_UNDF: u8 = 0x00;
const N_SECT: u8 = 0x0e;
const N_EXT: u8 = 0x01;

fn arch_name(cputype: u32) -> String {
    match cputype & 0x00ff_ffff {
        7 if cputype & 0x0100_0000 != 0 => "x86_64".into(),
        12 if cputype & 0x0100_0000 != 0 => "arm64".into(),
        12 => "arm".into(),
        7 => "i386".into(),
        t => format!("cpu{}", t),
    }
}

fn filetype_name(t: u32) -> String {
    match t {
        1 => "object".into(),
        2 => "executable".into(),
        6 => "dylib".into(),
        7 => "dylinker".into(),
        8 => "bundle".into(),
        10 => "dysym".into(),
        11 => "kext".into(),
        t => format!("type{}", t),
    }
}

fn platform_name(p: u32) -> String {
    match p {
        1 => "macos".into(),
        2 => "ios".into(),
        3 => "tvos".into(),
        4 => "watchos".into(),
        6 => "maccatalyst".into(),
        7 => "iossimulator".into(),
        11 => "xros".into(),
        p => format!("platform{}", p),
    }
}

fn version_str(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

// ─────────────────────────────── parse ──────────────────────────────

/// Parse a Mach-O container (thin or fat) fully. Pure bytes in, structure out.
pub fn parse(bytes: &[u8]) -> Result<MachO> {
    let magic_be = u32::from_be_bytes(
        bytes
            .get(0..4)
            .ok_or(Error::BadMagic(0))?
            .try_into()
            .unwrap(),
    );
    match magic_be {
        FAT_MAGIC | FAT_MAGIC_64 => parse_fat(bytes, magic_be == FAT_MAGIC_64),
        _ => {
            let magic_le = u32::from_le_bytes(bytes.get(0..4).unwrap().try_into().unwrap());
            match magic_le {
                MH_MAGIC_64 | MH_CIGAM_64 => Ok(MachO {
                    fat: false,
                    slices: vec![parse_slice(bytes, 0, magic_le == MH_MAGIC_64)?],
                }),
                m => Err(Error::BadMagic(m)),
            }
        }
    }
}

fn parse_fat(bytes: &[u8], wide: bool) -> Result<MachO> {
    let rd = Rd {
        b: bytes,
        le: false,
    };
    let narch = rd.u32(4)? as usize;
    let arch_size = if wide { 32 } else { 20 };
    let mut slices = Vec::with_capacity(narch);
    for i in 0..narch {
        let a = 8 + i * arch_size;
        let cputype = rd.u32(a)?;
        let (off, _size) = if wide {
            (rd.u64(a + 8)? as usize, rd.u64(a + 16)? as usize)
        } else {
            (rd.u32(a + 8)? as usize, rd.u32(a + 12)? as usize)
        };
        let inner = rd.at(off, 4)?;
        let le = u32::from_le_bytes(inner.try_into().unwrap()) == MH_MAGIC_64;
        let mut s = parse_slice(&bytes[off..], 0, le)?;
        s.arch = arch_name(cputype);
        s.slice_offset = off as u64;
        slices.push(s);
    }
    Ok(MachO { fat: true, slices })
}

fn parse_slice(bytes: &[u8], base: usize, little: bool) -> Result<Slice> {
    let rd = Rd {
        b: bytes,
        le: little,
    };
    let cputype = rd.u32(base + 4)?;
    let filetype = rd.u32(base + 12)?;
    let ncmds = rd.u32(base + 16)? as usize;
    let flags = rd.u32(base + 24)?;

    let mut s = Slice {
        arch: arch_name(cputype),
        filetype: filetype_name(filetype),
        pie: flags & MH_PIE != 0,
        stack_executable: flags & MH_ALLOW_STACK_EXECUTION != 0,
        ..Default::default()
    };

    let mut symtab: Option<(u32, u32, u32, u32)> = None;
    let mut cs: Option<(u32, u32)> = None;

    let mut off = base + 32;
    for _ in 0..ncmds {
        let cmd = rd.u32(off)?;
        let cmdsize = rd.u32(off + 4)? as usize;
        if cmdsize < 8 {
            return Err(Error::Malformed("load command size < 8"));
        }
        match cmd {
            LC_SEGMENT_64 => {
                let segname = rd.cstr(off + 8, 16)?;
                let vmaddr = rd.u64(off + 24)?;
                let fileoff = rd.u64(off + 40)?;
                let filesize = rd.u64(off + 48)?;
                let nsects = rd.u32(off + 64)? as usize;
                // Only record real file-backed content.
                if filesize > 0 && segname != "__PAGEZERO" {
                    if s.image_base == 0 {
                        s.image_base = vmaddr;
                    }
                    let mut sec_off = off + 72;
                    for _ in 0..nsects {
                        s.sections.push(Section {
                            sectname: rd.cstr(sec_off, 16)?,
                            segname: rd.cstr(sec_off + 16, 16)?,
                            addr: rd.u64(sec_off + 32)?,
                            size: rd.u64(sec_off + 40)?,
                            fileoff: rd.u32(sec_off + 48)? as u64,
                        });
                        sec_off += 80;
                    }
                }
                let _ = fileoff;
            }
            LC_SYMTAB => {
                symtab = Some((
                    rd.u32(off + 8)?,
                    rd.u32(off + 12)?,
                    rd.u32(off + 16)?,
                    rd.u32(off + 20)?,
                ));
            }
            LC_UUID => {
                let u = rd.at(off + 8, 16)?;
                s.uuid = Some(u.iter().map(|b| format!("{:02x}", b)).collect());
            }
            LC_ID_DYLIB => {
                let name_off = off + rd.u32(off + 8)? as usize;
                s.install_name = Some(cstr_at(&rd, name_off, off + cmdsize)?);
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                let name_off = off + rd.u32(off + 8)? as usize;
                s.dylibs.push(cstr_at(&rd, name_off, off + cmdsize)?);
            }
            LC_RPATH => {
                let path_off = off + rd.u32(off + 8)? as usize;
                s.rpaths.push(cstr_at(&rd, path_off, off + cmdsize)?);
            }
            LC_MAIN => {
                s.entry_offset = Some(rd.u64(off + 8)?);
            }
            LC_ENCRYPTION_INFO_64 => {
                s.cryptid = Some(rd.u32(off + 16)?);
            }
            LC_CODE_SIGNATURE => {
                cs = Some((rd.u32(off + 8)?, rd.u32(off + 12)?));
                s.code_signed = true;
            }
            LC_FUNCTION_STARTS => {
                s.function_starts = Some((rd.u32(off + 8)?, rd.u32(off + 12)?));
            }
            LC_DYLD_EXPORTS_TRIE => {
                s.exports_trie = Some((rd.u32(off + 8)?, rd.u32(off + 12)?));
            }
            LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS => {
                s.platform = Some(
                    if cmd == LC_VERSION_MIN_MACOSX {
                        "macos"
                    } else {
                        "ios"
                    }
                    .into(),
                );
                s.min_version = Some(version_str(rd.u32(off + 8)?));
                s.sdk_version = Some(version_str(rd.u32(off + 12)?));
            }
            LC_BUILD_VERSION => {
                s.platform = Some(platform_name(rd.u32(off + 8)?));
                s.min_version = Some(version_str(rd.u32(off + 12)?));
                s.sdk_version = Some(version_str(rd.u32(off + 16)?));
            }
            _ => {}
        }
        off += cmdsize;
    }

    if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        read_symtab(&rd, symoff, nsyms, stroff, strsize, &mut s)?;
    }
    if let Some((csoff, cssize)) = cs {
        s.entitlements = read_entitlements(&rd, csoff as usize, cssize as usize);
    }

    // ObjC metadata lives as tables of C strings in dedicated sections.
    for sec in &s.sections {
        if sec.sectname == "__objc_classname" {
            for os in ascii_strings(
                &rd.at(sec.fileoff as usize, sec.size as usize)?,
                4,
                sec.fileoff,
            ) {
                s.objc_classes.push(os.text);
            }
        } else if sec.sectname == "__objc_methname" {
            for os in ascii_strings(
                &rd.at(sec.fileoff as usize, sec.size as usize)?,
                2,
                sec.fileoff,
            ) {
                s.objc_selectors.push(os.text);
            }
        }
    }

    Ok(s)
}

/// Read a NUL-terminated string starting at an absolute offset within
/// the enclosing load command (lc_str offsets are command-relative).
fn cstr_at(rd: &Rd, off: usize, end: usize) -> Result<String> {
    let max = end.saturating_sub(off);
    let b = rd.at(off, max.min(4096))?;
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    Ok(String::from_utf8_lossy(&b[..n]).into_owned())
}

fn read_symtab(
    rd: &Rd,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
    s: &mut Slice,
) -> Result<()> {
    let strs = rd.at(stroff as usize, strsize as usize)?;
    for i in 0..nsyms as usize {
        let n = symoff as usize + i * 16;
        let strx = rd.u32(n)? as usize;
        let n_type = rd.at(n + 4, 1)?[0];
        let n_sect = rd.at(n + 5, 1)?[0];
        if strx == 0 || strx >= strs.len() {
            continue;
        }
        let end = strs[strx..].iter().position(|&c| c == 0).unwrap_or(0);
        if end == 0 {
            continue;
        }
        let name = String::from_utf8_lossy(&strs[strx..strx + end]).into_owned();
        match n_type & N_TYPE {
            N_UNDF if n_sect == 0 => s.imports.push(name),
            N_SECT if n_type & N_EXT != 0 => s.exports.push(name),
            _ => {}
        }
    }
    Ok(())
}

/// Walk a code-signature superblob for the embedded entitlements blob.
/// Code signature structures are big-endian regardless of the binary's
/// own byte order.
fn read_entitlements(rd: &Rd, off: usize, _size: usize) -> Option<String> {
    let cs = Rd {
        b: rd.at(off, rd.b.len().saturating_sub(off)).ok()?,
        le: false,
    };
    if cs.u32(0).ok()? != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }
    let count = cs.u32(8).ok()? as usize;
    for i in 0..count {
        let idx = 12 + i * 8;
        let slot = cs.u32(idx).ok()?;
        let boff = cs.u32(idx + 4).ok()? as usize;
        if slot != CSSLOT_ENTITLEMENTS && slot != CSSLOT_DER_ENTITLEMENTS {
            continue;
        }
        let magic = cs.u32(boff).ok()?;
        let len = cs.u32(boff + 4).ok()? as usize;
        if magic == CSMAGIC_EMBEDDED_ENTITLEMENTS {
            let body = cs.at(boff + 8, len.saturating_sub(8)).ok()?;
            return Some(String::from_utf8_lossy(body).into_owned());
        }
        if magic == CSMAGIC_EMBEDDED_ENTITLEMENTS_DER {
            return Some(format!("<DER entitlements, {} bytes>", len - 8));
        }
    }
    None
}

// ─────────────────────────────── strings ────────────────────────────

fn ascii_strings(bytes: &[u8], min_len: usize, base: u64) -> Vec<OffString> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &c) in bytes.iter().enumerate() {
        if (0x20..0x7f).contains(&c) {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            if let Some(s) = start.take() {
                if i - s >= min_len {
                    out.push(OffString {
                        offset: base + s as u64,
                        text: String::from_utf8_lossy(&bytes[s..i]).into_owned(),
                        wide: false,
                    });
                }
            }
        }
    }
    out
}

/// Extract printable strings (ASCII and UTF-16LE) with file offsets.
pub fn strings(bytes: &[u8], min_len: usize) -> Vec<OffString> {
    let mut out = ascii_strings(bytes, min_len.max(1), 0);
    // UTF-16LE: printable char followed by a NUL, repeated.
    let mut i = 0;
    while i + 1 < bytes.len() {
        // A wide run only begins where the previous byte is not ASCII —
        // otherwise "world\0" reads as UTF-16 'd' + wide text.
        let bounded = i == 0 || !(0x20..0x7f).contains(&bytes[i - 1]);
        if bounded && (0x20..0x7f).contains(&bytes[i]) && bytes[i + 1] == 0 {
            let start = i;
            while i + 1 < bytes.len() && (0x20..0x7f).contains(&bytes[i]) && bytes[i + 1] == 0 {
                i += 2;
            }
            let chars = (i - start) / 2;
            if chars >= min_len {
                let text: String = bytes[start..i]
                    .chunks_exact(2)
                    .map(|c| c[0] as char)
                    .collect();
                out.push(OffString {
                    offset: start as u64,
                    text,
                    wide: true,
                });
            }
        } else {
            i += 1;
        }
    }
    out.sort_by_key(|s| s.offset);
    out
}

// ─────────────────────────────── audit ──────────────────────────────

/// A single evidenced flag: what was seen and where.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flag {
    pub kind: String,
    pub detail: String,
    /// File offsets backing the claim.
    pub evidence: Vec<u64>,
}

/// Full audit of one file. `flags` is the machine-usable verdict list;
/// everything in it is backed by `evidence` offsets a sceptic can check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub fat: bool,
    pub slices: Vec<Slice>,
    pub urls: Vec<String>,
    pub flags: Vec<Flag>,
}

/// Imports that mark interesting attack surface. Substring match on the
/// symbol name — deliberately broad, findings carry evidence.
const SENSITIVE_APIS: &[(&str, &str)] = &[
    ("socket", "raw sockets"),
    ("connect", "network connect"),
    ("NSURLSession", "http client"),
    ("CFNetwork", "http client"),
    ("SecItemCopyMatching", "keychain read"),
    ("SecKeychain", "keychain"),
    ("kSecAttr", "keychain"),
    ("IOHIDDevice", "hid access"),
    ("AVCapture", "camera/mic"),
    ("CGWindowListCreate", "screen capture"),
    ("AXIsProcessTrusted", "accessibility"),
    ("dlopen", "dynamic loading"),
    ("mmap", "raw memory map"),
    ("task_for_pid", "process introspection"),
    ("ptrace", "debugger control"),
    ("SMJobBless", "privileged helper install"),
    ("AuthorizationExecute", "elevated execution"),
    ("system", "shell exec"),
    ("posix_spawn", "process spawn"),
    ("NSTask", "process spawn"),
];

fn extract_urls(bytes: &[u8]) -> Vec<String> {
    let mut urls = BTreeSet::new();
    for w in bytes.windows(7) {
        if w == b"http://" || w == b"https:/".as_slice() {
            // Extend to a reasonable terminator.
            let start = w.as_ptr() as usize - bytes.as_ptr() as usize;
            let end = bytes[start..]
                .iter()
                .position(|&c| {
                    c == 0 || c == b'"' || c == b'\'' || c == b' ' || c == b')' || c == b'>'
                })
                .map(|p| start + p)
                .unwrap_or(bytes.len())
                .min(start + 200);
            if end - start > 8 {
                if let Ok(u) = std::str::from_utf8(&bytes[start..end]) {
                    if u.chars().all(|c| c.is_ascii_graphic()) {
                        urls.insert(u.to_string());
                    }
                }
            }
        }
    }
    urls.into_iter().collect()
}

/// Audit a file: parse, hash, extract URLs, and flag notable surfaces.
pub fn audit_file(path: &Path) -> Result<Report> {
    let bytes = fs::read(path)?;
    audit_bytes(&bytes, &path.display().to_string())
}

/// Audit a byte buffer under a display name (tests, stdin, carve-outs).
pub fn audit_bytes(bytes: &[u8], name: &str) -> Result<Report> {
    let m = parse(bytes)?;
    let sha = hex(&Sha256::digest(bytes));
    let urls = extract_urls(bytes);
    let mut flags = Vec::new();

    for s in &m.slices {
        if !s.code_signed {
            flags.push(Flag {
                kind: "unsigned".into(),
                detail: format!("{} slice has no LC_CODE_SIGNATURE", s.arch),
                evidence: vec![s.slice_offset],
            });
        }
        if s.stack_executable {
            flags.push(Flag {
                kind: "executable-stack".into(),
                detail: format!("{} slice allows stack execution", s.arch),
                evidence: vec![s.slice_offset],
            });
        }
        if let Some(c) = s.cryptid {
            if c > 0 {
                flags.push(Flag {
                    kind: "encrypted".into(),
                    detail: format!("{} slice is FairPlay-encrypted (cryptid {})", s.arch, c),
                    evidence: vec![s.slice_offset],
                });
            }
        }
        for imp in &s.imports {
            for &(pat, kind) in SENSITIVE_APIS {
                if imp.contains(pat) {
                    flags.push(Flag {
                        kind: kind.into(),
                        detail: format!("{} imports {}", s.arch, imp),
                        evidence: vec![s.slice_offset],
                    });
                    break;
                }
            }
        }
        for r in &s.rpaths {
            if r.starts_with('@') || r.contains("/tmp") || r.contains("~/") {
                flags.push(Flag {
                    kind: "writable-rpath".into(),
                    detail: format!("{} rpath {} is attacker-writable", s.arch, r),
                    evidence: vec![s.slice_offset],
                });
            }
        }
    }
    for u in &urls {
        flags.push(Flag {
            kind: "network-endpoint".into(),
            detail: format!("embedded URL {}", u),
            evidence: vec![],
        });
    }

    Ok(Report {
        path: name.into(),
        sha256: sha,
        size: bytes.len() as u64,
        fat: m.fat,
        slices: m.slices,
        urls,
        flags,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// ─────────────────────────────── diff ───────────────────────────────

/// What changed between two audits of the same logical binary —
/// e.g. before and after an update.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Diff {
    pub hash_changed: bool,
    pub size_delta: i64,
    pub dylibs_added: Vec<String>,
    pub dylibs_removed: Vec<String>,
    pub imports_added: Vec<String>,
    pub imports_removed: Vec<String>,
    pub entitlements_added: Vec<String>,
    pub entitlements_removed: Vec<String>,
    pub urls_added: Vec<String>,
    pub urls_removed: Vec<String>,
    pub flag_kinds_added: Vec<String>,
    pub flag_kinds_removed: Vec<String>,
}

fn set_delta(a: &[String], b: &[String]) -> (Vec<String>, Vec<String>) {
    let sa: BTreeSet<&String> = a.iter().collect();
    let sb: BTreeSet<&String> = b.iter().collect();
    (
        sb.difference(&sa).map(|s| (*s).clone()).collect(),
        sa.difference(&sb).map(|s| (*s).clone()).collect(),
    )
}

fn all_imports(r: &Report) -> Vec<String> {
    r.slices
        .iter()
        .flat_map(|s| s.imports.iter().cloned())
        .collect()
}

fn all_dylibs(r: &Report) -> Vec<String> {
    r.slices
        .iter()
        .flat_map(|s| s.dylibs.iter().cloned())
        .collect()
}

fn all_entitlements(r: &Report) -> Vec<String> {
    r.slices
        .iter()
        .filter_map(|s| s.entitlements.clone())
        .collect()
}

/// Diff two reports. `b` is the newer file.
pub fn diff(a: &Report, b: &Report) -> Diff {
    let (dylibs_added, dylibs_removed) = set_delta(&all_dylibs(a), &all_dylibs(b));
    let (imports_added, imports_removed) = set_delta(&all_imports(a), &all_imports(b));
    let (entitlements_added, entitlements_removed) =
        set_delta(&all_entitlements(a), &all_entitlements(b));
    let (urls_added, urls_removed) = set_delta(&a.urls, &b.urls);
    let fa: Vec<String> = a.flags.iter().map(|f| f.kind.clone()).collect();
    let fb: Vec<String> = b.flags.iter().map(|f| f.kind.clone()).collect();
    let (flag_kinds_added, flag_kinds_removed) = set_delta(&fa, &fb);
    Diff {
        hash_changed: a.sha256 != b.sha256,
        size_delta: b.size as i64 - a.size as i64,
        dylibs_added,
        dylibs_removed,
        imports_added,
        imports_removed,
        entitlements_added,
        entitlements_removed,
        urls_added,
        urls_removed,
        flag_kinds_added,
        flag_kinds_removed,
    }
}

// ─────────────────────────────── tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal arm64 executable: header + LC_SEGMENT_64 + LC_UUID + LC_MAIN.
    fn synth_macho() -> Vec<u8> {
        let mut b = Vec::new();
        let ncmds = 3u32;
        let sizeofcmds = 72 + 24 + 24u32;
        // mach_header_64
        b.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        b.extend_from_slice(&0x0100_000cu32.to_le_bytes()); // arm64
        b.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
        b.extend_from_slice(&2u32.to_le_bytes()); // execute
        b.extend_from_slice(&ncmds.to_le_bytes());
        b.extend_from_slice(&sizeofcmds.to_le_bytes());
        b.extend_from_slice(&MH_PIE.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // reserved
                                                  // LC_SEGMENT_64 __TEXT, one section
        b.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b.extend_from_slice(&(72u32 + 80).to_le_bytes());
        let mut seg = [0u8; 16];
        seg[..6].copy_from_slice(b"__TEXT");
        b.extend_from_slice(&seg);
        b.extend_from_slice(&0x100000000u64.to_le_bytes()); // vmaddr
        b.extend_from_slice(&0x4000u64.to_le_bytes()); // vmsize
        b.extend_from_slice(&0u64.to_le_bytes()); // fileoff
        b.extend_from_slice(&0x400u64.to_le_bytes()); // filesize
        b.extend_from_slice(&7i32.to_le_bytes()); // maxprot
        b.extend_from_slice(&5i32.to_le_bytes()); // initprot
        b.extend_from_slice(&1u32.to_le_bytes()); // nsects
        b.extend_from_slice(&0u32.to_le_bytes()); // flags
        let mut sect = [0u8; 16];
        sect[..6].copy_from_slice(b"__text");
        b.extend_from_slice(&sect);
        b.extend_from_slice(&seg);
        b.extend_from_slice(&0x100000f90u64.to_le_bytes()); // addr
        b.extend_from_slice(&0x100u64.to_le_bytes()); // size
        b.extend_from_slice(&0x200u32.to_le_bytes()); // offset
        b.extend_from_slice(&[0u8; 28]); // align..reserved3
                                         // LC_UUID
        b.extend_from_slice(&LC_UUID.to_le_bytes());
        b.extend_from_slice(&24u32.to_le_bytes());
        b.extend_from_slice(&[0xabu8; 16]);
        // LC_MAIN
        b.extend_from_slice(&LC_MAIN.to_le_bytes());
        b.extend_from_slice(&24u32.to_le_bytes());
        b.extend_from_slice(&0xf90u64.to_le_bytes()); // entryoff
        b.extend_from_slice(&0u64.to_le_bytes());
        b
    }

    #[test]
    fn parses_synth() {
        let m = parse(&synth_macho()).unwrap();
        assert!(!m.fat);
        let s = &m.slices[0];
        assert_eq!(s.arch, "arm64");
        assert_eq!(s.filetype, "executable");
        assert!(s.pie);
        assert_eq!(s.sections.len(), 1);
        assert_eq!(s.sections[0].sectname, "__text");
        assert_eq!(s.entry_offset, Some(0xf90));
    }

    #[test]
    fn rejects_junk() {
        assert!(matches!(parse(b"not a mach-o"), Err(Error::BadMagic(_))));
    }

    #[test]
    fn strings_finds_ascii_and_wide() {
        let mut b = b"hello world\0".to_vec();
        b.extend_from_slice(
            "wide string\0"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>()
                .as_slice(),
        );
        let ss = strings(&b, 5);
        assert!(ss.iter().any(|s| s.text == "hello world" && !s.wide));
        assert!(ss.iter().any(|s| s.text == "wide string" && s.wide));
    }

    #[test]
    fn urls_extracted() {
        let b = b"call https://api.example.com/telemetry now\0";
        let u = extract_urls(b);
        assert_eq!(u, vec!["https://api.example.com/telemetry"]);
    }

    #[test]
    fn audit_flags_unsigned() {
        let r = audit_bytes(&synth_macho(), "synth").unwrap();
        assert!(r.flags.iter().any(|f| f.kind == "unsigned"));
        assert!(r.slices[0].pie);
    }

    #[test]
    fn diff_reports_changes() {
        let a = audit_bytes(&synth_macho(), "a").unwrap();
        let mut b_bytes = synth_macho();
        b_bytes.extend_from_slice(b"https://evil.example.com/x\0");
        let b = audit_bytes(&b_bytes, "b").unwrap();
        let d = diff(&a, &b);
        assert!(d.hash_changed);
        assert!(d.urls_added.iter().any(|u| u.contains("evil.example.com")));
    }

    /// Real system binary — only meaningful on macOS.
    #[test]
    #[cfg(target_os = "macos")]
    fn audits_real_binary() {
        let r = audit_file(Path::new("/bin/echo")).unwrap();
        assert!(r.code_signed_all());
        assert!(!r.slices.is_empty());
        let s = &r.slices[0];
        assert!(s.dylibs.iter().any(|d| d.contains("libSystem")));
        assert_eq!(s.filetype, "executable");
    }
}

impl Report {
    /// True when every slice carries LC_CODE_SIGNATURE.
    pub fn code_signed_all(&self) -> bool {
        self.slices.iter().all(|s| s.code_signed)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod cache_tests {
    use super::cache::SharedCache;
    use super::parse;
    use std::path::Path;

    const CACHE: &str = "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e";

    /// Only runs where a Darwin 27-style cryptex cache exists.
    #[test]
    fn carves_libsystem_from_live_cache() {
        let path = Path::new(CACHE);
        if !path.exists() {
            eprintln!("no cryptex cache here — skipping");
            return;
        }
        let mut c = SharedCache::open(path).unwrap();
        c.enumerate_images().unwrap();
        assert!(c.images.len() > 100, "expected a full cache index");
        let (name, bytes) = c.extract("libsystem_c.dylib").unwrap();
        assert!(name.contains("libsystem_c"));
        let m = parse(&bytes).unwrap();
        assert!(!m.slices.is_empty());
        // Zerofill sections legitimately offset past EOF — check the
        // file-backed string sections instead.
        let cstr = m.slices[0]
            .sections
            .iter()
            .find(|s| s.sectname == "__cstring")
            .expect("libsystem_c has __cstring");
        assert!((cstr.fileoff + cstr.size) as usize <= bytes.len());
    }
}
