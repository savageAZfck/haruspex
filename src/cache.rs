//! Dyld shared-cache carving — pull framework images back out of the
//! cache without `dyld_shared_cache_util` or `ipsw`.
//!
//! On modern macOS private frameworks ship no binary on disk; the code
//! lives inside the split dyld cache (`dyld_shared_cache_arm64e`, `.01`,
//! `.02`, ... `.dylddata`, `.dyldreadonly`). Every cache file with a
//! `dyld_v1 ` magic carries its own mapping table; the main file's image
//! index names every image and its load address. `extract` walks an
//! image's Mach-O load commands inside the cache and rebuilds the
//! original file layout so `haruspex::parse` can read it like any other
//! binary.
//!
//! Reads are positioned (`read_exact_at`) — the cache is far larger than
//! RAM, so nothing is slurped whole. Note: cached images have no on-disk
//! linkedit (symbols and code signatures live in cache-local tables), so
//! extracted files carry sections, strings and ObjC metadata but no
//! symtab or signature blob.

use crate::{Error, Result};
use std::fs::{self, File};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

const HEADER_MAGIC: &[u8; 8] = b"dyld_v1 ";

// Field offsets inside dyld_cache_header (stable since cache format v11).
const OFF_MAPPING: usize = 16; // u32 mappingOffset
const OFF_NMAPPING: usize = 20; // u32 mappingCount
const OFF_MAPPING_SLIDE: usize = 304; // u32 mappingWithSlideOffset
const OFF_NMAPPING_SLIDE: usize = 308; // u32 mappingWithSlideCount

const LC_SEGMENT_64: u32 = 0x19;
const MH_MAGIC_64: u32 = 0xfeedfacf;

fn le32(b: &[u8], off: usize) -> Result<u32> {
    b.get(off..off + 4)
        .map(|x| u32::from_le_bytes(x.try_into().unwrap()))
        .ok_or(Error::Truncated {
            at: off,
            need: 4,
            len: b.len(),
        })
}

fn le64(b: &[u8], off: usize) -> Result<u64> {
    b.get(off..off + 8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
        .ok_or(Error::Truncated {
            at: off,
            need: 8,
            len: b.len(),
        })
}

/// One (vmaddr, bytes) window into one cache file.
#[derive(Debug, Clone)]
struct Mapping {
    addr: u64,
    size: u64,
    file: usize, // index into SharedCache::files
    off: u64,
    prot: u32,
}

/// A named image in the cache.
#[derive(Debug, Clone)]
pub struct Image {
    /// Install path, e.g. `/System/Library/PrivateFrameworks/ANECompiler.framework/ANECompiler`.
    pub path: String,
    pub load_addr: u64,
    pub uuid: String,
}

struct CacheFile {
    file: File,
}

impl CacheFile {
    fn read(&self, off: u64, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.file.read_exact_at(&mut buf, off)?;
        Ok(buf)
    }
}

/// An opened shared cache: every subcache file's mappings unified into
/// one address space. Files are kept as handles and read positionally —
/// nothing is slurped. `images` is populated lazily by `enumerate_images`
/// because Apple keeps changing the index format; scanning mapped
/// executable regions for Mach-O headers is format-proof.
pub struct SharedCache {
    files: Vec<CacheFile>,
    mappings: Vec<Mapping>,
    /// Suffix → index into `files` for the non-numbered subcaches
    /// (".dyldlinkedit", ".dylddata", ".dyldreadonly"). LC_DYLD_INFO-*
    /// offsets in carved images index raw file offsets inside these.
    aux: std::collections::HashMap<String, usize>,
    pub images: Vec<Image>,
}

impl SharedCache {
    /// Open a cache set: the main file plus every sibling subcache in the
    /// same directory (`.01`...`.NN`, `.dylddata`, `.dyldreadonly`, ...).
    /// `path` is the main file, e.g.
    /// `/System/Library/dyld/dyld_shared_cache_arm64e`.
    pub fn open(path: &Path) -> Result<SharedCache> {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let base = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or(Error::Malformed("cache path has no file name"))?;

        let mut names: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().starts_with(&base))
                    .unwrap_or(false)
            })
            .collect();
        names.sort();
        // Main file first so its image index is read into `images`.
        names.sort_by_key(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy() != base)
                .unwrap_or(true)
        });

        let mut files: Vec<CacheFile> = Vec::new();
        let mut mappings = Vec::new();
        let mut aux = std::collections::HashMap::new();

        for name in names {
            let file = File::open(&name)?;
            let head = {
                let mut h = vec![0u8; 512];
                file.read_exact_at(&mut h, 0)?;
                h
            };
            if &head[..8] != HEADER_MAGIC {
                continue; // .map, .atlas, .symbols — not subcaches
            }
            let idx = files.len();
            let cf = CacheFile { file };
            for suffix in [".dyldlinkedit", ".dylddata", ".dyldreadonly"] {
                if name
                    .file_name()
                    .map(|n| n.to_string_lossy().ends_with(suffix))
                    .unwrap_or(false)
                {
                    aux.insert(suffix[1..].to_string(), idx);
                }
            }
            for (addr, size, off, prot) in read_mappings(&cf, &head)? {
                mappings.push(Mapping {
                    addr,
                    size,
                    file: idx,
                    off,
                    prot,
                });
            }
            files.push(cf);
        }
        if files.is_empty() {
            return Err(Error::Malformed("no dyld cache files found"));
        }
        Ok(SharedCache {
            files,
            mappings,
            aux,
            images: Vec::new(),
        })
    }

    /// Raw read inside an aux subcache (".dyldlinkedit" etc.) at a file
    /// offset — this is where `LC_DYLD_EXPORTS_TRIE`,
    /// `LC_FUNCTION_STARTS`, `LC_DYLD_INFO` payloads of carved images
    /// actually live.
    pub fn aux_read(&self, which: &str, off: u64, n: usize) -> Result<Vec<u8>> {
        let idx = *self
            .aux
            .get(which)
            .ok_or(Error::Malformed("aux subcache not present"))?;
        self.files[idx].read(off, n)
    }

    /// Carve an image and build its full code index: function
    /// boundaries from `LC_FUNCTION_STARTS`, names from the export trie
    /// (both read out of the shared linkedit), plus every PC-relative
    /// xref in `__text`.
    pub fn code_index(&mut self, needle: &str) -> Result<(String, crate::code::CodeIndex)> {
        let (name, bytes) = self.extract(needle)?;
        let m = crate::parse(&bytes)?;
        let slice = m
            .slices
            .first()
            .ok_or(Error::Malformed("carved image has no slice"))?;
        // LC offsets index the shared linkedit file; if it is absent
        // (older caches) fall back to reading the carved image itself.
        let le = match self.aux.get("dyldlinkedit") {
            Some(&i) => Some(self.files[i].file.try_clone()?),
            None => None,
        };
        let carved = le.is_none().then_some(bytes.clone());
        let idx = crate::code::index_code(&bytes, slice, move |off, len| {
            if let Some(f) = &le {
                let mut b = vec![0u8; len as usize];
                f.read_exact_at(&mut b, off)?;
                return Ok(b);
            }
            let (lo, hi) = (off as usize, off as usize + len as usize);
            carved
                .as_deref()
                .and_then(|c| c.get(lo..hi))
                .map(|s| s.to_vec())
                .ok_or(Error::Malformed("linkedit range outside image"))
        })?;
        Ok((name, idx))
    }

    /// Walk every executable mapping looking for page-aligned Mach-O
    /// headers, then ask each image for its own install name via
    /// LC_ID_DYLIB. Deliberately index-free: Darwin has moved the image
    /// table several times, but the images cannot hide their own headers.
    pub fn enumerate_images(&mut self) -> Result<()> {
        if !self.images.is_empty() {
            return Ok(());
        }
        const PAGE: u64 = 4096;
        const CHUNK: usize = 8 * 1024 * 1024;
        let ms: Vec<Mapping> = self.mappings.clone();
        for m in &ms {
            if m.prot & 4 == 0 {
                continue; // only r-x mappings contain image text
            }
            let f = &self.files[m.file];
            let mut pos = 0u64;
            while pos < m.size {
                let take = (CHUNK as u64).min(m.size - pos) as usize;
                let buf = f.read(m.off + pos, take)?;
                for w in 0..take / PAGE as usize {
                    let o = w * PAGE as usize;
                    if le32(&buf[o..], 0).unwrap_or(0) != MH_MAGIC_64 {
                        continue;
                    }
                    let load_addr = m.addr + pos + o as u64;
                    if let Some(img) = self.image_header(load_addr)? {
                        self.images.push(img);
                    }
                }
                pos += take as u64;
            }
        }
        self.images.sort_by(|a, b| a.path.cmp(&b.path));
        self.images.dedup_by(|a, b| a.path == b.path);
        Ok(())
    }

    /// Verify a candidate header and read its identity: install name and
    /// UUID straight from its own load commands.
    fn image_header(&self, load_addr: u64) -> Result<Option<Image>> {
        let head = self.read_at(load_addr, 4096)?;
        let ncmds = le32(&head, 16)? as usize;
        let sizeofcmds = le32(&head, 20)? as usize;
        if ncmds == 0 || ncmds > 200 || sizeofcmds > 4096 - 32 {
            return Ok(None);
        }
        let mut path = String::new();
        let mut uuid = String::new();
        let mut off = 0usize;
        for _ in 0..ncmds {
            let cmd = le32(&head[32..], off)?;
            let cmdsize = le32(&head[32..], off + 4)? as usize;
            if cmdsize < 8 || off + cmdsize > sizeofcmds {
                break;
            }
            match cmd {
                0x1b => {
                    uuid = head[32 + off + 8..32 + off + 24]
                        .iter()
                        .map(|x| format!("{:02x}", x))
                        .collect();
                }
                0xd => {
                    // LC_ID_DYLIB: the name is an lc_str inside the command.
                    let name_off = off + le32(&head[32..], off + 8)? as usize;
                    let b = &head[32 + name_off..32 + off + cmdsize];
                    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                    path = String::from_utf8_lossy(&b[..end]).into_owned();
                }
                _ => {}
            }
            off += cmdsize;
        }
        if path.is_empty() {
            return Ok(None);
        }
        Ok(Some(Image {
            path,
            load_addr,
            uuid,
        }))
    }

    /// Images whose path contains `needle` (e.g. "ANECompiler").
    /// Populates the index on first use.
    pub fn find(&mut self, needle: &str) -> Result<Vec<Image>> {
        self.enumerate_images()?;
        Ok(self
            .images
            .iter()
            .filter(|i| i.path.contains(needle))
            .cloned()
            .collect())
    }

    /// Read `n` bytes at a cache virtual address by consulting every
    /// subcache's mapping table.
    pub fn read_at(&self, vmaddr: u64, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        let mut done = 0usize;
        while done < n {
            let cur = vmaddr + done as u64;
            let m = self
                .mappings
                .iter()
                .find(|m| cur >= m.addr && cur < m.addr + m.size)
                .ok_or(Error::Malformed("vmaddr outside all cache mappings"))?;
            let avail = (m.addr + m.size - cur) as usize;
            let take = avail.min(n - done);
            let foff = m.off + (cur - m.addr);
            out.extend_from_slice(&self.files[m.file].read(foff, take)?);
            done += take;
        }
        Ok(out)
    }

    /// Rebuild an image into a self-consistent Mach-O. Cached images do
    /// not keep original file offsets — `__LINKEDIT` is shared across the
    /// whole cache and other segments' `fileoff`s describe cache layout.
    /// So segments are repacked contiguously in vmaddr order, every
    /// `fileoff`/`section.offset` is rewritten to the new layout, and the
    /// symtab pointers that referenced the shared linkedit are zeroed.
    /// The result feeds straight into `haruspex::parse`.
    pub fn extract(&mut self, needle: &str) -> Result<(String, Vec<u8>)> {
        let found = self.find(needle)?;
        let img = found
            .first()
            .ok_or(Error::Malformed("image not found in cache"))?
            .clone();

        let head = self.read_at(img.load_addr, 4096)?;
        if le32(&head, 0)? != MH_MAGIC_64 {
            return Err(Error::Malformed("image does not start with mach_header_64"));
        }
        let ncmds = le32(&head, 16)? as usize;
        let sizeofcmds = le32(&head, 20)? as usize;
        let cmds = if sizeofcmds <= 4096 - 32 {
            head[32..32 + sizeofcmds].to_vec()
        } else {
            self.read_at(img.load_addr + 32, sizeofcmds)?
        };

        // Segment inventory + the byte ranges of load-command fields that
        // need patching, all keyed to positions inside `cmds`.
        struct Seg {
            vmaddr: u64,
            filesize: u64,
            cmd_at: usize,        // offset of this LC_SEGMENT_64 inside cmds
            sect_ats: Vec<usize>, // offsets of each section_64 inside cmds
        }
        let mut segs: Vec<Seg> = Vec::new();
        let mut symtab_at: Option<usize> = None;
        let mut off = 0usize;
        for _ in 0..ncmds {
            let cmd = le32(&cmds, off)?;
            let cmdsize = le32(&cmds, off + 4)? as usize;
            if cmdsize < 8 || off + cmdsize > cmds.len() {
                return Err(Error::Malformed("bad load command in cached image"));
            }
            match cmd {
                LC_SEGMENT_64 => {
                    let segname = std::str::from_utf8(&cmds[off + 8..off + 24])
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string();
                    let nsects = le32(&cmds, off + 64)? as usize;
                    if segname != "__LINKEDIT" && le64(&cmds, off + 48)? > 0 {
                        let mut sect_ats = Vec::with_capacity(nsects);
                        for j in 0..nsects {
                            sect_ats.push(off + 72 + j * 80);
                        }
                        segs.push(Seg {
                            vmaddr: le64(&cmds, off + 24)?,
                            filesize: le64(&cmds, off + 48)?,
                            cmd_at: off,
                            sect_ats,
                        });
                    }
                }
                0x2 => symtab_at = Some(off), // LC_SYMTAB points into shared linkedit
                _ => {}
            }
            off += cmdsize;
        }
        if segs.is_empty() {
            return Err(Error::Malformed("cached image has no file-backed segments"));
        }
        segs.sort_by_key(|s| s.vmaddr);

        // Output: load commands verbatim at 0, then segments packed.
        let hdr_len = 32 + sizeofcmds;
        let mut out = vec![0u8; hdr_len];
        out[32..].copy_from_slice(&cmds);
        // The mach_header itself: 32 bytes from the image start.
        out[..32].copy_from_slice(&head[..32]);

        for seg in &segs {
            let new_off = out.len() as u64;
            let data = self.read_at(seg.vmaddr, seg.filesize as usize)?;
            out.extend_from_slice(&data);
            // Patch this LC_SEGMENT_64's fileoff, and every section's
            // offset: new = seg_new + (sec.offset - seg.old_fileoff).
            out[seg.cmd_at + 32 + 40..seg.cmd_at + 32 + 48].copy_from_slice(&new_off.to_le_bytes());
            for &sa in &seg.sect_ats {
                // In cached images section.offset no longer holds a file
                // offset; addr (a vmaddr) is still truthful. Remap via
                // sec.addr - seg.vmaddr instead.
                let sec_addr = le64(&cmds, sa + 32)?;
                let new_sec_off = new_off + sec_addr.wrapping_sub(seg.vmaddr);
                out[sa + 32 + 48..sa + 32 + 52]
                    .copy_from_slice(&(new_sec_off as u32).to_le_bytes());
            }
        }
        if let Some(sa) = symtab_at {
            for f in 0..4 {
                out[sa + 32 + 8 + f * 4..sa + 32 + 12 + f * 4].copy_from_slice(&0u32.to_le_bytes());
            }
        }
        Ok((img.path.clone(), out))
    }
}

fn read_mappings(f: &CacheFile, head: &[u8]) -> Result<Vec<(u64, u64, u64, u32)>> {
    // Prefer the modern mapping_and_slide table (64-byte entries),
    // else the classic 32-byte mapping table.
    let (off, count, entry) = {
        let so = le32(head, OFF_MAPPING_SLIDE)? as usize;
        let sc = le32(head, OFF_NMAPPING_SLIDE)? as usize;
        if sc > 0 && so > 0 {
            (so, sc, 64usize)
        } else {
            (
                le32(head, OFF_MAPPING)? as usize,
                le32(head, OFF_NMAPPING)? as usize,
                32,
            )
        }
    };
    let b = f.read(off as u64, count * entry)?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = i * entry;
        let addr = le64(&b, o)?;
        let size = le64(&b, o + 8)?;
        let foff = le64(&b, o + 16)?;
        // Classic entry: initProt is a u32 at +24; mapping_and_slide
        // entries are 64B with initProt as the last u64 at +56.
        let prot = if entry == 64 {
            le64(&b, o + 56)? as u32
        } else {
            le32(&b, o + 24)?
        };
        if size > 0 {
            out.push((addr, size, foff, prot));
        }
    }
    Ok(out)
}
