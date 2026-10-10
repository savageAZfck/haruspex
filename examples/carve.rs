use haruspex_macho::cache::SharedCache;
use std::path::Path;

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn main() {
    let mut c = SharedCache::open(Path::new(
        "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
    ))
    .unwrap();
    let (path, out) = c.extract("libsystem_c.dylib").unwrap();
    println!("{} -> {} bytes", path, out.len());
    // Walk load cmds in carved file, print first __TEXT section's offset.
    let ncmds = le32(&out, 16);
    let mut off = 32usize;
    for _ in 0..ncmds {
        let cmd = le32(&out, off);
        let cs = le32(&out, off + 4) as usize;
        if cmd == 0x19 {
            let seg = std::str::from_utf8(&out[off + 8..off + 24])
                .unwrap_or("?")
                .trim_end_matches('\0')
                .to_string();
            let fo = le64(&out, off + 40);
            let fs = le64(&out, off + 48);
            let nsects = le32(&out, off + 64);
            println!(
                "seg {} fileoff {:#x} filesize {:#x} nsects {}",
                seg, fo, fs, nsects
            );
            let mut so = off + 72;
            for _ in 0..nsects {
                let sn = std::str::from_utf8(&out[so..so + 16])
                    .unwrap_or("?")
                    .trim_end_matches('\0')
                    .to_string();
                let saddr = le64(&out, so + 32);
                let ssize = le64(&out, so + 40);
                let soff = le32(&out, so + 48);
                if sn.starts_with("__objc") || sn == "__cstring" || sn == "__text" {
                    println!(
                        "   {} addr {:#x} size {:#x} off {:#x}",
                        sn, saddr, ssize, soff
                    );
                }
                so += 80;
            }
        }
        off += cs;
    }
}
