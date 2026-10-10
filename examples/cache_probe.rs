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
    let found = c
        .find("ANECompiler.framework/Versions/A/ANECompiler")
        .unwrap();
    let img = &found[0];
    println!("{} @ {:#x}", img.path, img.load_addr);
    let head = c.read_at(img.load_addr, 8192).unwrap();
    let ncmds = le32(&head, 16);
    println!("ncmds={} sizeofcmds={}", ncmds, le32(&head, 20));
    let mut off = 32usize;
    for i in 0..ncmds as usize {
        let cmd = le32(&head, off);
        let cs = le32(&head, off + 4) as usize;
        if cmd == 0x19 {
            let name = std::str::from_utf8(&head[off + 8..off + 24]).unwrap_or("?");
            println!(
                "seg {:16} vmaddr {:#x} fileoff {:#x} filesize {:#x}",
                name.trim_end_matches('\0'),
                le64(&head, off + 24),
                le64(&head, off + 40),
                le64(&head, off + 48)
            );
        } else {
            println!("cmd {:#x} size {}", cmd, cs);
        }
        off += cs;
    }
}
