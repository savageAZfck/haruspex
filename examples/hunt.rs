use haruspex_macho::cache::SharedCache;
use haruspex_macho::code::disasm_listing;
use haruspex_macho::parse;
use std::path::Path;

fn main() {
    let mut c = SharedCache::open(Path::new(
        "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
    ))
    .unwrap();
    let needle = std::env::args().nth(1).expect("image needle");
    let grep = std::env::args().nth(2).expect("string to xref");
    let (name, bytes) = c.extract(&needle).unwrap();
    let m = parse(&bytes).unwrap();
    let s = &m.slices[0];
    let (name2, idx) = c.code_index(&needle).unwrap();
    assert_eq!(name, name2);

    for os in haruspex_macho::strings(&bytes, 8) {
        if !os.text.contains(&grep) {
            continue;
        }
        let va = match s.vmaddr_of_fileoff(os.offset) {
            Some(v) => v,
            None => continue,
        };
        let sites: Vec<u64> = idx
            .xrefs
            .iter()
            .filter(|x| x.target == va)
            .map(|x| x.site)
            .collect();
        if sites.is_empty() {
            println!("{:?} — no code refs", os.text);
            continue;
        }
        println!("{:?} @ {va:#x}", os.text);
        for site in sites.iter().take(4) {
            let f = idx.function_at(*site).unwrap();
            println!(
                "  ref at {:#x} in {} ({:#x}..{:#x})",
                site,
                f.label(),
                f.addr,
                f.end
            );
            // disasm context: 24 insns before the site to 6 after
            let lo = site.saturating_sub(96).max(f.addr);
            let hi = (site + 24).min(f.end);
            let t = s.text().unwrap();
            let off_lo = (lo - t.addr) as usize;
            let off_hi = (hi - t.addr) as usize;
            let code = &bytes[t.fileoff as usize + off_lo..t.fileoff as usize + off_hi];
            for line in disasm_listing(code, lo) {
                let mark = if line.starts_with(&format!("{:x}:", site)) {
                    " <=="
                } else {
                    ""
                };
                println!("      {line}{mark}");
            }
        }
    }
}
