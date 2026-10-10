use haruspex_macho::cache::SharedCache;
use haruspex_macho::parse;
use std::path::Path;

fn main() {
    let cache_path = Path::new("/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e");
    let mut c = SharedCache::open(cache_path).unwrap();
    let (name, idx) = c
        .code_index("ANECompiler.framework/Versions/A/ANECompiler")
        .unwrap();
    println!(
        "{name}: {} functions, {} exports, {} xrefs",
        idx.functions.len(),
        idx.exports.len(),
        idx.xrefs.len()
    );
    let named = idx.functions.iter().filter(|f| f.name.is_some()).count();
    println!("named functions: {named}");
    // Show some exported names
    for (_, n) in idx.exports.iter().take(8) {
        println!("  exp {n}");
    }
    // Find the bss-limit string in the carved file, convert to vmaddr, xref it
    let (_, bytes) = c
        .extract("ANECompiler.framework/Versions/A/ANECompiler")
        .unwrap();
    let m = parse(&bytes).unwrap();
    let s = &m.slices[0];
    for os in haruspex_macho::strings(&bytes, 8) {
        if os.text.contains("bss limit") {
            let va = s.vmaddr_of_fileoff(os.offset).unwrap();
            let sites: Vec<_> = idx.xrefs.iter().filter(|x| x.target == va).collect();
            println!("\n\"{}\" @va {va:#x}  refs: {}", os.text, sites.len());
            for x in sites.iter().take(5) {
                let f = idx
                    .function_at(x.site)
                    .map(|f| f.label())
                    .unwrap_or_else(|| "?".into());
                println!("  site {:#x} in {}", x.site, f);
            }
        }
    }
}
