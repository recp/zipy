use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest_dir.join("../..");
    let target = env::var("TARGET").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .std("c11")
        .warnings(false)
        .include(root.join("include"))
        .include(root.join("src"))
        .include(root.join("deps/defl/include"))
        .include(root.join("deps/huff/include"))
        .define("ZIPY_STATIC", "1")
        .define("ZIPY_EXPORTS", "1")
        .define("UNZ_STATIC", "1")
        .define("UNZ_EXPORTS", "1")
        .file(root.join("src/zip.c"))
        .file(root.join("src/crypto/dec.c"))
        .file(root.join("src/crypto/aes_wg.c"))
        .file(root.join("src/crypto/sha1.c"))
        .file(root.join("deps/defl/src/infl/infl.c"))
        .file(root.join("deps/defl/src/infl/stream.c"))
        .file(root.join("deps/defl/src/infl/mem.c"));

    if target.contains("windows") {
        build.file(root.join("src/win/thread.c"));
    } else {
        build.file(root.join("src/posix/thread.c"));
    }

    if !target.contains("windows") {
        build.flag_if_supported("-O3");
    }

    build.compile("zipy");

    if target.contains("linux") || target.contains("android") {
        println!("cargo:rustc-link-lib=pthread");
    }

    for path in [
        "include/zipy/common.h",
        "include/zipy/version.h",
        "include/zipy/zip.h",
        "src/zip.c",
        "src/zip_private.h",
        "src/crypto/dec.c",
        "src/crypto/dec.h",
        "src/crypto/aes_wg.c",
        "src/crypto/aes_wg.h",
        "src/crypto/sha1.c",
        "src/crypto/sha1.h",
        "src/posix/thread.c",
        "src/posix/thread.h",
        "src/win/thread.c",
        "src/win/thread.h",
        "deps/defl/src/infl/infl.c",
        "deps/defl/src/infl/stream.c",
        "deps/defl/src/infl/mem.c",
        "deps/defl/include/defl/infl.h",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
}
