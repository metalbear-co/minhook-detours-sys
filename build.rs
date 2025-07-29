use std::{env, path::Path};

fn main() {
    if let Ok(_) = env::var("DOCS_RS") {
        // Docs don't need to build the library.
        return;
    }

    if env::var("CARGO_CFG_WINDOWS").is_err() {
        panic!("only Windows is supported");
    }

    println!("cargo:rerun-if-changed=minhook-detours");

    let minhook_dir = Path::new("minhook-detours");
    let phnt_dir = minhook_dir.join("phnt");
    let slimdetours_dir = minhook_dir.join("SlimDetours");

    cc::Build::new()
        .include(phnt_dir)
        .file(minhook_dir.join("MinHook.c"))
        .file(slimdetours_dir.join("Trampoline.c"))
        .file(slimdetours_dir.join("Transaction.c"))
        .file(slimdetours_dir.join("Thread.c"))
        .file(slimdetours_dir.join("Memory.c"))
        .file(slimdetours_dir.join("Instruction.c"))
        .file(slimdetours_dir.join("InlineHook.c"))
        .file(slimdetours_dir.join("Disassembler.c"))
        .compile("MinHook");
}
