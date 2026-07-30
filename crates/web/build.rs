//! Bundles the TypeScript UI (`ui/src/app.ts`) into a single `app.js` with Bun, so `cargo build`
//! alone still produces one deployable binary — Bun is a build-time tool, never a runtime
//! dependency. `src/ui.rs` embeds the result via `include_str!(concat!(env!("OUT_DIR"), "/app.js"))`.
//!
//! Requires `bun` on `PATH` (https://bun.sh). Nothing here needs network access: `bun build` type-
//! strips and bundles TypeScript natively, with no `node_modules` to install.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let ui_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));

    println!("cargo:rerun-if-changed={}", ui_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ui_dir.join("index.html").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ui_dir.join("style.css").display()
    );

    let status = Command::new("bun")
        .args(["build", "src/app.ts", "--outdir"])
        .arg(&out_dir)
        .current_dir(&ui_dir)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("`bun build` exited with {s}"),
        Err(e) => panic!(
            "failed to run `bun build` in {}: {e}\n\
             burpsy-web's UI is TypeScript, bundled at build time with Bun (https://bun.sh) — \
             install it and make sure `bun` is on PATH.",
            ui_dir.display()
        ),
    }
}
