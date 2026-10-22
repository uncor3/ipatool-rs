use std::path::Path;

use ipatool::sap::unicorn::patch::patch_windows_arm64_tcg_masks;

fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut image = std::fs::read(path)?;
    patch_windows_arm64_tcg_masks(&mut image).map_err(|error| error.to_string())?;
    std::fs::write(path, image)?;
    Ok(())
}

fn main() {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: patch-unicorn-windows-arm64 <libunicorn.dll>");
        std::process::exit(2);
    };

    if let Err(error) = run(Path::new(&path)) {
        eprintln!("failed to patch Unicorn for Windows ARM64: {error}");
        std::process::exit(1);
    }
}
