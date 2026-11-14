//! Embeds the KeyLease Console (`apps/console/dist`, built with `pnpm build`)
//! into the server binary. Without a build, the server serves a page that
//! explains how to build it. `KEYLEASE_CONSOLE_DIST` points elsewhere.

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

fn walk(root: &Path, directory: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, files);
        } else if let Ok(relative) = path.strip_prefix(root) {
            files.push((relative.to_string_lossy().replace('\\', "/"), path));
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=KEYLEASE_CONSOLE_DIST");
    let default =
        Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../apps/console/dist");
    let dist = env::var("KEYLEASE_CONSOLE_DIST")
        .map(PathBuf::from)
        .unwrap_or(default);
    println!("cargo:rerun-if-changed={}", dist.display());
    let mut files = Vec::new();
    if dist.join("index.html").is_file() {
        walk(&dist, &dist, &mut files);
    }
    let mut out = String::from(
        "/// Console files: (path below /console/, bytes).\npub(crate) static CONSOLE_FILES: &[(&str, &[u8])] = &[\n",
    );
    for (relative, path) in files {
        let absolute = fs::canonicalize(&path).unwrap_or(path);
        writeln!(
            out,
            "    ({relative:?}, include_bytes!({:?})),",
            absolute.display().to_string()
        )
        .unwrap();
    }
    out.push_str("];\n");
    // Rewrite only on change, so an unchanged console does not rebuild the crate.
    let target = Path::new(&env::var("OUT_DIR").unwrap()).join("console_files.rs");
    if fs::read_to_string(&target).ok().as_deref() != Some(out.as_str()) {
        fs::write(target, out).unwrap();
    }
}
