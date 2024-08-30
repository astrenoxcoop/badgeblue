use std::path::{Path, PathBuf};

fn main() {
    #[cfg(feature = "embed")]
    {
        minijinja_embed::embed_templates!("templates");
    }

    let font_path = get_static_base_dir().join("DejaVuSansMNerdFont-Regular.ttf");
    println!(
        "cargo:rustc-env=FONT_PATH={}",
        font_path.to_str().expect("font path is not valid UTF-8")
    );
}

fn get_static_base_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("static")
}
