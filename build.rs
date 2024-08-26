fn main() {
    #[cfg(feature = "embed")]
    {
        minijinja_embed::embed_templates!("templates");
    }
}
