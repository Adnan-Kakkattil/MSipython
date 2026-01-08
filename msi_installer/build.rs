fn main() {
    // This build script ensures WIX toolset is available
    println!("cargo:rerun-if-changed=build.rs");
}

