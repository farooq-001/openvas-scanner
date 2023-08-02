fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.

    cc::Build::new()
        .file("c/nasl_aes_mac_gcm/nasl_aes_mac_gcm.c")
        .compile("crypt");

    println!("cargo:rerun-if-changed=src/nasl_aes_mac_gcm.c");
    println!("cargo:rustc-link-lib=gcrypt");
}
