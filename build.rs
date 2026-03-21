fn main() {
    cc::Build::new()
        .file("Core/sandbox.c")
        .include("Core")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-std=c11")
        .compile("sandbox");
    println!("cargo:rustc-link-lib=seccomp");
}