fn main() {
    cc::Build::new()
        .file("src/sandbox.c")          
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-std=c11")
        .compile("sandbox");
}