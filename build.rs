fn main() {
    let mut build = cc::Build::new();
    build.file("Core/sandbox.c");
    build.include("Core");
    build.flag("-Wall");
    build.flag("-Wextra");
    build.flag("-std=c11");

    #[cfg(windows)]
    {
        build.file("Core/firewall.c");
        build.compile("sandbox");
        println!("cargo:rustc-link-lib=userenv");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=fwpuclnt");
    }

    #[cfg(unix)]
    {
        build.compile("sandbox");
        println!("cargo:rustc-link-lib=seccomp");
    }
}
