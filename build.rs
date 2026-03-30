fn main() {
    #[cfg(windows)]
    {
        let mut build = cc::Build::new();

        build
            .file("Core/sandbox.c")
            .file("Core/firewall.c") // se existir
            .include("Core")
            .flag_if_supported("/W4")   // warnings MSVC
            .flag_if_supported("/std:c11");

        build.compile("sandbox");

        // libs do Windows
        println!("cargo:rustc-link-lib=userenv");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=fwpuclnt");
    }

    #[cfg(not(windows))]
    {
        panic!("Este projeto atualmente suporta apenas Windows");
    }
}