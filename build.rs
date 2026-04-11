fn main() {
    #[cfg(windows)]
    {
        // Configuração do Manifest para privilégios de administrador e isolamento
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("app.manifest");
        res.compile().unwrap();

        let mut build = cc::Build::new();

        build
            .file("Core/sandbox.c")
            .include("Core")
            .flag_if_supported("/W4")   // warnings MSVC
            .flag_if_supported("/std:c11");

        // Verifica se firewall.c existe antes de tentar compilar
        if std::path::Path::new("Core/firewall.c").exists() {
            build.file("Core/firewall.c");
        }

        build.compile("sandbox");

        // libs do Windows
        println!("cargo:rustc-link-lib=userenv");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=fwpuclnt");
    }

    #[cfg(not(windows))]
    {
        // Apenas para evitar erros em ambientes de desenvolvimento não-Windows
        println!("cargo:warning=Este projeto foi projetado para Windows.");
    }
}
