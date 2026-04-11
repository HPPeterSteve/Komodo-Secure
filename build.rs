/*
 * build.rs
 *
 * Script de build do Cargo — compila vault_security.c + vault_ffi.c
 * e linka o resultado como biblioteca estática.
 *
 * Dependências do sistema (Debian/Ubuntu):
 *   sudo apt install libssl-dev
 *
 * Uso: coloque este arquivo na raiz do projeto Rust (ao lado de Cargo.toml).
 */

use std::process::Command;


fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    /* ── 1. Compilar vault_security.c ────────────────────────────────── */
    let status = Command::new("gcc")
        .args([
            "-O2",
            "-Wall",
            "-Wextra",
            /* Não incluir main() do vault_security.c ao linkar como lib.
             * Adicionamos -DVAULT_FFI_BUILD para que o vault_security.c
             * possa condicionar o main() com #ifndef VAULT_FFI_BUILD */
            "-DVAULT_FFI_BUILD",
            "-fPIC",
            "-c",
            "c_src/vault_security.c",
            "-o",
        ])
        .arg(format!("{}/vault_security.o", out_dir))
        .args(["-lssl", "-lcrypto", "-lpthread"])
        .status()
        .expect("Falha ao invocar gcc para vault_security.c");

    assert!(status.success(), "Compilação de vault_security.c falhou");

    /* ── 2. Compilar vault_ffi.c ─────────────────────────────────────── */
    let status = Command::new("gcc")
        .args([
            "-O2",
            "-Wall",
            "-Wextra",
            "-DVAULT_FFI_BUILD",
            "-fPIC",
            "-c",
            "c_src/vault_ffi.c",
            "-o",
        ])
        .arg(format!("{}/vault_ffi.o", out_dir))
        .status()
        .expect("Falha ao invocar gcc para vault_ffi.c");

    assert!(status.success(), "Compilação de vault_ffi.c falhou");

    /* ── 3. Criar libvault_security.a ────────────────────────────────── */
    let status = Command::new("ar")
        .args(["rcs"])
        .arg(format!("{}/libvault_security.a", out_dir))
        .arg(format!("{}/vault_security.o", out_dir))
        .arg(format!("{}/vault_ffi.o", out_dir))
        .status()
        .expect("Falha ao invocar ar");

    assert!(status.success(), "Criação de libvault_security.a falhou");

    /* ── 4. Instruções de linkagem para o Cargo ─────────────────────── */
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=vault_security");

    /* OpenSSL e pthreads (dinâmicos) */
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=pthread");

    /* Recompilar se os fontes C mudarem */
    println!("cargo:rerun-if-changed=c_src/vault_security.c");
    println!("cargo:rerun-if-changed=c_src/vault_ffi.c");
    println!("cargo:rerun-if-changed=c_src/vault_ffi.h");
}