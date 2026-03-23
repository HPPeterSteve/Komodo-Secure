mod cli;
mod vault;
mod crypto;
mod log;
mod path_assistant;
mod gui;

use colored::*;
use std::path::PathBuf;
use nix::unistd::Uid;
use eframe::egui;

fn check_root() {
    if !Uid::effective().is_root() {
        eprintln!("{}", "✖ Erro: Este programa deve ser executado como root (sudo).".red());
        eprintln!("{}", "O Komodo-Secure requer privilégios elevados para gerenciar o isolamento do sandbox e namespaces.".yellow());
        std::process::exit(1);
    }
}

fn main() -> Result<(), eframe::Error> {
    check_root();
    log::info("Aplicação iniciada com GUI.");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("Komodo-Secure 🛡️"),
        ..Default::default()
    };

    eframe::run_native(
        "Komodo-Secure",
        options,
        Box::new(|_cc| Ok(Box::new(gui::KomodoApp::default()))),
    )
}
