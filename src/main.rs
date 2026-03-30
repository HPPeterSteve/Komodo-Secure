mod cli;
mod vault;
mod crypto;
mod log;
mod path_assistant;
mod gui;

use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    log::info("Aplicação iniciada no Windows.");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("Komodo-Secure 🛡️ (Windows Edition)"),
        ..Default::default()
    };

    eframe::run_native(
        "Komodo-Secure",
        options,
        Box::new(|_cc| Ok(Box::new(gui::KomodoApp::default()))),
    )
}
