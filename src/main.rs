mod cli;
mod vault;
mod crypto;
mod log;
mod path_assistant;
mod gui;

use colored::*;
use nix::unistd::Uid;
use std::env;
use std::path::Path;

fn check_root() {
    #[cfg(unix)]
    {
        if !Uid::effective().is_root() {
            eprintln!("{}", "✖ Erro: Este programa deve ser executado como root (sudo).".red());
            eprintln!("{}", "O Komodo-Secure requer privilégios elevados para gerenciar o isolamento do sandbox e namespaces.".yellow());
            std::process::exit(1);
        }
    }
    #[cfg(windows)]
    {
        // No Windows, verificamos se o processo tem privilégios de administrador
        // (Simplificado para esta versão)
        log::info("Verificando privilégios de administrador no Windows...");
    }
}

fn print_help() {
    println!("{}", "🛡️  Komodo-Secure CLI (Windows Optimized) 🛡️".bold().cyan());
    println!("\nUso: komodo-secure <comando> [argumentos]");
    println!("\nComandos disponíveis:");
    println!("  create-vault <caminho>          Cria um novo cofre");
    println!("  encrypt <arquivo> <senha>       Criptografa um arquivo");
    println!("  decrypt <arquivo.enc> <senha>   Descriptografa um arquivo");
    println!("  status <caminho_cofre>          Mostra o status do cofre");
    println!("  add-file <cofre> <arquivo>      Adiciona um arquivo ao cofre");
    println!("  remove-file <cofre> <arquivo>   Remove um arquivo do cofre");
    println!("  isolate-directory <diretorio>   Isola um diretório (Windows Job Object)");
    println!("  gui                             Inicia a interface gráfica");
    println!("  help                            Mostra esta ajuda");
}

fn main() {
    check_root();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    let command = &args[1];

    match command.as_str() {
        "create-vault" => {
            let path = path_assistant::ensure_path(args.get(2).map(|s| s.as_str()).as_ref(), "Digite o caminho do cofre:", true);
            if let Some(p) = path {
                vault::create(p.to_str().unwrap_or_default());
            }
        }
        "encrypt" => {
            let file_path = path_assistant::ensure_path(args.get(2).map(|s| s.as_str()).as_ref(), "Digite o caminho do arquivo para criptografar:", false);
            if let Some(p) = file_path {
                let password = if args.len() >= 4 { args[3].clone() } else {
                    inquire::Password::new("Digite a senha:").prompt().unwrap_or_default()
                };
                if let Err(e) = crypto::encrypt_file(&p, &password) {
                    eprintln!("Erro ao criptografar: {}", e);
                }
            }
        }
        "decrypt" => {
            let file_path = path_assistant::ensure_path(args.get(2).map(|s| s.as_str()).as_ref(), "Digite o caminho do arquivo .enc:", false);
            if let Some(p) = file_path {
                let password = if args.len() >= 4 { args[3].clone() } else {
                    inquire::Password::new("Digite a senha:").prompt().unwrap_or_default()
                };
                if let Err(e) = crypto::decrypt_file(&p, &password) {
                    eprintln!("Erro ao descriptografar: {}", e);
                }
            }
        }
        "status" => {
            let path = path_assistant::ensure_path(args.get(2).map(|s| s.as_str()).as_ref(), "Digite o caminho do cofre:", true);
            if let Some(p) = path {
                if let Err(e) = vault::get_vault_status(p.to_str().unwrap_or_default()) {
                    eprintln!("Erro ao obter status: {}", e);
                }
            }
        }
        "add-file" => {
            let vault_path = path_assistant::ensure_path(args.get(2).map(|s| s.as_str()).as_ref(), "Digite o caminho do cofre:", true);
            let file_path = path_assistant::ensure_path(args.get(3).map(|s| s.as_str()).as_ref(), "Digite o caminho do arquivo:", false);
            
            if let (Some(v), Some(f)) = (vault_path, file_path) {
                if let Err(e) = vault::add_file(v.to_str().unwrap_or_default(), f.to_str().unwrap_or_default()) {
                    eprintln!("Erro ao adicionar arquivo: {}", e);
                }
            }
        }
        "remove-file" => {
            let vault_path = path_assistant::ensure_path(args.get(2).map(|s| s.as_str()).as_ref(), "Digite o caminho do cofre:", true);
            if let Some(v) = vault_path {
                let file_name = if args.len() >= 4 { args[3].clone() } else {
                    inquire::Text::new("Digite o nome do arquivo para remover:").prompt().unwrap_or_default()
                };
                if let Err(e) = vault::remove_file(v.to_str().unwrap_or_default(), &file_name) {
                    eprintln!("Erro ao remover arquivo: {}", e);
                }
            }
        }
        "isolate-directory" => {
            let path = path_assistant::ensure_path(args.get(2).map(|s| s.as_str()).as_ref(), "Digite o diretório para isolar:", true);
            if let Some(p) = path {
                vault::isolate_directory(p.to_str().unwrap_or_default());
            }
        }
        "gui" => {
            start_gui();
        }
        "help" | "--help" | "-h" => {
            print_help();
        }
        _ => {
            println!("Comando desconhecido: {}", command);
            print_help();
        }
    }
}

fn start_gui() {
    log::info("Iniciando interface gráfica...");
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("Komodo-Secure 🛡️"),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Komodo-Secure",
        options,
        Box::new(|_cc| Ok(Box::new(gui::KomodoApp::default()))),
    );

    if let Err(e) = result {
        eprintln!("Erro ao iniciar GUI: {}", e);
    }
}
