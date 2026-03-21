mod cli;
mod vault;
mod crypto;

use colored::*;
use inquire::Password;
use rustyline::DefaultEditor;
use std::io::{self, IsTerminal};

fn show_help() {
    println!(
        "{}",
        "
Comandos disponíveis:

create-vault <path>        → cria um cofre
add-file <vault> <file>    → adiciona arquivo ao cofre
safe-copy <src> <dst>      → copia com segurança
allow-write <file>         → libera escrita
read-directory <dir>       → lista arquivos
isolate-directory <dir>    → isola diretório
secure-copy <file> <vault> [pass] → protege e armazena (senha opcional)
encrypt <file> [pass]      → criptografa arquivo (senha opcional)
decrypt <file> [pass]      → descriptografa arquivo (senha opcional)
help                       → ajuda
exit                       → sair
"
        .cyan()
    );
}

fn get_password(prompt_text: &str, provided_pass: Option<&&str>) -> String {
    // 1. Tentar usar a senha fornecida via argumento
    if let Some(pass) = provided_pass {
        return pass.to_string();
    }

    // 2. Tentar ler do stdin se não for um terminal (ex: echo "senha" | app)
    if !io::stdin().is_terminal() {
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            return input.trim().to_string();
        }
    }

    // 3. Fallback para prompt interativo seguro
    Password::new(prompt_text)
        .without_confirmation()
        .prompt()
        .unwrap_or_default()
}

fn handle_command(parts: Vec<&str>) {
    match parts[0] {
        "isolate-directory" => {
            if let Some(dir) = parts.get(1) {
                vault::isolate_directory(dir);
            } else {
                println!("{}", "Uso: isolate-directory <dir>".yellow());
            }
        }

        "create-vault" => {
            if let Some(path) = parts.get(1) {
                vault::create(path);
                println!("{}", "✔ Cofre criado".green());
            } else {
                println!("{}", "Uso: create-vault <path>".yellow());
            }
        }

        "safe-copy" => {
            if let (Some(src), Some(dst)) = (parts.get(1), parts.get(2)) {
                match vault::safe_copy(src, dst) {
                    Ok(_) => println!("{}", "✔ Arquivo copiado".green()),
                    Err(e) => eprintln!("{}", format!("✖ Erro: {}", e).red()),
                }
            } else {
                println!("{}", "Uso: safe-copy <src> <dst>".yellow());
            }
        }

        "allow-write" => {
            if let Some(path) = parts.get(1) {
                vault::allow_write(path);
                println!("{}", "✔ Escrita liberada".green());
            } else {
                println!("{}", "Uso: allow-write <file>".yellow());
            }
        }

        "read-directory" => {
            if let Some(dir) = parts.get(1) {
                let files = vault::read_directory(dir);

                println!("{}", format!("📁 {}:", dir).blue());
                for f in files {
                    println!("  {}", format!("• {}", f).white());
                }
            } else {
                println!("{}", "Uso: read-directory <dir>".yellow());
            }
        }

        "add-file" => {
            if let (Some(vault_path), Some(file)) = (parts.get(1), parts.get(2)) {
                match vault::add_file(vault_path, file) {
                    Ok(_) => println!("{}", "✔ Arquivo adicionado".green()),
                    Err(e) => eprintln!("{}", format!("✖ Erro: {}", e).red()),
                }
            } else {
                println!("{}", "Uso: add-file <vault> <file>".yellow());
            }
        }

        "encrypt" => {
            if let Some(file) = parts.get(1) {
                let pass = get_password("Senha:", parts.get(2));

                if !pass.is_empty() {
                    let current_dir = std::env::current_dir().expect("Falha ao obter diretório atual");
                    let full_path = current_dir.join(file);
                    match crypto::encrypt_file(&full_path, &pass) {
                        Ok(_) => println!("{}", "✔ Arquivo criptografado".green()),
                        Err(e) => eprintln!("{}", format!("✖ Erro: {}", e).red()),
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            } else {
                println!("{}", "Uso: encrypt <file> [senha]".yellow());
            }
        }

        "decrypt" => {
            if let Some(file) = parts.get(1) {
                let pass = get_password("Senha:", parts.get(2));

                if !pass.is_empty() {
                    let current_dir = std::env::current_dir().expect("Falha ao obter diretório atual");
                    let full_path = current_dir.join(file);
                    match crypto::decrypt_file(&full_path, &pass) {
                        Ok(_) => println!("{}", "✔ Arquivo descriptografado".green()),
                        Err(e) => eprintln!("{}", format!("✖ Erro: {}", e).red()),
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            } else {
                println!("{}", "Uso: decrypt <file> [senha]".yellow());
            }
        }

        "secure-copy" => {
            if let (Some(file), Some(vault_path)) = (parts.get(1), parts.get(2)) {
                let pass = get_password("Defina uma senha para o cofre:", parts.get(3));

                if !pass.is_empty() {
                    vault::secure_store(file, vault_path, &pass);
                    println!("{}", "✔ Arquivo protegido e armazenado no cofre".green());
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao processar senha".red());
                }
            } else {
                println!("{}", "Uso: secure-copy <arquivo> <diretorio_vault> [senha]".yellow());
            }
        }

        "help" => {
            show_help();

            println!("{}", "Digite o número da pergunta (ou Enter para pular):".purple());

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();

            let answer = input.trim();

            if !answer.is_empty() {
                cli::questions(answer);
            }
        }

        _ => {
            println!("{}", format!("✖ Comando '{}' não existe.", parts[0]).red());
            println!("{}", "Digite 'help' para ver os comandos.".yellow());
        }
    }
}

fn main() {
    let mut rl = DefaultEditor::new().unwrap();

    println!(
        "{}",
        "Nova versão! 🎉 KomodoSec v0.04 iniciado. Digite 'help'".bright_green()
    );

    loop {
        let readline = rl.readline(&"KomodoSec> ".bright_blue().to_string());

        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str()).ok();

                let input = line.trim();

                if input.is_empty() {
                    continue;
                }

                if input == "exit" {
                    println!("{}", "Saindo...".yellow());
                    break;
                }

                let parts: Vec<&str> = input.split_whitespace().collect();
                handle_command(parts);
            }

            Err(_) => {
                println!("{}", "Erro na leitura".red());
                break;
            }
        }
    }
}
