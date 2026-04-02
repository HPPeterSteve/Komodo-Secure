mod cli;
mod vault;
mod crypto;
mod log;
mod path_assistant;
mod sys_info;
mod usb_key;
mod komodo_mb_usage;   // mantenha se você ainda usa

use colored::*;
use inquire::Password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

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
remove-file <vault> <file> → remove arquivo do cofre
status <vault>             → status do cofre
run-in-sandbox <dir>       → roda diretório em sandbox
system-info                → informações do sistema
check-pid <pid>            → checa se PID está rodando
existent-pids <name>       → lista PIDs de processos contendo nome
print-memory-usage         → exibe uso de memória
help                       → ajuda
exit                       → sair
"
        .cyan()
    );
}

fn get_password(prompt_text: &str, provided_pass: Option<&&str>) -> String {
    if let Some(pass) = provided_pass {
        return pass.to_string();
    }

    if !io::stdin().is_terminal() {
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            return input.trim().to_string();
        }
    }

    Password::new(prompt_text)
        .without_confirmation()
        .prompt()
        .unwrap_or_default()

    
}



fn handle_command(parts: Vec<&str>) {
    match parts[0] {
        "isolate-directory" => {
            if let Some(dir) = path_assistant::ensure_path(parts.get(1), "Diretório para isolar:", true) {
                log::info(&format!("Isolando diretório: {:?}", dir));
                vault::isolate_directory(dir.to_str().unwrap());
            }
        }

        "create-vault" => {
            let path = if let Some(p) = parts.get(1) {
                PathBuf::from(p)
            } else {
                let input = inquire::Text::new("Caminho para o novo cofre:").prompt().unwrap_or_default();
                PathBuf::from(input)
            };
            
            if !path.as_os_str().is_empty() {
                log::info(&format!("Criando cofre em: {:?}", path));
                vault::create(path.to_str().unwrap());
                println!("{}", "✔ Cofre criado".green());
            }
        }

        "safe-copy" => {
            let src = path_assistant::ensure_path(parts.get(1), "Arquivo de origem:", false);
            let dst = if let Some(p) = parts.get(2) {
                Some(PathBuf::from(p))
            } else {
                let input = inquire::Text::new("Caminho de destino:").prompt().ok();
                input.map(PathBuf::from)
            };

            if let (Some(s), Some(d)) = (src, dst) {
                log::info(&format!("Cópia segura: {:?} -> {:?}", s, d));
                match vault::safe_copy(s.to_str().unwrap(), d.to_str().unwrap()) {
                    Ok(_) => println!("{}", "✔ Arquivo copiado".green()),
                    Err(e) => {
                        log::error(&format!("Erro em safe-copy: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "allow-write" => {
            if let Some(path) = path_assistant::ensure_path(parts.get(1), "Arquivo para liberar escrita:", false) {
                log::info(&format!("Liberando escrita: {:?}", path));
                vault::allow_write(path.to_str().unwrap());
                println!("{}", "✔ Escrita liberada".green());
            }
        }

        "read-directory" => {
            if let Some(dir) = path_assistant::ensure_path(parts.get(1), "Diretório para listar:", true) {
                let dir_str = dir.to_str().unwrap();
                log::info(&format!("Listando diretório: {}", dir_str));
                let files = vault::read_directory(dir_str);
                println!("{}", format!("📁 {}:", dir_str).blue());
                for f in files {
                    println!("  {}", format!("• {}", f).white());
                }
            }
        }

        "add-file" => {
            let vault_path = path_assistant::ensure_path(parts.get(1), "Caminho do cofre:", true);
            let file = path_assistant::ensure_path(parts.get(2), "Arquivo para adicionar:", false);

            if let (Some(v), Some(f)) = (vault_path, file) {
                log::info(&format!("Adicionando arquivo {:?} ao cofre {:?}", f, v));
                match vault::add_file(v.to_str().unwrap(), f.to_str().unwrap()) {
                    Ok(_) => println!("{}", "✔ Arquivo adicionado".green()),
                    Err(e) => {
                        log::error(&format!("Erro em add-file: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "remove-file" => {
            let vault_path = path_assistant::ensure_path(parts.get(1), "Caminho do cofre:", true);
            let file = if let Some(f) = parts.get(2) {
                Some(f.to_string())
            } else {
                inquire::Text::new("Nome do arquivo no cofre:").prompt().ok()
            };

            if let (Some(v), Some(f)) = (vault_path, file) {
                log::info(&format!("Removendo arquivo {} do cofre {:?}", f, v));
                match vault::remove_file(v.to_str().unwrap(), &f) {
                    Ok(_) => println!("{}", "✔ Arquivo removido".green()),
                    Err(e) => {
                        log::error(&format!("Erro em remove-file: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "status" => {
            if let Some(vault_path) = path_assistant::ensure_path(parts.get(1), "Caminho do cofre:", true) {
                log::info(&format!("Verificando status do cofre: {:?}", vault_path));
                match vault::get_vault_status(vault_path.to_str().unwrap()) {
                    Ok(_) => (),
                    Err(e) => {
                        log::error(&format!("Erro em status: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "encrypt" => {
            if let Some(file) = path_assistant::ensure_path(parts.get(1), "Arquivo para criptografar:", false) {
                let pass = get_password("Senha:", parts.get(2));
                if !pass.is_empty() {
                    log::info(&format!("Criptografando arquivo: {:?}", file));
                    match crypto::encrypt_file(&file, &pass) {
                        Ok(_) => println!("{}", "✔ Arquivo criptografado".green()),
                        Err(e) => {
                            log::error(&format!("Erro em encrypt: {}", e));
                            eprintln!("{}", format!("✖ Erro: {}", e).red());
                        }
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            }
        }

        "decrypt" => {
            if let Some(file) = path_assistant::ensure_path(parts.get(1), "Arquivo para descriptografar:", false) {
                let pass = get_password("Senha:", parts.get(2));
                if !pass.is_empty() {
                    log::info(&format!("Descriptografando arquivo: {:?}", file));
                    match crypto::decrypt_file(&file, &pass) {
                        Ok(_) => println!("{}", "✔ Arquivo descriptografado".green()),
                        Err(e) => {
                            log::error(&format!("Erro em decrypt: {}", e));
                            eprintln!("{}", format!("✖ Erro: {}", e).red());
                        }
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            }
        }

        "secure-copy" => {
            let file = path_assistant::ensure_path(parts.get(1), "Arquivo de origem:", false);
            let vault_path = path_assistant::ensure_path(parts.get(2), "Caminho do cofre:", true);

            if let (Some(f), Some(v)) = (file, vault_path) {
                let pass = get_password("Defina uma senha para o cofre:", parts.get(3));
                if !pass.is_empty() {
                    log::info(&format!("Secure-copy: {:?} para {:?}", f, v));
                    vault::secure_store(f.to_str().unwrap(), v.to_str().unwrap(), &pass);
                    println!("{}", "✔ Arquivo protegido e armazenado no cofre".green());
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao processar senha".red());
                }
            }
        }
        "run-in-sandbox" => {
            if let Some(dir) = path_assistant::ensure_path(parts.get(1), "Diretório para rodar em sandbox:", true) {
                log::info(&format!("Rodando diretório em sandbox: {:?}", dir));
                vault::run_in_sandbox(dir.to_str().unwrap());
            }
        }
        "system-info" => {
            log::info("Exibindo informações do sistema");
            sys_info::print_system_info();
        }
        "check-pid" => {
            if let Some(pid_str) = parts.get(1) {
                if let Ok(pid) = pid_str.parse::<i32>() {
                    log::info(&format!("Checando PID: {}", pid));
                    sys_info::check_pid(pid);
                } else {
                    println!("{}", "✖ PID inválido. Use um número inteiro.".red());
                }
            } else {
                println!("{}", "✖ Por favor, forneça um PID para verificar.".red());
            }
        }
        "existent-pids" => {
            if let Some(name) = parts.get(1) {
                log::info(&format!("Listando PIDs existentes para: {}", name));
                let pids = sys_info::existent_pids(name);
                if pids.is_empty() {
                    println!("{}", format!("Nenhum processo encontrado contendo '{}'", name).yellow());
                } else {
                    println!("{}", format!("Processos encontrados contendo '{}':", name).green());
                    for pid in pids {
                        println!("  {}", format!("• PID: {}", pid).white());
                    }
                }
            } else {
                println!("{}", "✖ Por favor, forneça um nome para buscar os PIDs.".red());
            }
        }
        "print-memoy-usage" => {
            log::info("Exibindo uso de memória");
            komodo_mb_usage::print_memory_winapi();
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
        
        "exit" => {
            log::info("Aplicação encerrada pelo usuário.");
            println!("{}", "Saindo...".yellow());
            std::process::exit(0);
        }

        _ => {
            log::warn(&format!("Comando inválido: {}", parts[0]));
            println!("{}", format!("✖ Comando '{}' não existe.", parts[0]).red());
            println!("{}", "Digite 'help' para ver os comandos.".yellow());
        }
    }
}

fn main() {
    let mut rl = DefaultEditor::new().unwrap();
    log::info("Aplicação iniciada.");

    println!(
        "{}",
        "Komodo-Secure v0.62.0 iniciado! 🛡️ Sub-sistema de Assistência de Caminhos ATIVO.
        todos os direitos reservados.
        Digite 'help'".bright_green()
    );
    ctrlc::set_handler(|| {
        println!("\n^C");
        log::info("Aplicação fechando");
        std::process::exit(0);
    }).expect("Erro ao definir handler");

    loop {
        let readline = rl.readline(&"Komodo-Secure> ".bright_blue().to_string());

        match readline {
    Ok(line) => {
        rl.add_history_entry(line.as_str()).ok();
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        let parts: Vec<&str> = input.split_whitespace().collect();
        handle_command(parts);
    }

    Err(ReadlineError::Eof) => {
        println!("\n^D");
        log::info("EOF detectado.");
        break;
    }

    Err(err) => {
        log::error(&format!("Erro na leitura: {:?}", err));
        break;
    }
    }
   }
}
