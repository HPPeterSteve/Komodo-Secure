mod cli;
mod vault;
mod hash;
use colored::*;
use rustyline::DefaultEditor;

fn show_help()
 {
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
help                       → ajuda
exit                       → sair
"
        .cyan()
    );
}

fn handle_command(parts: Vec<&str>) {
    match parts[0] {
        "isolate-directory" => {
            if let Some(dir) = parts.get(1) {
                vault::isolate_directory(dir);
                println!("{}", "✔ Diretório isolado".green());
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

        "help" => {
            show_help();

            println!("{}", "Digite o número da pergunta (ou Enter para pular):".purple());

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)
            .unwrap();

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
        "Solo-Sec v0.035alpha iniciado. Digite 'help'".bright_green()
    );

    loop {
        let readline = rl.readline(&"solo-sec> ".bright_blue().to_string());

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