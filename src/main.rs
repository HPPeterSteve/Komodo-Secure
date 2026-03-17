
mod cli;
mod immutable;
mod usb_key;
mod vault;

fn main() {
    loop {
        println!(
            "
        Solo-Sec v0.03 Alpha
        Modules: 6
        Commands: 4


        Digite um comando (ou 'exit' para sair):
        comandos existentes:
        create-vault  
        add-file 
        allow-write
        read-directory
        isolate-directory
        help
        "
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        if input == "exit" {
            break;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "isolate-directory" => {
                if let Some(directory) = parts.get(1) {
                    vault::isolate_directory(directory);
                } else {
                    println!("Falta o caminho do diretório!");
                }
            }
            "create-vault" => {
                if let Some(&path) = parts.get(1) {
                    vault::create(path);
                } else {
                    println!("Falta o caminho do cofre!");
                }
            }
            "add-file" => {
                if let (Some(vault), Some(file)) = (parts.get(1), parts.get(2)) {
                    let result = vault::safe_copy(vault, file);
                    if let Err(e) = result {
                        eprintln!("Erro ao adicionar arquivo: {}", e);
                    }
                } else {
                    println!("Faltam argumentos para add-file!");
                }
            }
            "allow-write" => {
                if let Some(path) = parts.get(1) {
                    vault::allow_write(path);
                } else {
                    println!("Falta o caminho do arquivo!");
                }
            }
            "read-directory" => {
                if let Some(directory) = parts.get(1) {
                    let files = vault::read_directory(directory);
                    println!("Arquivos no diretório {}: {:?}", directory, files);
                } else {
                    println!("Falta o caminho do diretório!");
                }
            }
            "help" => {
                println!("Digite o número da pergunta para obter a resposta:");

                if let Some(answer) = parts.get(1) {
                    cli::questions(answer);
                } else {
                    let mut input = String::new();

                    std::io::stdin()
                        .read_line(&mut input)
                        .expect("erro ao ler entrada");

                    let answer = input.trim();
                    cli::questions(answer);
                }
            }

            _ => {
                println!("Comando desconhecido: {}", parts[0]);
                println!("Digite 'questions' para ver ajuda.");
            }
        }
    }
}
