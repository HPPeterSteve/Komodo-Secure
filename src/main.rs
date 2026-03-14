mod cli;
mod vault;
mod immutable;
mod usb_key;

fn main() {
    loop {
        println!("Digite um comando (ou 'exit' para sair):
        comandos existentes:
        create-vault <path>
        add-file <vault> <file> ");
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
            "create-vault" => {
                if let Some(path) = parts.get(1) {
                    vault::create(path);
                } else {
                    println!("Falta o caminho do cofre!");
                }
            }
            "add-file" => {
                if let (Some(vault), Some(file)) = (parts.get(1), parts.get(2)) {
                    vault::add_file(vault, file);
                } else {
                    println!("Faltam argumentos para add-file!");
                }
            }
            _ => cli::help(),
        }
    }
}