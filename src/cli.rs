use std::env;

#[allow(dead_code)]
pub struct Args {
    pub command: String,
    pub path: String,
    pub file: String,
}
#[allow(dead_code)]
pub fn get_args() -> Args {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        help();
        std::process::exit(0);
    }

    let command = args.get(1).unwrap_or(&"".to_string()).clone();
    let path = args.get(2).unwrap_or(&"".to_string()).clone();
    let file = args.get(3).unwrap_or(&"".to_string()).clone();

    Args {
        command,
        path,
        file,
    }
}
pub fn questions(_answer: &str) {
    println!(
        "
    Perguntas:
    (1) Como criar um cofre?
    (2) Como adicionar um arquivo ao cofre?
    (3) Como ler os arquivos dentro do cofre?
    (4) Como permitir escrita em um arquivo específico dentro do cofre?
    (5) Como tornar um arquivo imutável dentro do cofre?
    (6) Funcionalidades futuras ;)"
    );
    match _answer {
    "1" => println!("Para criar um cofre, use o comando 'create-vault' mais: (caminho_do_cofre)"),
    "2" => println!("Para adicionar um arquivo ao cofre, use o comando 'add-file (caminho_do_cofre) (caminho_do_arquivo)'."),
    "3" => println!("Para ler os arquivos dentro do cofre, use o comando 'read-directory (caminho_do_cofre)'."),
    "4" => println!("Para permitir escrita em um arquivo específico dentro do cofre, use o comando 'allow-write (caminho_do_arquivo)'."),
    "5" => println!("Para tornar um arquivo imutável dentro do cofre, use o comando 'make-immutable (caminho_do_arquivo)'."),
    "6" => println!("Funcionalidade futuras serão anunciadas em breve! no momento estaremos focados em verificação de chaves usb para a adição de chaves de segurança para não permitir a exclusão por meio de arquivos maliciosos,
    focaremos em melhoria de usabilidade, futuras mudanças de arquitetura e otimizações"),
    _ => println!("Resposta inválida. Por favor, escolha uma opção de 1 a 7."),
   }
}
pub fn help() {
    println!("Comandos:");
    println!("create-vault <path>");
    println!("add-file <vault> <file>");
}
