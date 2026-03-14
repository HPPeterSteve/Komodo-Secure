use std::{fs::{self, OpenOptions}, path::Path};
#[warn(dead_code)]
use std::env;
#[allow(dead_code)]
use std::io::Write;

// é usado #[allow(dead_code)] para mitigar avisos de codigo não utilizado, tudo será orquestrado 
// diretamente ao main, e isso é intencional, pois o código é modularizado para facilitar a manutenção e a organização,
// é má pratica escrever codigo que não seja orquestrado diretamente na main de arquivos únicos.
#[allow(dead_code)]
pub struct Args {
    pub command: String,
    pub path: String,
    pub file: String,
} 
#[allow(dead_code)]
// A função get_args é responsável por coletar os argumentos de linha de comando fornecidos pelo usuário.
// essa função é essencial para politica de usabilidade deste programa.

pub fn get_args() -> Args {

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        help();
        std::process::exit(0);
    }

    let command = args.get(1).unwrap_or(&"".to_string()).clone();
    let path = args.get(2).unwrap_or(&"".to_string()).clone();
    let file = args.get(3).unwrap_or(&"".to_string()).clone();

    Args { command, path, file }
}

pub fn create(dir: &str) {
    if let Err(e) =  std::fs::create_dir_all(dir) {
        eprintln!("Erro ao criar cofre: {}", e);
        return; 
       }
    println!("Criando cofre em {}", dir);
}


pub fn add_file(vault: &str, file: &str){
    let diretory =  std::path::Path::new(vault);
    if !diretory.exists() {
        eprintln!("Cofre não encontrado: {}", vault);
        return;
    } 
    let file = fs::copy(file, diretory.join(file)).expect("Falha ao copiar arquivo para o cofre");

    
    println!("Adicionando arquivo {:?} ao cofre {}", file, vault);
}

#[allow(dead_code)]
// nessa função, é necessario ler e examinar a lista de arquivos
// precisamos garantir que os arquivos estão dentro do diretorio.
pub fn read_directory(directory: &str) -> Vec<String> {
    let mut files = Vec::new();
    let mut _counter  = 0;

    for entry in std::fs::read_dir(directory).unwrap().flatten() {
        if entry.file_type().unwrap().is_file() {
            if let Some(name) = entry.file_name().to_str() {
                files.push(name.to_string());
                _counter += 1;
            }           
        }
        println!("contagem de arquivos totais: {}", _counter);
        if _counter == 0 {
            eprintln!("Erro ao ler diretório/arquivos totais: {}", directory);
      }
    }
    files
}

const SANDBOX_DIR: &str = "C:/Users/Pedro/Desktop/Solo_SEC/sandbox";

#[allow(dead_code)]
pub fn isolate_directory(directory: &str) {

    let files = read_directory(directory);
    let dir_sandbox = Path::new(SANDBOX_DIR);
    if !dir_sandbox.exists() {
        std::fs::create_dir_all(SANDBOX_DIR).expect("Failed to create sandbox directory");
    }
    let full_path = dir_sandbox.join(directory);
    if !full_path.exists() {
        std::fs::create_dir_all(&full_path).expect("Failed to create sandbox subdirectory");
    }
    println!("Isolando diretório {}", directory);
    println!("Arquivos encontrados:");
    for file in files {
        println!(" - {}", file);
    } 
    let mut permission = fs::metadata(directory).expect("Failed to get metadata").permissions();
    permission.set_readonly(true);
    fs::set_permissions(directory, permission).expect("Failure permission");
    
}
#[allow(dead_code)]    
pub fn allow_write(path: &str) {
    // nota é preciso declarar o arquivo antes de verificar se ele existe, para evitar erros de permissão.
    // ou criar ele e depois checar se existe
    let file_exists = std::path::Path::new(path);
    if !file_exists.exists(){
        println!("Arquivo não encontrado: {}", path);

        return;
    }   
     let _path_write = fs::metadata(&file_exists);
     let mut permission = fs::metadata(&file_exists).expect("Falha ao conseguir metadata").permissions();
     permission.set_readonly(false);

     fs::set_permissions(path, permission).expect("Falha ao setar permissão de escrita");

     let mut _file = OpenOptions::new()
     .write(true)
     .open(&file_exists)
     .expect("Falha ao abrir arquivo para escrita");
     writeln!(_file, "Permissão de escrita concedida para {}", path).expect("Falha ao escrever no arquivo");
}

pub fn help() {

    println!("Commands:");
    println!("create-vault <path>");
    println!("add-file <vault> <file>");
    
}