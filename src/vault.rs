#[warn(dead_code)]
use std::env;
#[allow(dead_code)]
use std::io::Write;
use std::{
 fs::{self, /*metadata, */ OpenOptions}, io::{BufReader, BufWriter}, path::{Path, PathBuf}
};

#[allow(dead_code)]

use std::io::Read;


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

    Args {
        command,
        path,
        file,
    }
}

pub fn create(dir: &str) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("Erro ao criar cofre: {}", e);
        return;
    } else {
         let _path_not_specified = "C:/Users/Pedro/Desktop/Solo_SEC/sandbox/default_vault";
         println!("Cofre criado com sucesso em {}", dir);
    }
    println!("Criando cofre em {}", dir);
   }
#[allow(dead_code)]   
pub fn add_file(vault: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path = Path::new(file);

    // validações básicas
    
    if !vault_path.exists() {
        eprintln!("Cofre não encontrado: {}", vault);
        return Ok(());
    }

    if !file_path.exists() || !file_path.is_file() {
        eprintln!("Arquivo inválido: {}", file);
        return Ok(());
    }

    // pega só o nome do arquivo (segurança)
    
    let file_name = file_path
        .file_name()
        .ok_or("Falha ao obter nome do arquivo")?;

    let destination: PathBuf = vault_path.join(file_name);

    // evita sobrescrever sem querer
    if destination.exists() {
        eprintln!("Arquivo já existe no cofre: {}", destination.display());
        return Ok(());
    }

    let bytes = fs::copy(file_path, &destination)?;

    println!(
        "Arquivo adicionado ao cofre: {}\nBytes copiados: {}",
        destination.display(),
        bytes
    );

    Ok(())
}

#[allow(dead_code)]
pub fn safe_copy<P: AsRef<Path>>(src: P, dstn: P) -> core::result::Result<(), Box<dyn std::error::Error>> {
    let source_path = src.as_ref();
    let destination_path = dstn.as_ref();

    let temporary_path = destination_path.with_extension("tmp_copy");

    let source_file = fs::File::open(source_path)?;
    let mut origin_file = BufReader::new(source_file);

    let temporary_file = fs::File::create(&temporary_path)?;
    let mut writer = BufWriter::new(temporary_file);
    // vai até o ultimo byte
    let mut buffer = [0u8; 65536];
    loop {
        let bytes_read = origin_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        writer.write_all(&buffer[..bytes_read])?;

    } writer.flush()?;

    fs::rename(&temporary_path, destination_path)?;
    Ok(())

}
#[allow(dead_code)]
// No vault.rs

#[allow(dead_code)]
pub fn secure_store(src: &str, vault: &str, password: &str) {
    let source = Path::new(src);
    let vault_path = Path::new(vault);

    // 1. Validações de existência
    if !source.exists() {
        eprintln!("Erro: Arquivo de origem não existe: {}", src);
        return;
    }
    if !vault_path.exists() {
        eprintln!("Erro: Cofre (diretório) não existe: {}", vault);
        return;
    }

    // 2. Definir o destino dentro do cofre
    let file_name = match source.file_name() {
        Some(name) => name,
        None => return,
    };
    let destination = vault_path.join(file_name);

    // 3. Primeiro copiamos o arquivo para dentro do cofre com segurança
    if let Err(e) = safe_copy(source, &destination) {
        eprintln!("Erro ao copiar arquivo para o cofre: {}", e);
        return;
    }

    // 3. Copiamos o arquivo original para o cofre
    let destination_in_vault = vault_path.join(file_name);
    if let Err(e) = safe_copy(source, &destination_in_vault) {
        eprintln!("Erro ao copiar arquivo para o cofre: {}", e);
        return;
    }

    // 4. Criptografamos a cópia do arquivo dentro do cofre. A função encrypt_file criará um novo arquivo .enc
    // e manterá o original (não criptografado) no mesmo local.
    crate::crypto::encrypt_file(&destination_in_vault, password);

    // 5. Removemos a cópia não criptografada do arquivo que está dentro do cofre.
    // O arquivo criptografado (com extensão .enc) permanecerá.
    let _ = fs::remove_file(&destination_in_vault);

    // 6. Removemos o arquivo original da sua localização inicial.
    let _ = fs::remove_file(source);
}
#[allow(dead_code)]
// nessa função, é necessario ler e examinar a lista de arquivos
// precisamos garantir que os arquivos estão dentro do diretorio.

pub fn read_directory(directory: &str) -> Vec<String> {
    let mut files = Vec::new();
    let path = Path::new(directory);

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Erro ao ler diretório {}: {}", directory, e);
            return files;
        }
    };

    for entry in entries.flatten() {
        if let Ok(file_type) = entry.file_type() {
            if file_type.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    files.push(name.to_string());
                }
            }
        }
    }

    println!("Total de arquivos: {}", files.len());

    if files.is_empty() {
        eprintln!("Nenhum arquivo encontrado em: {}", directory);
    }

    files
}  



#[allow(dead_code)]
pub fn isolate_directory(directory: &str) {
let home_dir = home::home_dir().unwrap();
let sandbox_path = home_dir.join("Solo_SEC").join("sandbox");

    let files = read_directory(directory);
    let dir_sandbox = Path::new(&sandbox_path);

    if !dir_sandbox.exists() {
        std::fs::create_dir_all(&sandbox_path).expect("Failed to create sandbox directory");
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
    let mut permission = fs::metadata(directory)
        .expect("Failed to get metadata")
        .permissions();

        permission.set_readonly(true);
        fs::set_permissions(directory, permission).expect("Failure permission");
}

#[allow(dead_code)]

pub fn allow_write(path: &str) {
    // nota é preciso declarar o arquivo antes de verificar se ele existe, para evitar erros de permissão.
   
    // ou criar ele e depois checar se existe
    let file_exists = std::path::Path::new(path);
    if !file_exists.exists() {
        println!("Arquivo não encontrado: {}", path);

        return;
    }
    let _path_write = fs::metadata(&file_exists);
    let mut permission = fs::metadata(&file_exists)
      
        .expect("Falha ao conseguir metadata")
        .permissions();

    permission.set_readonly(false);

    fs::set_permissions(path, permission).expect("Falha ao setar permissão de escrita");

    let mut _file = OpenOptions::new()

        .write(true)
        .open(&file_exists)
        .expect("Falha ao abrir arquivo para escrita");

    writeln!(_file, "Permissão de escrita concedida para {}", path)
        .expect("Falha ao escrever no arquivo");

}
#[allow(dead_code)]
pub fn delete_sandbox<P: AsRef<Path>>(directory: P) -> std::result::Result<(), std::io::Error> {
    let info_files = directory.as_ref();
    if info_files.exists() && (info_files).is_dir() {
        std::fs::remove_dir_all(info_files)?;
        println!(" OSandbox deletada com sucesso: {}", info_files.display());
        {
            eprintln!(
                "Não foi possivel deletar diretório: {}",
                info_files.display()
            );
        }
    } else {
        eprintln!(
            "Sandbox não encontrada ou não é um diretório: {}",
            info_files.display()
        );
    }

    Ok(())
}

pub fn help() {

    println!("Commands:");
    println!("create-vault <path>");
    println!("add-file <vault> <file>");
}