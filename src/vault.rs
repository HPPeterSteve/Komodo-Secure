use std::io::{Read, Write};
use std::{
    fs,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};
use std::ffi::{c_char, CString};

unsafe extern "C" {
    fn try_hard_isolate(path: *const c_char) -> bool;
}

pub fn isolate_directory(directory: &str) {
    let home_dir = home::home_dir().unwrap_or_default();
    let sandbox_path = home_dir.join("Komodo_SEC").join("sandbox");

    let files = read_directory(directory);
    let dir_sandbox = Path::new(&sandbox_path);

    if !dir_sandbox.exists() {
        if let Err(e) = std::fs::create_dir_all(&sandbox_path) {
            eprintln!("Falha ao criar diretório sandbox: {}", e);
            return;
        }
    }

    let full_path = dir_sandbox.join(directory);
    if !full_path.exists() {
        if let Err(e) = std::fs::create_dir_all(&full_path) {
            eprintln!("Falha ao criar subdiretório sandbox: {}", e);
            return;
        }
    }

    let c_path = match CString::new(directory) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Caminho inválido para FFI (contém byte nulo?)");
            return;
        }
    };

    println!("Tentando isolamento avançado (mount namespace + readonly)...");

    let isolated = unsafe { try_hard_isolate(c_path.as_ptr()) };

    if isolated {
        println!("Isolamento forte aplicado (namespace + readonly)");
    } else {
        println!("Isolamento namespace falhou (provável falta de privilégio)");
        println!("Aplicando isolamento básico (readonly)...");
    }

    println!("Isolando diretório {}", directory);
    println!("Arquivos encontrados:");

    for file in files {
        println!(" - {}", file);
    }

    if let Ok(metadata) = fs::metadata(directory) {
        let mut permission = metadata.permissions();
        permission.set_readonly(true);
        if let Err(e) = fs::set_permissions(directory, permission) {
            eprintln!("Falha ao aplicar permissão readonly: {}", e);
        } else {
            println!("Permissão readonly aplicada com sucesso (fallback)");
        }
    } else {
        eprintln!("Não foi possível ler metadados do diretório");
    }
}

pub fn create(dir: &str) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("Erro ao criar cofre: {}", e);
        return;
    } else {
        println!("Cofre criado com sucesso em {}", dir);
    }
}

pub fn add_file(vault: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path = Path::new(file);

    if !vault_path.exists() {
        eprintln!("Cofre não encontrado: {}", vault);
        return Ok(());
    }

    if !file_path.exists() || !file_path.is_file() {
        eprintln!("Arquivo inválido: {}", file);
        return Ok(());
    }

    let file_name = file_path
        .file_name()
        .ok_or("Falha ao obter nome do arquivo")?;

    let destination: PathBuf = vault_path.join(file_name);

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

pub fn safe_copy<P: AsRef<Path>>(src: P, dstn: P) -> Result<(), Box<dyn std::error::Error>> {
    let source_path = src.as_ref();
    let destination_path = dstn.as_ref();

    let temporary_path = destination_path.with_extension("tmp_copy");

    let source_file = fs::File::open(source_path)?;
    let mut origin_file = BufReader::new(source_file);

    let temporary_file = fs::File::create(&temporary_path)?;
    let mut writer = BufWriter::new(temporary_file);
    
    let mut buffer = [0u8; 65536];
    loop {
        let bytes_read = origin_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        writer.write_all(&buffer[..bytes_read])?;
    }
    writer.flush()?;

    fs::rename(&temporary_path, destination_path)?;
    Ok(())
}

pub fn secure_store(src: &str, vault: &str, password: &str) {
    let source = Path::new(src);
    let vault_path = Path::new(vault);

    if !source.exists() {
        eprintln!("Erro: Arquivo de origem não existe: {}", src);
        return;
    }
    if !vault_path.exists() {
        eprintln!("Erro: Cofre (diretório) não existe: {}", vault);
        return;
    }

    let file_name = match source.file_name() {
        Some(name) => name,
        None => return,
    };
    let destination = vault_path.join(file_name);

    if let Err(e) = safe_copy(source, &destination) {
        eprintln!("Erro ao copiar arquivo para o cofre: {}", e);
        return;
    }
    let destination_in_vault = destination;

    if let Err(e) = crate::crypto::encrypt_file(&destination_in_vault, password) {
        eprintln!("Erro ao criptografar arquivo no cofre: {}", e);
        return;
    }
    let _ = fs::remove_file(&destination_in_vault);
    let _ = fs::remove_file(source);
}

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

pub fn allow_write(path: &str) {
    let file_exists = Path::new(path);
    if !file_exists.exists() {
        println!("Arquivo não encontrado: {}", path);
        return;
    }
    
    if let Ok(metadata) = fs::metadata(file_exists) {
        let mut permission = metadata.permissions();
        permission.set_readonly(false);
        if let Err(e) = fs::set_permissions(path, permission) {
            eprintln!("Falha ao setar permissão de escrita: {}", e);
        }
    }
}

pub fn remove_file(vault: &str, file_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path = vault_path.join(file_name);

    if !file_path.exists() {
        return Err(format!("Arquivo '{}' não encontrado no cofre '{}'", file_name, vault).into());
    }

    fs::remove_file(file_path)?;
    println!("✔ Arquivo '{}' removido do cofre '{}'", file_name, vault);
    Ok(())
}

pub fn get_vault_status(vault: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    if !vault_path.exists() {
        return Err(format!("Cofre '{}' não encontrado", vault).into());
    }

    let files = read_directory(vault);
    let mut total_size = 0;
    for file in &files {
        let path = vault_path.join(file);
        if let Ok(metadata) = fs::metadata(path) {
            total_size += metadata.len();
        }
    }

    println!("\n--- Status do Cofre: {} ---", vault);
    println!("Total de arquivos: {}", files.len());
    println!("Tamanho total: {:.2} KB", total_size as f64 / 1024.0);
    Ok(())
}
