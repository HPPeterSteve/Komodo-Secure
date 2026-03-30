use std::env;
use std::io::Write;
use std::{
    fs,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};
use std::io::Read;

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::*;
#[cfg(windows)]
use windows_sys::Win32::Security::*;
#[cfg(windows)]
use windows_sys::Win32::Foundation::*;

pub fn isolate_directory(directory: &str) {
    println!("Aplicando isolamento no Windows para: {}", directory);
    
    #[cfg(windows)]
    {
        // No Windows, usamos ACLs para tornar o diretório somente leitura
        // Esta é uma implementação simplificada para demonstrar o conceito
        println!("Configurando permissões de leitura (ACL) no Windows...");
        // Em uma implementação real, usaríamos SetFileSecurity ou SetNamedSecurityInfo
    }

    #[cfg(not(windows))]
    {
        println!("Aviso: Isolamento de diretório nativo não disponível nesta plataforma.");
    }

    if let Ok(metadata) = fs::metadata(directory) {
        let mut permission = metadata.permissions();
        permission.set_readonly(true);
        if let Err(e) = fs::set_permissions(directory, permission) {
            eprintln!("Falha ao aplicar permissão readonly: {}", e);
        } else {
            println!("Permissão readonly aplicada com sucesso.");
        }
    }
}

pub fn create(dir: &str) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("Erro ao criar cofre: {}", e);
    } else {
        println!("Cofre criado com sucesso em {}", dir);
    }
}

pub fn add_file(vault: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path = Path::new(file);

    if !vault_path.exists() {
        return Err(format!("Cofre não encontrado: {}", vault).into());
    }

    if !file_path.exists() || !file_path.is_file() {
        return Err(format!("Arquivo inválido: {}", file).into());
    }

    let file_name = file_path.file_name().ok_or("Falha ao obter nome do arquivo")?;
    let destination = vault_path.join(file_name);

    if destination.exists() {
        return Err(format!("Arquivo já existe no cofre: {}", destination.display()).into());
    }

    fs::copy(file_path, &destination)?;
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
        if bytes_read == 0 { break; }
        writer.write_all(&buffer[..bytes_read])?;
    }
    writer.flush()?;

    fs::rename(&temporary_path, destination_path)?;
    Ok(())
}

pub fn secure_store(src: &str, vault: &str, password: &str) {
    let source = Path::new(src);
    let vault_path = Path::new(vault);

    if !source.exists() || !vault_path.exists() {
        eprintln!("Erro: Origem ou destino não existe.");
        return;
    }

    let file_name = match source.file_name() {
        Some(name) => name,
        None => return,
    };
    let destination = vault_path.join(file_name);

    if let Err(e) = safe_copy(source, &destination) {
        eprintln!("Erro ao copiar: {}", e);
        return;
    }

    if let Err(e) = crate::crypto::encrypt_file(&destination, password) {
        eprintln!("Erro ao criptografar: {}", e);
        return;
    }
    let _ = fs::remove_file(&destination);
    let _ = fs::remove_file(source);
}

pub fn read_directory(directory: &str) -> Vec<String> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        files.push(name.to_string());
                    }
                }
            }
        }
    }
    files
}

pub fn remove_file(vault: &str, file_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path = vault_path.join(file_name);
    if !file_path.exists() {
        return Err("Arquivo não encontrado".into());
    }
    fs::remove_file(file_path)?;
    Ok(())
}

pub fn get_vault_status(vault: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    if !vault_path.exists() { return Err("Cofre não encontrado".into()); }
    let files = read_directory(vault);
    println!("Cofre: {} | Arquivos: {}", vault, files.len());
    Ok(())
}

pub fn allow_write(path: &str) {
    if let Ok(metadata) = fs::metadata(path) {
        let mut permission = metadata.permissions();
        permission.set_readonly(false);
        let _ = fs::set_permissions(path, permission);
    }
}
