use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use std::fs;
use std::path::Path;

pub fn encrypt_file(path: &Path, key_bytes: &[u8; 32]) {
    // 1. Ler os dados
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Erro ao ler arquivo: {}", e);
            return;
        }
    };

    // 2. Inicializar cifra e gerar Nonce aleatório
    let cipher = Aes256Gcm::new_from_slice(key_bytes).expect("Chave inválida");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // Agora o OsRng será encontrado

    // 3. Criptografar (A trait Aead precisa estar no escopo para o .encrypt funcionar)
    let encrypted = match cipher.encrypt(&nonce, data.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Erro na criptografia: {}", e);
            return;
        }
    };

    // 4. Concatenar Nonce + Ciphertext (Necessário para conseguir decriptar depois)
    let mut final_data = nonce.to_vec();
    final_data.extend(encrypted);

    let new_path = path.with_extension("enc");
    if let Err(e) = fs::write(new_path, final_data) {
        eprintln!("Erro ao salvar arquivo: {}", e);
    }
}
#[allow(dead_code)]
pub fn decrypt_file(path: &Path, key_bytes: &[u8; 32]) {
    // 1. Ler o arquivo criptografado (.enc)
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Erro ao ler arquivo criptografado: {}", e);
            return;
        }
    };

    // 2. O AES-GCM usa nonces de 12 bytes. 
    // Precisamos separar o que é Nonce do que é dado criptografado.
    if data.len() < 12 {
        eprintln!("Erro: Arquivo corrompido ou muito pequeno.");
        return;
    }

    let (nonce_slice, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice);

    // 3. Inicializar a cifra com a mesma chave
    let cipher = Aes256Gcm::new_from_slice(key_bytes).expect("Chave inválida");

    // 4. Decriptar
    let decrypted = match cipher.decrypt(nonce, ciphertext) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("❌ Falha na decriptação! Senha incorreta ou arquivo violado.");
            return;
        }
    };

    // 5. Salvar o arquivo original (removendo a extensão .enc)
    let mut new_path = path.to_path_buf();
    new_path.set_extension(""); // Remove o .enc e tenta voltar ao original
    
    // Se o arquivo original não tinha extensão, você pode setar uma específica ou manter assim
    if let Err(e) = fs::write(&new_path, decrypted) {
        eprintln!("Erro ao salvar arquivo decriptado: {}", e);
    } else {
        println!("✔ Arquivo restaurado: {:?}", new_path.file_name().unwrap());
    }
}