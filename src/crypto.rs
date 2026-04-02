use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;
use std::{fs, path::Path};



const ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;

/// Deriva uma chave AES-256 a partir de uma senha e salt
fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut _key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        ITERATIONS,
        &mut _key,
    );
    _key
}

/// Criptografa um arquivo usando AES-256-GCM + PBKDF2
pub fn encrypt_file(path: &Path, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Ler dados
    let data = fs::read(path)?;

    // 2. Gerar salt e derivar chave
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key_bytes = derive_key_from_password(password, &salt);

    // 3. Inicializar cifra e gerar nonce
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| "Chave inválida")?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // 4. Criptografar
    let encrypted = cipher.encrypt(&nonce, data.as_ref()).map_err(|e| format!("Erro na criptografia: {}", e))?;

    // 5. Salvar: SALT (16 bytes) + NONCE (12 bytes) + CIPHERTEXT
    let mut final_data = Vec::new();
    final_data.extend_from_slice(&salt);
    final_data.extend_from_slice(&nonce);
    final_data.extend_from_slice(&encrypted);

    let new_path = path.with_extension("enc");
    fs::write(&new_path, final_data)?;
    println!("Arquivo criptografado salvo em: {:?}", new_path);
    Ok(())
}
#[allow(dead_code)]
/// Descriptografa um arquivo criptografado com `encrypt_file`
pub fn decrypt_file(path: &Path, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Ler arquivo
    let data = fs::read(path)?;

    // 2. Verificar tamanho mínimo (SALT + NONCE)
    if data.len() < SALT_LEN + 12 {
        return Err("Erro: Arquivo corrompido ou muito pequeno.".into());
    }

    // 3. Extrair salt, nonce e ciphertext
    let (salt, rest) = data.split_at(SALT_LEN);
    let (nonce_slice, ciphertext) = rest.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice);

    // 4. Derivar chave
    let key_bytes = derive_key_from_password(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| "Chave inválida")?;

    // 5. Descriptografar
    let decrypted = cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Erro na descriptografia: {}", e))?;

    // 6. Salvar arquivo restaurado
    let new_path = path.with_extension("dec");
    fs::write(&new_path, decrypted)?;
    println!("Arquivo descriptografado salvo em: {:?}", new_path);
    Ok(())
}
pub fn derive_master_key(password: &str, usb_key_bytes: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // Concatena senha + chave USB para criar material mais forte
    let mut combined = Vec::new();
    combined.extend_from_slice(password.as_bytes());
    combined.extend_from_slice(usb_key_bytes);

    // Usa um salt fixo ou derivado (aqui usamos um salt fixo bom o suficiente)
    let salt = b"KomodoVault_Salt_v0.1_2026"; // pode ser mudado depois

    let mut master_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        &combined,
        salt,
        ITERATIONS * 2,        // mais iterações quando combinamos dois fatores
        &mut master_key,
    );

    Ok(master_key)
}