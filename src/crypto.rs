use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use hmac::Hmac;
use sha2::Sha256;
use rand::RngCore;
use std::{fs, path::Path};

type HmacSha256 = Hmac<Sha256>;

const ITERATIONS: u32 = 100_000; // recomendado >= 100k
const SALT_LEN: usize = 16;

/// Deriva uma chave AES-256 a partir de uma senha e salt
fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut _key = [0u8; 32];
    pbkdf2_hmac::<HmacSha256>(
        password.as_bytes(),
        salt,
        ITERATIONS,
        &mut _key,
    );
    _key
}

/// Criptografa um arquivo usando AES-256-GCM + PBKDF2
pub fn encrypt_file(path: &Path, password: &str) {
    // 1. Ler dados
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Erro ao ler arquivo: {}", e);
            return;
        }
    };

    // 2. Gerar salt e derivar chave
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key_bytes = derive_key_from_password(password, &salt);

    // 3. Inicializar cifra e gerar nonce
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("Chave inválida");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // 4. Criptografar
    let encrypted = match cipher.encrypt(&nonce, data.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Erro na criptografia: {}", e);
            return;
        }
    };

    // 5. Salvar: SALT (16 bytes) + NONCE (12 bytes) + CIPHERTEXT
    let mut final_data = Vec::new();
    final_data.extend_from_slice(&salt);
    final_data.extend_from_slice(&nonce);
    final_data.extend_from_slice(&encrypted);

    let new_path = path.with_extension("enc");
    if let Err(e) = fs::write(&new_path, final_data) {
        eprintln!("Erro ao salvar arquivo: {}", e);
    } else {
        println!("Arquivo criptografado salvo em: {:?}", new_path);
    }
}

/// Descriptografa um arquivo criptografado com `encrypt_file`
pub fn decrypt_file(path: &Path, password: &str) {
    // 1. Ler arquivo
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Erro ao ler arquivo criptografado: {}", e);
            return;
        }
    };

    // 2. Verificar tamanho mínimo (SALT + NONCE)
    if data.len() < SALT_LEN + 12 {
        eprintln!("Erro: Arquivo corrompido ou muito pequeno.");
        return;
    }

    // 3. Extrair salt, nonce e ciphertext
    let (salt, rest) = data.split_at(SALT_LEN);
    let (nonce_slice, ciphertext) = rest.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice);

    // 4. Derivar chave
    let key_bytes = derive_key_from_password(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("Chave inválida");

    // 5. Descriptografar
    let decrypted = match cipher.decrypt(nonce, ciphertext) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Erro na descriptografia: {}", e);
            return;
        }
    };

    // 6. Salvar arquivo restaurado
    let new_path = path.with_extension("dec");
    if let Err(e) = fs::write(&new_path, decrypted) {
        eprintln!("Erro ao salvar arquivo descriptografado: {}", e);
    } else {
        println!("Arquivo descriptografado salvo em: {:?}", new_path);
    }
}

