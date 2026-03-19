use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

pub fn encrypt_file(path: &Path, key: &[u8; 32]) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted = match cipher.encrypt(&nonce, data.as_ref()) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut final_data = nonce.to_vec();
    final_data.extend(encrypted);

    let new_path = path.with_extension("enc");
    let _ = fs::write(new_path, final_data);
}

pub fn decrypt_file(path: &Path, key: &[u8; 32]) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let (nonce_bytes, ciphertext) = data.split_at(12);

    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    let decrypted = match cipher.decrypt(nonce, ciphertext) {
        Ok(d) => d,
        Err(_) => {
            println!("❌ Falha ao descriptografar");
            return;
        }
    };

    let new_path = path.with_extension("dec");
    let _ = fs::write(new_path, decrypted);
}