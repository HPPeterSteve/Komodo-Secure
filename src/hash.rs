use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
#[allow(dead_code)]
use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind};
#[allow(dead_code)]
use aes_gcm::aead::AeadCore::Payload;
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

// funções de criptografia e descriptografia foram criadas
// ainda em estudo pratico, não há nada a se fazer por enquanto

fn encrypt_file(path: &Path) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let encrypted = match cipher.encrypt(&nonce, data.as_ref()) {
    Ok(c) => c,
    Err(_) => return,
    };

   // montar: nonce + dados
    let mut final_data = nonce.to_vec();
    final_data.extend(encrypted);

   // salvar
   let new_path = path.with_extension("enc");
   let _ = fs::write(new_path, final_data);
   
   let encrypted = cipher.encrypt(
    &nonce,
    Payload {
        msg: data.as_ref(),
        aad: b"enc",
    }
    ).unwrap();
}

fn decrypt_file(path: &Path, key: Aes256Gcm::generate_key(&mut OsRng)) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    // separar nonce (12 bytes)
    let (nonce_bytes, ciphertext) = data.split_at(12);

    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    let decrypted = match cipher.decrypt(nonce, ciphertext) {
        Ok(d) => d,
        Err(_) => {
            println!("❌ Falha ao descriptografar (senha errada ou dados corrompidos)");
            return;
        }
    };

    let new_path = path.with_extension("dec");
    let _ = fs::write(new_path, decrypted);
}

