use crate::crypto;
use crate::usb_key; // ou o módulo onde está read_and_validate_usb_key

#[derive(Debug)]
pub enum VaultError {
    UsbKeyMissing(String),
    WrongPassword,
    DecryptionFailed(String),
    IoError(String),
}

pub fn unlock_vault(
    vault_path: &Path,
    password: &str,
    usb_key_path: &str,
) -> Result<(), VaultError> {
    
    // 1. Ler e validar chave USB
    let usb_key_bytes = match usb_key::read_and_validate_usb_key(usb_key_path) {
        Ok(bytes) => bytes,
        Err(msg) => return Err(VaultError::UsbKeyMissing(msg)),
    };

    // 2. Derivar chave mestra combinando senha + USB key
    let master_key = match crypto::derive_master_key(password, &usb_key_bytes) {
        Ok(key) => key,
        Err(_) => return Err(VaultError::WrongPassword),
    };

    // 3. TODO: Usar a master_key para descriptografar o vault de verdade
    // Por enquanto, vamos reutilizar sua função decrypt_file (mas adaptada)
    
    // Exemplo temporário (ainda usando password, mas na próxima versão mudamos):
    if let Err(e) = crypto::decrypt_file(vault_path, password) {  // ← vamos melhorar isso depois
        return Err(VaultError::DecryptionFailed(e.to_string()));
    }

    println!("Vault destravado com sucesso!");
    Ok(())
}