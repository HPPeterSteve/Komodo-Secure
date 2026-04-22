Komodo Secure




Introdução
🇧🇷 Português

Komodo Secure é um projeto que combina o poder do Rust com a flexibilidade do C, criando uma arquitetura híbrida focada em segurança, desempenho e controle de baixo nível.

O sistema implementa recursos avançados de proteção tanto em ambientes Windows quanto Linux, incluindo sandboxing, criptografia e isolamento de processos.

English

Komodo Secure is a project that merges the strengths of Rust and C, creating a hybrid architecture focused on security, performance, and low-level control.

It delivers advanced protection features for both Windows and Linux, including sandboxing, cryptography, and process isolation.

Table of Contents
Architecture Overview
Security Features
FFI Bindings
Project Structure
Cryptography
Performance
Installation
Usage Examples
Contributing
License
Architecture Overview
                       +-------------+
                       | Rust Layer  |
                       +-------------+
                             |
                             | FFI bridge
                             |
                       +-------------+
                       |    C Core   |
                       +-------------+
                             |
                             | Windows/Linux APIs
                             |
                     +----------------------+
                     | OS Security Layer    |
                     +----------------------+
Security Features
🪟 Windows
AppContainer Isolation
Restricted Tokens
DEP / ASLR
WFP Firewall
Win32k Blocking
Isolated Desktop
Linux
inotify Monitoring
Namespaces (PID, Mount, Network)
Seccomp Filtering
OpenSSL Cryptography
pthread Mutex Locking
FFI Bindings

O projeto expõe funções C para Rust via FFI:

Vault Lifecycle
int vault_create_ffi(const char *name, int vault_type, const char *path, const char *password);
int vault_delete_ffi(uint32_t id, const char *password);
int vault_rename_ffi(uint32_t id, const char *new_name, const char *password);
int vault_unlock_ffi(uint32_t id, const char *password);
int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass);
Cryptography
int vault_encrypt_ffi(uint32_t id, const char *password);
int vault_decrypt_ffi(uint32_t id, const char *password);
Monitoring
int vault_scan_ffi(uint32_t id);
int vault_resolve_ffi(uint32_t id, const char *password);
Info
void vault_info_ffi(uint32_t id);
void vault_list_ffi();
void vault_files_ffi(uint32_t id);
Sandbox
int vault_sandbox_ffi(uint32_t id, const char *password);
Project Structure
src/            # Rust source
c_src/          # C core
core_linux/     # Linux-specific logic
Core/           # Windows sandbox
tests/          # Test suite
Cargo.toml      # Rust dependencies
README.md       # Documentation
Cryptography
AES-256-GCM (Authenticated Encryption)
Argon2 (Key Derivation)
PBKDF2 (310k iterations - OWASP 2023)
SHA-256 (Integrity)
Performance
Operation	Speed
AES-256 Encryption	~500 MB/s
AES-256 Decryption	~500 MB/s
Argon2	~100ms
PBKDF2	~150ms
FFI Call	<0.1ms
Installation
🪟 Windows
git clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure
cargo build --release --target x86_64-pc-windows-msvc
🐧 Linux
git clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure
cargo build --release
Usage Examples
Criar Vault
komodo-secure create-vault /home/user/MyVault
Adicionar Arquivo
komodo-secure add-file /home/user/file.txt
Criptografar
komodo-secure encrypt file.txt "MyPassword123"
Descriptografar
komodo-secure decrypt file.txt.enc "MyPassword123"
Status
komodo-secure status /home/user/MyVault
🤝 Contributing

Contribuições são bem-vindas!

git checkout -b feature/minha-feature
git commit -m "feat: nova feature"
git push origin feature/minha-feature

Abra um Pull Request 🚀

📜 License

Este projeto está sob a licença MIT.

Author

HPPeterSteve

Security Researcher
Rust + C Systems Developer
Focused on sandboxing & cryptography
