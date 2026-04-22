
# Komodo Secure

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

## 📖 Introdução

🇧🇷 **Português**

Komodo Secure é um projeto que combina o poder do Rust com a flexibilidade do C, criando uma arquitetura híbrida focada em segurança, desempenho e controle de baixo nível.  
O sistema implementa recursos avançados de proteção tanto em ambientes Windows quanto Linux, incluindo sandboxing, criptografia e isolamento de processos.

🇺🇸 **English**

Komodo Secure is a project that merges the strengths of Rust and C, creating a hybrid architecture focused on security, performance, and low-level control.  
It delivers advanced protection features for both Windows and Linux, including sandboxing, cryptography, and process isolation.

---

## 📑 Table of Contents
1. [Architecture Overview](#architecture-overview)  
2. [Security Features](#security-features)  
3. [FFI Bindings](#ffi-bindings)  
4. [Project Structure](#project-structure)  
5. [Cryptography](#cryptography)  
6. [Performance](#performance)  
7. [Installation](#installation)  
8. [Usage Examples](#usage-examples)  
9. [Contributing](#contributing)  
10. [License](#license)  
11. [Author](#author)  

---

## 🏗️ Architecture Overview

```plaintext
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
🔐 Security Features
🪟 Windows
AppContainer Isolation

Restricted Tokens

DEP / ASLR

WFP Firewall

Win32k Blocking

Isolated Desktop

🐧 Linux
inotify Monitoring

Namespaces (PID, Mount, Network)

Seccomp Filtering

OpenSSL Cryptography

pthread Mutex Locking

📦 FFI Bindings
O projeto expõe funções C para Rust via FFI:

Vault Lifecycle
c
int vault_create_ffi(const char *name, int vault_type, const char *path, const char *password);
int vault_delete_ffi(uint32_t id, const char *password);
int vault_rename_ffi(uint32_t id, const char *new_name, const char *password);
int vault_unlock_ffi(uint32_t id, const char *password);
int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass);
Cryptography
c
int vault_encrypt_ffi(uint32_t id, const char *password);
int vault_decrypt_ffi(uint32_t id, const char *password);
Monitoring
c
int vault_scan_ffi(uint32_t id);
int vault_resolve_ffi(uint32_t id, const char *password);
Info
c
void vault_info_ffi(uint32_t id);
void vault_list_ffi();
void vault_files_ffi(uint32_t id);
Sandbox
c
int vault_sandbox_ffi(uint32_t id, const char *password);
📂 Project Structure
Código
src/            # Rust source
c_src/          # C core
core_linux/     # Linux-specific logic
Core/           # Windows sandbox
tests/          # Test suite
Cargo.toml      # Rust dependencies
README.md       # Documentation
🔑 Cryptography
AES-256-GCM (Authenticated Encryption)

Argon2 (Key Derivation)

PBKDF2 (310k iterations - OWASP 2023)

SHA-256 (Integrity)

📊 Performance
Operation	Speed
AES-256 Encryption	~500 MB/s
AES-256 Decryption	~500 MB/s
Argon2	~100ms
PBKDF2	~150ms
FFI Call	


⚙️ Installation
🪟 Windows
bash
git clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure
cargo build --release --target x86_64-pc-windows-msvc
🐧 Linux
bash
git clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure
cargo build --release
🚀 Usage Examples
bash
# Criar Vault
komodo-secure create-vault /home/user/MyVault

# Adicionar Arquivo
komodo-secure add-file /home/user/file.txt

# Criptografar
komodo-secure encrypt file.txt "MyPassword123"

# Descriptografar
komodo-secure decrypt file.txt.enc "MyPassword123"

# Status
komodo-secure status /home/user/MyVault
🤝 Contributing
Contribuições são bem-vindas!

bash
git checkout -b feature/minha-feature
git commit -m "feat: nova feature"
git push origin feature/minha-feature
Abra um Pull Request 🚀

📜 License
MIT License

Copyright (c) 2026 Steve Homer (Komodo Secure Project)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

👤 Author
HPPeterSteve

Security Researcher

Rust + C Systems Developer

Focused on sandboxing & cryptography
