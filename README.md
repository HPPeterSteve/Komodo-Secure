Komodo SecureA high-performance, hybrid security architecture merging the safety of Rust with the raw power of C.📖 Introdução / Introduction<details open><summary><b>🇧🇷 Português</b></summary><p align="justify">Komodo Secure é um projeto que combina o poder do <b>Rust</b> com a flexibilidade do <b>C</b>, criando uma arquitetura híbrida focada em segurança, desempenho e controle de baixo nível. O sistema implementa recursos avançados de proteção tanto em ambientes Windows quanto Linux, incluindo sandboxing, criptografia e isolamento de processos.</p></details><details><summary><b>🇺🇸 English</b></summary><p align="justify">Komodo Secure is a project that merges the strengths of <b>Rust</b> and <b>C</b>, creating a hybrid architecture focused on security, performance, and low-level control. It delivers advanced protection features for both Windows and Linux, including sandboxing, cryptography, and process isolation.</p></details>🗺️ Architecture OverviewSnippet de códigograph TD
    A[Rust Layer: Logic & CLI] -->|FFI Bridge| B[C Core: Low-Level Engine]
    B --> C{OS Security Layer}
    C -->|Windows| D[AppContainer / Win32k Blocking]
    C -->|Linux| E[Namespaces / Seccomp]
[!NOTE]A ponte FFI (Foreign Function Interface) permite que o Rust gerencie a memória com segurança enquanto o C interage diretamente com as APIs de kernel mais profundas.🛡️ Security FeaturesFeature🪟 Windows🐧 LinuxIsolationAppContainer & Isolated DesktopNamespaces (PID, Net, Mount)MonitoringWFP Firewallinotify MonitoringKernel ProtectionWin32k Blocking & DEP/ASLRSeccomp FilteringConcurrencyWindows Mutexpthread Mutex LockingCryptographyNative CryptoAPIOpenSSL🔌 FFI BindingsO projeto expõe funções críticas do Core em C para o ecossistema Rust:Vault LifecycleCint vault_create_ffi(const char *name, int vault_type, const char *path, const char *password);
int vault_delete_ffi(uint32_t id, const char *password);
int vault_unlock_ffi(uint32_t id, const char *password);
Cryptography & SandboxCint vault_encrypt_ffi(uint32_t id, const char *password);
int vault_sandbox_ffi(uint32_t id, const char *password);
📂 Project StructureBash📦 Komodo-Secure
 ┣ 📂 src/          # Rust source (High-level logic & CLI)
 ┣ 📂 c_src/        # C core (Hardware & Kernel interaction)
 ┃ ┣ 📂 core_linux/ # Linux-specific security logic
 ┃ ┗ 📂 Core/       # Windows sandbox & API hooks
 ┣ 📂 tests/        # Multi-language test suite
 ┗ 📜 Cargo.toml    # Rust dependencies & Build script
🔐 Cryptography StackO Komodo Secure utiliza algoritmos de última geração para garantir a integridade dos dados:AES-256-GCM: Criptografia autenticada para dados em repouso.Argon2: Derivação de chave resistente a ataques de GPU.PBKDF2: 310.000 iterações (Padrão OWASP 2023).SHA-256: Verificação de integridade estrutural.⚡ Performance BenchmarksOperationSpeed / LatencyAES-256 (Enc/Dec)~500 MB/sArgon2 KDF~100msPBKDF2 KDF~150msFFI Overhead< 0.1ms🚀 Installation🪟 WindowsPowerShellgit clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure
cargo build --release --target x86_64-pc-windows-msvc
🐧 LinuxBashgit clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure
cargo build --release
💻 Usage ExamplesCriar um novo VaultBashkomodo-secure create-vault /home/user/MyVault
Criptografar arquivosBashkomodo-secure encrypt file.txt "MyPassword123"
🤝 ContributingContribuições são o que fazem a comunidade open source um lugar incrível!git checkout -b feature/minha-featuregit commit -m "feat: nova feature"git push origin feature/minha-featureAbra um Pull Request 🚀📜 LicenseDistribuído sob a licença MIT. Veja LICENSE para mais informações.👤 AuthorHPPeterSteveSecurity ResearcherRust + C Systems DeveloperFocused on sandboxing & cryptography<p align="center">Feito com ❤️ por <a href="https://github.com/HPPeterSteve">HPPeterSteve</a></p>
