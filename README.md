# 🔐 Komodo-Secure v0.5.0
_reliable, compact, and secure_
> Rust-based security CLI for file protection, isolation, and secure management, focused on robustness and usability.
## 🚀 Overview
**Komodo-Secure** is a command-line interface (CLI) tool focused on:
* Creating and managing secure vaults
* Secure encryption with AES-256-GCM
* Safe copy operations and directory isolation
* Permission control
Designed with focus on **security, simplicity, and extensibility**.
## ⚙️ Installation
### Download Executable (Linux x86_64)
For the fastest installation, you can download the pre-compiled binary:
```bash
wget https://github.com/HPPeterSteve/Solo-Secure/releases/download/v0.5.0/Solo_sec_v0.5.0_linux_amd64 -O komodo_sec
chmod +x komodo_sec
sudo mv komodo_sec /usr/local/bin/
# 🔐 Komodo-Secure v0.5.0
_confiável, compacto e seguro_
> CLI de segurança em Rust para proteção, isolamento e gerenciamento seguro de arquivos, com foco em robustez e usabilidade.
## 🚀 Visão Geral
O **Komodo-Secure** é uma ferramenta de linha de comando (CLI) focada em:
* Criação e gerenciamento de cofres de arquivos
* Criptografia segura com AES-256-GCM
* Operações seguras de cópia e isolamento
* Controle de permissões
Projetado com foco em **segurança, simplicidade e extensibilidade**.
## ⚙️ Instalação
### Download do Executável (Linux x86_64)
Para a instalação mais rápida, você pode baixar o binário pré-compilado:
```bash
wget https://github.com/HPPeterSteve/Solo-Secure/releases/download/v0.5.0/Solo_sec_v0.5.0_linux_amd64 -O komodo_sec
chmod +x komodo_sec
sudo mv komodo_sec /usr/local/bin/
```
Após a instalação, o comando `komodo_sec` estará disponível globalmente no seu terminal.
### Pré-requisitos (para compilação do código-fonte)
* Rust (via rustup)
* Linux recomendado (Ubuntu 22.04+)
* `libseccomp-dev` (para o sandbox em C)
### Clone e build (do código-fonte)
```bash
git clone https://github.com/HPPeterSteve/Solo-Secure.git
cd Komodo-Secure
cargo build --release
```
Binário gerado em:
```bash
target/release/Komodo_sec
```
## 📦 Comandos
| Comando | Descrição |
| :--------------------------- | :------------------------------ |
| `create-vault <path>` | Cria um novo cofre |
| `add-file <vault> <file>` | Adiciona arquivo ao cofre |
| `safe-copy <src> <dst>` | Cópia segura (atomicidade) |
| `allow-write <file>` | Libera escrita |
| `read-directory <dir>` | Lista arquivos |
| `isolate-directory <dir>` | Isola diretório |
| `secure-copy <file> <vault>` | Criptografa e move para o cofre |
| `encrypt <file> [senha]` | Criptografa arquivo |
| `decrypt <file> [senha]` | Descriptografa arquivo |
| `status <vault>` | Exibe estatísticas do cofre |
| `remove-file <vault> <file>` | Remove arquivo do cofre |
| `help` | Ajuda |
| `exit` | Sair |
## 🔐 Criptografia
* Algoritmo: **AES-256-GCM**
* Derivação de chave: **PBKDF2 (SHA-256)**
* Salt aleatório por operação
* Nonce único por criptografia
### 🔄 Fluxo
```
plaintext → derivação de chave → AES-256-GCM → arquivo .enc
```
## 🔑 Entrada de Senha (Modo Inteligente)
O sistema utiliza fallback em três níveis:
1. **Argumento CLI**
    ```bash
    encrypt arquivo.txt senha123
    ```
2. **stdin (automação)**
    ```bash
    echo "senha123" | Solo_sec encrypt arquivo.txt
    ```
3. **Prompt seguro interativo**
### ⚠️ Aviso de Segurança
* Senhas via argumento podem aparecer no histórico do terminal
* Recomendado para produção:
    ```bash
    echo "senha" | Solo_sec encrypt arquivo.txt
    ```
## 🧪 Testes
### Teste de integridade
```bash
Solo_sec encrypt arquivo.txt senha
Solo_sec decrypt arquivo.enc senha
diff arquivo.txt arquivo.dec
```
Resultado esperado:
```
Integridade confirmada
```
## 🛡️ Segurança e Melhorias (v0.5.0)
Esta versão traz um salto em **usabilidade** e **rastreabilidade**:
* **Sub-sistema de Assistência de Caminhos (Path Assistant)**:
    * **Fuzzy Matching**: Se você digitar um caminho errado, o sistema sugere o arquivo mais próximo usando a distância de Levenshtein.
    * **Interatividade**: Prompts inteligentes que guiam o usuário caso faltem argumentos ou caminhos.
* **Sistema de Logs Estruturado**: Todas as operações (sucessos, avisos e erros) são registradas no arquivo `solo_secure.log` com timestamps precisos.
* **Filtros Seccomp no Sandbox**: Isolamento de diretórios reforçado no componente em C para bloquear chamadas de sistema críticas.
* **UX Refinada**: Interface CLI mais amigável com integração total da biblioteca `inquire`.
---
## 🛡️ Segurança e Melhorias (v0.4.0)
* **Filtros Seccomp no Sandbox**: Introdução do isolamento via seccomp.
* **Tratamento de Erros Aprimorado**: Feedback mais claro ao usuário.
* **Novos Comandos**: Adição de `status` e `remove-file`.
## 🧠 Arquitetura
Separação de responsabilidades:
```
CLI (main)
  ↓
Crypto (criptografia)
  ↓
Vault (armazenamento)
```
### Princípios
* Cada módulo faz **uma única função**
* Criptografia desacoplada do sistema de arquivos
* CLI apenas orquestra operações
## 🧪 Futuro / Roadmap
* [ ] Migração para Argon2
* [ ] Suporte a plugins
* [ ] Fuzz testing (cargo fuzz)
* [ ] Cobertura de testes (tarpaulin)
* [ ] Logs estruturados
* [ ] Suporte a variáveis de ambiente para senha
## 🤝 Contribuição
Contribuições são bem-vindas!
### Como contribuir
1. Fork do projeto
2. Crie uma branch (`feature/minha-feature`)
3. Commit suas mudanças
4. Abra um Pull Request
## 📄 Licença
MIT License
## 💡 Filosofia
> Segurança não é só criptografia.
> É controle, previsibilidade e confiança no sistema.
## 👨‍💻 Autor
Desenvolvido por Peter
## ⭐ Se esse projeto te ajudou
Considere dar uma estrela no repositório!
 
 🔐 Komodo-Secure v0.5.0Reliable, compact, and secure. > A high-performance Rust CLI for file protection, sandbox isolation, and cryptographic vault management.🚀 OverviewKomodo-Secure is a specialized security tool designed for developers and power users who need a lightweight yet robust way to handle sensitive data. It bridges the gap between simple encryption scripts and complex enterprise vault systems.Secure Vaulting: Create encrypted containers for sensitive assets.Military-Grade Crypto: AES-256-GCM authenticated encryption.Active Isolation: Linux seccomp filters for directory-level sandboxing.Smart UX: Path Assistant with Levenshtein-based fuzzy matching.⚙️ InstallationQuick Install (Linux x86_64)Download the pre-compiled binary directly to your local bin:Bashwget https://github.com/HPPeterSteve/Solo-Secure/releases/download/v0.5.0/Solo_sec_v0.5.0_linux_amd64 -O komodo_sec
chmod +x komodo_sec
sudo mv komodo_sec /usr/local/bin/
Build from SourcePrerequisites: Rust (rustup), libseccomp-dev (for C-based sandbox components).Bashgit clone https://github.com/HPPeterSteve/Solo-Secure.git
cd Solo-Secure
cargo build --release
Binary path: target/release/Solo_sec📦 Commands at a GlanceCommandDescriptioncreate-vault <path>Initializes a new secure vault.encrypt <file> [key]Encrypts a file using AES-256-GCM.decrypt <file> [key]Decrypts an .enc file.isolate-directory <dir>Runs the directory in a restricted sandbox.safe-copy <src> <dst>Atomic file copy operation.status <vault>Displays vault health and statistics.secure-copy <f> <v>Encrypts and moves a file into a vault.🔐 Cryptographic SpecificationKomodo-Secure prioritizes data integrity over everything:Algorithm: AES-256-GCM (Authenticated Encryption).Key Derivation: PBKDF2 with SHA-256.Entropy: Random Salt per operation + Unique Nonce per file.Flow: Plaintext → KDF → AES-256-GCM → .enc Payload🔑 Smart Password InputThe CLI supports three fallback levels for automation and security:CLI Argument: encrypt file.txt mypassword (Convenient, but shows in history).Standard Input (stdin): echo "pass" | komodo_sec encrypt file.txt (Ideal for scripts).Interactive Prompt: Secure, hidden input (Best for manual use).🛡️ Key Features in v0.5.0Path Assistant (Fuzzy Matching)Never worry about typos again. If you enter a wrong path, the system calculates the Levenshtein distance and suggests the most likely file.Structured LoggingEvery operation is audited in solo_secure.log with precise timestamps, ensuring you can track changes and errors in your security workflow.Seccomp SandboxingThe C-component uses Linux Kernel Seccomp (Secure Computing Mode) to restrict system calls, providing a layer of isolation for directory operations.🧠 ArchitectureBuilt on the principle of Modular Responsibility:CLI Layer: Orchestrates user interaction using the inquire library.Crypto Engine: Handles all sensitive memory operations and encryption.Vault Manager: Manages file I/O, atomicity, and storage structures.🧪 Roadmap[ ] Argon2 Migration: Upgrading KDF for better GPU-resistance.[ ] Plugin System: Allowing custom scripts to hook into vault events.[ ] Environment Variables: Native support for $KOMODO_KEY.[ ] Cargo Fuzz: Intensive fuzz testing for the crypto module.📄 LicenseDistributed under the MIT License. See LICENSE for more information.👨‍💻 AuthorPeter - Systems DeveloperPhilosophy: Security is not just encryption. It is control, predictability, and trust in the system.
 
