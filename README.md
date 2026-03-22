# 🔐 Komodo-Secure v0.5.2

> CLI de segurança em Rust para proteção, isolamento e gerenciamento seguro de arquivos, com foco em robustez e usabilidade.

## ⚠️ **Aviso Importante: Execução como Root**

O Komodo-Secure **requer privilégios de root (sudo)** para operar corretamente. Isso se deve à sua capacidade de gerenciar o isolamento de diretórios e aplicar filtros de segurança avançados (seccomp) que protegem o sistema de arquivos. Tentar executar o programa sem `sudo` resultará em um erro e o encerramento da aplicação.

```bash
sudo Komodo_sec
```

---

## 🚀 Visão Geral

O **Komodo-Secure** é uma ferramenta de linha de comando (CLI) focada em:

*   Criação e gerenciamento de cofres de arquivos
*   Criptografia segura com AES-256-GCM
*   Operações seguras de cópia e isolamento
*   Controle de permissões

Projetado com foco em **segurança, simplicidade e extensibilidade**.

## ⚙️ Instalação

### Download do Executável (Linux x86_64)

Para a instalação mais rápida, você pode baixar o binário pré-compilado:

```bash
wget https://github.com/HPPeterSteve/Komodo-Secure/releases/download/v0.5.2/Komodo_sec_v0.5.2_linux_amd64 -O Komodo_sec
chmod +x Komodo_sec
sudo mv Komodo_sec /usr/local/bin/
```

Após a instalação, o comando `Komodo_sec` estará disponível globalmente no seu terminal.

### Pré-requisitos (para compilação do código-fonte)

*   Rust (via rustup)
*   Linux recomendado (Ubuntu 22.04+)
*   `libseccomp-dev` (para o sandbox em C)

### Clone e build (do código-fonte)

```bash
git clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure
cargo build --release
```

Binário gerado em:

```bash
target/release/Komodo_sec
```

## 📦 Comandos

| Comando                      | Descrição                       |
| :--------------------------- | :------------------------------ |
| `create-vault <path>`        | Cria um novo cofre              |
| `add-file <vault> <file>`    | Adiciona arquivo ao cofre       |
| `safe-copy <src> <dst>`      | Cópia segura (atomicidade)      |
| `allow-write <file>`         | Libera escrita                  |
| `read-directory <dir>`       | Lista arquivos                  |
| `isolate-directory <dir>`    | Isola diretório                 |
| `secure-copy <file> <vault>` | Criptografa e move para o cofre |
| `encrypt <file> [senha]`     | Criptografa arquivo             |
| `decrypt <file> [senha]`     | Descriptografa arquivo          |
| `status <vault>`             | Exibe estatísticas do cofre     |
| `remove-file <vault> <file>` | Remove arquivo do cofre         |
| `help`                       | Ajuda                           |
| `exit`                       | Sair                            |

## 🔐 Criptografia

*   Algoritmo: **AES-256-GCM**
*   Derivação de chave: **PBKDF2 (SHA-256)**
*   Salt aleatório por operação
*   Nonce único por criptografia

### 🔄 Fluxo

```
plaintext → derivação de chave → AES-256-GCM → arquivo .enc
```

## 🔑 Entrada de Senha (Modo Inteligente)

O sistema utiliza fallback em três níveis:

1.  **Argumento CLI**

    ```bash
    encrypt arquivo.txt senha123
    ```

2.  **stdin (automação)**

    ```bash
    echo "senha123" | Komodo_sec encrypt arquivo.txt
    ```

3.  **Prompt seguro interativo**

### ⚠️ Aviso de Segurança

*   Senhas via argumento podem aparecer no histórico do terminal
*   Recomendado para produção:

    ```bash
    echo "senha" | Komodo_sec encrypt arquivo.txt
    ```

## 🛡️ Segurança e Melhorias (v0.5.2)

Esta versão traz um salto em **usabilidade**, **rastreabilidade** e **segurança**:

*   **Rebranding para Komodo-Secure**: O projeto foi renomeado de Solo-Secure para Komodo-Secure.
*   **Obrigatoriedade de Root**: O programa agora exige privilégios de root para execução, garantindo que as operações de segurança e isolamento funcionem corretamente.
*   **Sub-sistema de Assistência de Caminhos (Path Assistant)**: 
    *   **Fuzzy Matching**: Se você digitar um caminho errado, o sistema sugere o arquivo mais próximo usando a distância de Levenshtein.
    *   **Interatividade**: Prompts inteligentes que guiam o usuário caso faltem argumentos ou caminhos.
*   **Sistema de Logs Estruturado**: Todas as operações (sucessos, avisos e erros) são registradas no arquivo `komodo_secure.log` com timestamps precisos.
*   **Filtros Seccomp no Sandbox**: Isolamento de diretórios reforçado no componente em C para bloquear chamadas de sistema críticas.
*   **UX Refinada**: Interface CLI mais amigável com integração total da biblioteca `inquire`.

---

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

*   Cada módulo faz **uma única função**
*   Criptografia desacoplada do sistema de arquivos
*   CLI apenas orquestra operações

## 🧪 Futuro / Roadmap

*   [ ] Migração para Argon2
*   [ ] Suporte a plugins
*   [ ] Fuzz testing (cargo fuzz)
*   [ ] Cobertura de testes (tarpaulin)
*   [ ] Suporte a variáveis de ambiente para senha

## 🤝 Contribuição

Contribuições são bem-vindas!

### Como contribuir

1.  Fork do projeto
2.  Crie uma branch (`feature/minha-feature`)
3.  Commit suas mudanças
4.  Abra um Pull Request

## 📄 Licença

MIT License

## 💡 Filosofia

> Segurança não é só criptografia.
> É controle, previsibilidade e confiança no sistema.

## 👨‍💻 Autor

Desenvolvido por Peter

## ⭐ Se esse projeto te ajudou

Considere dar uma estrela no repositório!

---

# 🇬🇧 Komodo-Secure v0.5.2 (English Version)

> Rust security CLI for secure file protection, isolation, and management, focusing on robustness and usability.

## ⚠️ **Important Notice: Root Execution Required**

Komodo-Secure **requires root privileges (sudo)** to operate correctly. This is due to its ability to manage directory isolation and apply advanced security filters (seccomp) that protect the file system. Attempting to run the program without `sudo` will result in an error and application termination.

```bash
sudo Komodo_sec
```

---

## 🚀 Overview

**Komodo-Secure** is a command-line interface (CLI) tool focused on:

*   Creating and managing file vaults
*   Secure encryption with AES-256-GCM
*   Secure copy and isolation operations
*   Permission control

Designed with a focus on **security, simplicity, and extensibility**.

## ⚙️ Installation

### Executable Download (Linux x86_64)

For the fastest installation, you can download the pre-compiled binary:

```bash
wget https://github.com/HPPeterSteve/Komodo-Secure/releases/download/v0.5.2/Komodo_sec_v0.5.2_linux_amd64 -O Komodo_sec
chmod +x Komodo_sec
sudo mv Komodo_sec /usr/local/bin/
```

After installation, the `Komodo_sec` command will be globally available in your terminal.

### Prerequisites (for source code compilation)

*   Rust (via rustup)
*   Recommended OS: Linux (Ubuntu 22.04+)
*   `libseccomp-dev` (for the C sandbox component)

### Clone and Build (from source)

```bash
git clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure
cargo build --release
```

Binary generated at:

```bash
target/release/Komodo_sec
```

## 📦 Commands

| Command                      | Description                       |
| :--------------------------- | :-------------------------------- |
| `create-vault <path>`        | Creates a new vault               |
| `add-file <vault> <file>`    | Adds a file to the vault          |
| `safe-copy <src> <dst>`      | Secure copy (atomicity)           |
| `allow-write <file>`         | Enables write permissions         |
| `read-directory <dir>`       | Lists files in a directory        |
| `isolate-directory <dir>`    | Isolates a directory              |
| `secure-copy <file> <vault>` | Encrypts and moves to vault       |
| `encrypt <file> [password]`  | Encrypts a file                   |
| `decrypt <file> [password]`  | Decrypts a file                   |
| `status <vault>`             | Displays vault statistics         |
| `remove-file <vault> <file>` | Removes a file from the vault     |
| `help`                       | Displays help                     |
| `exit`                       | Exits the application             |

## 🔐 Encryption

*   Algorithm: **AES-256-GCM**
*   Key derivation: **PBKDF2 (SHA-256)**
*   Random salt per operation
*   Unique nonce per encryption

### 🔄 Flow

```
plaintext → key derivation → AES-256-GCM → .enc file
```

## 🔑 Password Input (Smart Mode)

The system uses a three-level fallback:

1.  **CLI Argument**

    ```bash
    encrypt file.txt password123
    ```

2.  **stdin (automation)**

    ```bash
    echo "password123" | Komodo_sec encrypt file.txt
    ```

3.  **Secure interactive prompt**

### ⚠️ Security Warning

*   Passwords via argument may appear in terminal history
*   Recommended for production:

    ```bash
    echo "password" | Komodo_sec encrypt file.txt
    ```

## 🛡️ Security and Improvements (v0.5.2)

This version brings a leap in **usability**, **traceability**, and **security**:

*   **Rebranding to Komodo-Secure**: The project has been renamed from Solo-Secure to Komodo-Secure.
*   **Root Requirement**: The program now requires root privileges for execution, ensuring that security and isolation operations function correctly.
*   **Path Assistant Subsystem**: 
    *   **Fuzzy Matching**: If you type a wrong path, the system suggests the closest file using Levenshtein distance.
    *   **Interactivity**: Smart prompts guide the user if arguments are missing or paths are incorrect.
*   **Structured Logging System**: All operations (successes, warnings, and errors) are logged to `komodo_secure.log` with precise timestamps.
*   **Seccomp Filters in Sandbox**: Reinforced directory isolation in the C component to block critical system calls.
*   **Refined UX**: More user-friendly CLI with full integration of the `inquire` library.

---

## 🧠 Architecture

Separation of responsibilities:

```
CLI (main)
  ↓
Crypto (encryption)
  ↓
Vault (storage)
```

### Principles

*   Each module performs **a single function**
*   Encryption decoupled from the file system
*   CLI only orchestrates operations

## 🧪 Future / Roadmap

*   [ ] Migration to Argon2
*   [ ] Plugin support
*   [ ] Fuzz testing (cargo fuzz)
*   [ ] Test coverage (tarpaulin)
*   [ ] Environment variable support for passwords

## 🤝 Contribution

Contributions are welcome!

### How to contribute

1.  Fork the project
2.  Create a branch (`feature/my-feature`)
3.  Commit your changes
4.  Open a Pull Request

## 📄 License

MIT License

## 💡 Philosophy

> Security is not just encryption.
> It's control, predictability, and trust in the system.

## 👨‍💻 Author

Developed by Peter

## ⭐ If this project helped you

Consider starring the repository!
