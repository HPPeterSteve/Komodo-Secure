# 🔐 Komodo-Secure v0.5.0
_reliable, compact, and secure_

> Rust-based security CLI for file protection, isolation, and secure management — focused on robustness and usability.

[![English](https://img.shields.io/badge/English-README.md-blue)](README.md)
[![Português](https://img.shields.io/badge/Português-README.pt.md-green)](README.pt.md)
[![Español](https://img.shields.io/badge/Español-README.es.md-yellow)](README.es.md)

## 🚀 Overview

**Komodo-Secure** is a command-line tool designed for:
- Creating and managing secure file vaults
- Strong AES-256-GCM encryption
- Safe atomic file copy operations
- Directory isolation with hardening
- Permission management

Built with security, simplicity, and extensibility in mind.

## ⚙️ Installation

### Quick Install (Pre-built Binary – Linux x86_64)

```bash
wget https://github.com/HPPeterSteve/Solo-Secure/releases/download/v0.5.0/Solo_sec_v0.5.0_linux_amd64 -O komodo_sec
chmod +x komodo_sec
sudo mv komodo_sec /usr/local/bin/komodo_sec
Now run komodo_sec from anywhere.
Build from Source
Prerequisites:

Rust (install via rustup.rs)
Linux recommended (Ubuntu 22.04+)
libseccomp-dev (for enhanced C sandbox)

Bashgit clone https://github.com/HPPeterSteve/Solo-Secure.git
cd Solo-Secure
cargo build --release
Binary: target/release/komodo_sec
📦 Commands





























































CommandDescriptioncreate-vault <path>Create a new vaultadd-file <vault> <file>Add file to vaultsafe-copy <src> <dst>Secure atomic copyallow-write <file>Grant write permissionread-directory <dir>List files in directoryisolate-directory <dir>Isolate directory (readonly + namespace)secure-copy <file> <vault> [pass]Encrypt & store in vaultencrypt <file> [pass]Encrypt filedecrypt <file> [pass]Decrypt filestatus <vault>Show vault statisticsremove-file <vault> <file>Remove file from vaulthelpShow helpexitExit interactive mode
🔐 Cryptography

Algorithm: AES-256-GCM
Key Derivation: PBKDF2 (SHA-256)
Random salt per operation
Unique nonce per encryption

🔑 Password Input
Smart fallback:

Command-line argument
Stdin (scripts)
Interactive secure prompt

Warning: Avoid arguments for production passwords.
🛡️ v0.5.0 Highlights

Path Assistant (fuzzy matching + suggestions)
Structured logging (solo_secure.log)
Seccomp filters in C sandbox
Improved UX with inquire

📄 License
MIT
👨‍💻 Author
Peter
⭐ Give it a star if you like it!
text### 2. README.pt.md (Português)

```markdown
# 🔐 Komodo-Secure v0.5.0
_confiável, compacto e seguro_

> CLI de segurança em Rust para proteção, isolamento e gerenciamento seguro de arquivos — foco em robustez e usabilidade.

[![English](https://img.shields.io/badge/English-README.md-blue)](README.md)
[![Português](https://img.shields.io/badge/Português-README.pt.md-green)](README.pt.md)
[![Español](https://img.shields.io/badge/Español-README.es.md-yellow)](README.es.md)

## 🚀 Visão Geral

O **Komodo-Secure** é uma ferramenta de linha de comando para:
- Criação e gerenciamento de cofres seguros
- Criptografia forte AES-256-GCM
- Cópias atômicas seguras
- Isolamento de diretórios reforçado
- Controle de permissões

Projetado com ênfase em segurança, simplicidade e extensibilidade.

## ⚙️ Instalação

### Instalação Rápida (Binário Pré-compilado – Linux x86_64)

```bash
wget https://github.com/HPPeterSteve/Solo-Secure/releases/download/v0.5.0/Solo_sec_v0.5.0_linux_amd64 -O komodo_sec
chmod +x komodo_sec
sudo mv komodo_sec /usr/local/bin/komodo_sec
Execute komodo_sec de qualquer lugar.
Compilação do Fonte
Pré-requisitos:

Rust (instale via rustup.rs)
Linux recomendado (Ubuntu 22.04+)
libseccomp-dev (para sandbox em C reforçado)

Bashgit clone https://github.com/HPPeterSteve/Solo-Secure.git
cd Solo-Secure
cargo build --release
Binário: target/release/komodo_sec
📦 Comandos





























































ComandoDescriçãocreate-vault <caminho>Cria um novo cofreadd-file <cofre> <arquivo>Adiciona arquivo ao cofresafe-copy <origem> <destino>Cópia segura e atômicaallow-write <arquivo>Libera permissão de escritaread-directory <dir>Lista arquivos no diretórioisolate-directory <dir>Isola diretório (somente leitura + namespace)secure-copy <arquivo> <cofre> [senha]Criptografa e armazena no cofreencrypt <arquivo> [senha]Criptografa arquivodecrypt <arquivo> [senha]Descriptografa arquivostatus <cofre>Mostra estatísticas do cofreremove-file <cofre> <arquivo>Remove arquivo do cofrehelpMostra ajudaexitSai do modo interativo
🔐 Criptografia

Algoritmo: AES-256-GCM
Derivação de chave: PBKDF2 (SHA-256)
Salt aleatório por operação
Nonce único por criptografia

🔑 Entrada de Senha
Modo inteligente:

Argumento na linha de comando
stdin (para scripts)
Prompt interativo seguro

Aviso: Evite senhas como argumento em produção.
🛡️ Novidades v0.5.0

Assistente de caminhos (fuzzy + sugestões)
Logs estruturados (solo_secure.log)
Filtros Seccomp no sandbox em C
Interface mais amigável com inquire

📄 Licença
MIT
👨‍💻 Autor
Peter
⭐ Dá uma estrela se curtiu!
text### 3. README.es.md (Espanhol)

```markdown
# 🔐 Komodo-Secure v0.5.0
_confiable, compacto y seguro_

> CLI de seguridad basado en Rust para protección, aislamiento y gestión segura de archivos — enfocado en robustez y usabilidad.

[![English](https://img.shields.io/badge/English-README.md-blue)](README.md)
[![Português](https://img.shields.io/badge/Português-README.pt.md-green)](README.pt.md)
[![Español](https://img.shields.io/badge/Español-README.es.md-yellow)](README.es.md)

## 🚀 Visión General

**Komodo-Secure** es una herramienta de línea de comandos para:
- Crear y gestionar bóvedas seguras
- Cifrado fuerte AES-256-GCM
- Copias atómicas seguras
- Aislamiento de directorios reforzado
- Gestión de permisos

Diseñada con énfasis en seguridad, simplicidad y extensibilidad.

## ⚙️ Instalación

### Instalación Rápida (Binario Precompilado – Linux x86_64)

```bash
wget https://github.com/HPPeterSteve/Solo-Secure/releases/download/v0.5.0/Solo_sec_v0.5.0_linux_amd64 -O komodo_sec
chmod +x komodo_sec
sudo mv komodo_sec /usr/local/bin/komodo_sec
Ejecuta komodo_sec desde cualquier lugar.
Compilación desde Fuente
Requisitos:

Rust (instala vía rustup.rs)
Linux recomendado (Ubuntu 22.04+)
libseccomp-dev (para sandbox en C reforzado)

Bashgit clone https://github.com/HPPeterSteve/Solo-Secure.git
cd Solo-Secure
cargo build --release
Binario: target/release/komodo_sec
📦 Comandos





























































ComandoDescripcióncreate-vault <ruta>Crea una nueva bóvedaadd-file <bóveda> <archivo>Añade archivo a la bóvedasafe-copy <origen> <destino>Copia segura y atómicaallow-write <archivo>Permite escrituraread-directory <dir>Lista archivos en el directorioisolate-directory <dir>Aísla directorio (solo lectura + namespace)secure-copy <archivo> <bóveda> [pass]Cifra y almacena en la bóvedaencrypt <archivo> [pass]Cifra archivodecrypt <archivo> [pass]Descifra archivostatus <bóveda>Muestra estadísticas de la bóvedaremove-file <bóveda> <archivo>Elimina archivo de la bóvedahelpMuestra ayudaexitSale del modo interactivo
🔐 Criptografía

Algoritmo: AES-256-GCM
Derivación de clave: PBKDF2 (SHA-256)
Salt aleatorio por operación
Nonce único por cifrado

🔑 Entrada de Contraseña
Modo inteligente:

Argumento en línea de comandos
stdin (para scripts)
Prompt interactivo seguro

Advertencia: Evita contraseñas como argumento en producción.
🛡️ Novedades v0.5.0

Asistente de rutas (coincidencia fuzzy + sugerencias)
Logs estructurados (solo_secure.log)
Filtros Seccomp en sandbox C
Interfaz mejorada con inquire

📄 Licencia
MIT
👨‍💻 Autor
Peter
⭐ ¡Dale una estrella si te gustó!
text
