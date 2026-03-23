# Komodo-Secure 🛡️ v0.6.0 (GUI Edition)

O **Komodo-Secure** é uma ferramenta de segurança avançada para Linux, agora com uma interface gráfica (GUI) moderna desenvolvida em Rust. Ele oferece proteção de arquivos, isolamento de diretórios (sandbox) e monitoramento de recursos do sistema em tempo real.

## ⚠️ **Aviso Importante: Execução como Root**

O Komodo-Secure **requer privilégios de root (sudo)** para operar corretamente. Isso se deve à sua capacidade de gerenciar o isolamento de diretórios e aplicar filtros de segurança avançados (seccomp) que protegem o sistema de arquivos.

```bash
sudo ./target/release/komodo-secure
```

---

## ✨ Novidades na Versão GUI

- **Interface Gráfica Nativa**: Substituímos a CLI por uma interface intuitiva usando `egui`, agora com **todas as funcionalidades da CLI original integradas**.
- **Monitor de Recursos**: Uma aba dedicada para visualizar o uso de CPU e Memória RAM do seu sistema.
- **Explorador de Arquivos**: Uma segunda aba para listar e gerenciar arquivos localmente.
- **Segurança Reforçada**: Integração direta com o sub-sistema de isolamento e criptografia AES-256-GCM.

## 🚀 Como Executar

### Pré-requisitos (Linux)

Para compilar ou executar, você precisará das seguintes bibliotecas do sistema:

```bash
sudo apt-get update
sudo apt-get install -y libwayland-dev libx11-dev libxkbcommon-dev libegl1-mesa-dev libgl1-mesa-dev libasound2-dev libseccomp-dev
```

### Executando o Binário

O executável para Linux está disponível após a compilação em `target/release/komodo-secure`.

## 🛠️ Funcionalidades (Todas acessíveis via GUI)

### 1. Aba Principal (Segurança)
- **Criar Cofre**: Inicializa um diretório seguro para seus arquivos (`create-vault`).
- **Adicionar Arquivo**: Move arquivos para dentro do cofre protegido (`add-file`).
- **Remover Arquivo**: Remove um arquivo do cofre (`remove-file`).
- **Status do Cofre**: Exibe informações sobre o cofre (`status`).
- **Criptografar/Descriptografar**: Proteção de arquivos com senha usando criptografia de nível militar (AES-256-GCM) (`encrypt`, `decrypt`).
- **Secure Copy**: Copia e criptografa um arquivo para um cofre (`secure-copy`).
- **Isolar Diretório**: Aplica restrições de sandbox e permissões somente-leitura (`isolate-directory`).
- **Cópia Segura**: Realiza uma cópia atômica de arquivos (`safe-copy`).
- **Listar Diretório**: Lista arquivos em um diretório (`read-directory`).

### 2. Monitor de Recursos
- Visualização em tempo real do uso de cada núcleo da CPU.
- Monitoramento de consumo de memória RAM.

### 3. Aba de Arquivos
- Navegação e listagem de arquivos em diretórios específicos.
- Interface simplificada para visualização de conteúdo.

## 🔐 Criptografia e Segurança

*   Algoritmo: **AES-256-GCM**
*   Derivação de chave: **PBKDF2 (SHA-256)**
*   Isolamento: **Namespaces Linux + Seccomp Filters**

## 📦 Compilação

Se desejar compilar manualmente:

1. Instale o Rust: `curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. Clone o repositório.
3. Execute: `cargo build --release`

---
*Desenvolvido com foco em privacidade e segurança máxima no Linux.*
*Autor: Peter*
