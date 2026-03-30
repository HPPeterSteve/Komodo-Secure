# Komodo-Secure 🛡️ v0.6.0 (Windows Edition)

O **Komodo-Secure** é uma ferramenta de segurança avançada para Windows, agora com uma interface gráfica (GUI) moderna desenvolvida em Rust. Ele oferece proteção de arquivos, isolamento de diretórios e monitoramento de recursos do sistema em tempo real.

---

## ✨ Novidades na Versão Windows

- **Interface Gráfica Nativa**: Interface intuitiva usando `egui`, otimizada para Windows.
- **Isolamento de Diretórios**: Implementação de segurança baseada em permissões do sistema de arquivos do Windows.
- **Monitor de Recursos**: Aba dedicada para visualizar o uso de CPU e Memória RAM do seu sistema Windows.
- **Explorador de Arquivos**: Aba para listar e gerenciar arquivos localmente.
- **Segurança Reforçada**: Criptografia AES-256-GCM com derivação de chave PBKDF2.

## 🚀 Como Executar no Windows

### Pré-requisitos

Para compilar no Windows, você precisará do Rust instalado com o toolchain MSVC:

1. Instale o Rust via [rustup.rs](https://rustup.rs/).
2. Certifique-se de ter as "Ferramentas de Compilação do C++" instaladas (via Visual Studio Installer).

### Compilação

```powershell
# Clone o repositório
git clone https://github.com/HPPeterSteve/Komodo-Secure.git
cd Komodo-Secure

# Compile a versão release
cargo build --release
```

O executável será gerado em `target\release\komodo-secure.exe`.

## 🛠️ Funcionalidades

### 1. Aba Principal (Segurança)
- **Criar Cofre**: Inicializa um diretório seguro para seus arquivos.
- **Adicionar Arquivo**: Move arquivos para dentro do cofre protegido.
- **Criptografar/Descriptografar**: Proteção de arquivos com senha usando AES-256-GCM.
- **Isolar Diretório**: Aplica restrições de segurança no diretório selecionado.

### 2. Monitor de Recursos
- Visualização em tempo real do uso de CPU e Memória RAM.

### 3. Aba de Arquivos
- Navegação e listagem de arquivos locais.

## 🔐 Criptografia e Segurança

*   Algoritmo: **AES-256-GCM**
*   Derivação de chave: **PBKDF2 (SHA-256)**
*   Isolamento: **Windows File System Permissions**

---
*Desenvolvido com foco em privacidade e segurança máxima no Windows.*
*Autor: Peter*
