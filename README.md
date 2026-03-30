# Komodo-Secure 🛡️ v0.6.0 (Professional Edition)

Baixe a versão mais recente:

[Download Komodo-Secure v0.6.0]# Komodo-Secure 🛡️ v0.6.0 (Professional Edition)

Baixe a versão mais recente:

[Download Komodo-Secure v0.6.0](https://raw.githubusercontent.com/HPPeterSteve/Komodo-Secure/main/komodo-secure-0.6.0-New-Solo_Sec.exe)
O **Komodo-Secure** é uma ferramenta de segurança de alto nível para Windows, projetada para fornecer isolamento rigoroso de processos e proteção avançada de arquivos com overhead mínimo.

## ✨ O que há de novo na v0.6.0

Esta versão marca a transição para um **isolamento de nível profissional**, trazendo tecnologias usadas em navegadores modernos como Chrome e Edge para o seu terminal.

### 🔐 Sandbox Windows (Core/sandbox.c)
*   **AppContainer Isolation**: Execução em um container seguro com SID próprio, bloqueando acesso a recursos do sistema por padrão.
*   **Restricted Token**: Remoção completa de privilégios e grupos de administradores do processo sandboxed.
*   **Untrusted Integrity Level**: O nível mais baixo de integridade possível, impedindo qualquer interação com objetos de maior privilégio.
*   **Mitigation Policies**: Ativação de **DEP**, **ASLR forçado** e bloqueio de chamadas de sistema **Win32k** (Hardening de Kernel).
*   **Desktop Isolado**: Lançamento em um desktop virtual separado para evitar keylogging e capturas de tela.

### 🤖 Sub-sistema de Assistência (Path Assistant)
*   **Fuzzy Matching**: Correção automática de erros de digitação em caminhos de arquivos usando a distância de Levenshtein.
*   **Interface Interativa**: Sugestões inteligentes via CLI para garantir que você nunca perca o acesso aos seus cofres.

## 🛠️ Funcionalidades Principais

| Comando | Descrição |
| :--- | :--- |
| `create-vault` | Inicializa um diretório seguro para proteção de dados. |
| `add-file` | Move arquivos para dentro do cofre protegido. |
| `isolate-directory` | Aplica o **Isolamento Profissional** ao diretório escolhido. |
| `encrypt` / `decrypt` | Proteção AES-256-GCM com senha segura. |
| `secure-copy` | Copia e criptografa um arquivo para um cofre em uma única operação. |
| `status` | Relatório detalhado de ocupação e integridade do cofre. |

## 🚀 Como Executar

### Pré-requisitos
*   **Windows**: Windows 10/11 (para suporte total a AppContainer).
*   **Linux**: Kernel moderno com suporte a Namespaces e Seccomp.

### Compilação
```bash
# Para Windows (Recomendado)
cargo build --release --target x86_64-pc-windows-gnu

# Para Linux
cargo build --release
```

## 🔐 Segurança e Criptografia
*   **Algoritmo**: AES-256-GCM (Autenticada)
*   **Derivação**: PBKDF2 (SHA-256)
*   **Isolamento**: AppContainer (Win) / Namespaces + Seccomp (Linux)

---
*Desenvolvido com foco em privacidade.*
**Autor: Peter (HPPeterSteve)**
