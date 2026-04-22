# Komodo-Secure

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

## 📖 Introdução

**Komodo-Secure** é um framework de segurança híbrido que combina:
- **Rust**: segurança de memória e alto nível.
- **C**: acesso direto ao sistema e baixo nível.

O projeto entrega **cofres criptografados de alto desempenho**, isolamento de processos e sandboxing avançado para ambientes Windows e Linux.  
Licenciado sob **AGPL-3.0**, garantindo uso livre, mas exigindo abertura de modificações.

---

## 🏗️ Arquitetura

```plaintext
┌──────────────────────────────────────────────────────────────┐
│              CAMADA DE INTERFACE COM USUÁRIO                 │
│                   Rust CLI / TUI (main.rs)                   │
│  • clap 4.6 — argumentos CLI                                 │
│  • ratatui 0.30 — UI de terminal                             │
│  • inquire 0.9 — prompts interativos                         │
│  • colored 3.1 — saída colorida                              │
└─────────────────────────┬──────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│           CAMADA DE CRIPTOGRAFIA (src/crypto.rs)              │
│  • AES-256-GCM (AEAD)                                         │
│  • Argon2id — derivação de chave                              │
│  • PBKDF2 — 310k iterações (OWASP 2023)                       │
│  • SHA-256 — integridade                                      │
└─────────────────────────┬──────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│        PONTE FFI (src/vault.rs) - RUST ↔ C                    │
│  • 14 funções vault_*_ffi                                     │
│  • Conversões CString                                         │
│  • Wrappers seguros                                           │
└────┬────────────────────────────┬─────────────────────────────┘
     │                            │
┌────▼─────────────────┐  ┌──────▼──────────────────────────┐
│  CAMADA WINDOWS      │  │   CAMADA LINUX                  │
│ (Core/sandbox.c)     │  │ (core_linux/diamondVaults.c)    │
│ • AppContainer       │  │ • inotify monitoring            │
│ • Restricted Token   │  │ • Namespaces Linux              │
│ • DEP/ASLR           │  │ • Seccomp filtering             │
│ • Win32k Blocking    │  │ • OpenSSL AES-256-CBC           │
│ • Isolated Desktop   │  │ • PBKDF2 310k iterations        │
└──────────────────────┘  └──────────────────────────────────┘
