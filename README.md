# 🔐 Solo-Secure v0.4.0

> CLI de segurança em Rust para proteção, isolamento e gerenciamento seguro de arquivos, com foco em robustez e usabilidade.

## 🚀 Visão Geral

O **Solo-Secure** é uma ferramenta de linha de comando (CLI) focada em:

* Criação e gerenciamento de cofres de arquivos
* Criptografia segura com AES-256-GCM
* Operações seguras de cópia e isolamento
* Controle de permissões

Projetado com foco em **segurança, simplicidade e extensibilidade**.

## ⚙️ Instalação

### Download do Executável (Linux x86_64)

Para a instalação mais rápida, você pode baixar o binário pré-compilado:

```bash
wget https://github.com/HPPeterSteve/Solo-Secure/releases/download/v0.4.0/Solo_sec_v0.4.0_linux_amd64 -O Solo_sec
chmod +x Solo_sec
sudo mv Solo_sec /usr/local/bin/
```

Após a instalação, o comando `Solo_sec` estará disponível globalmente no seu terminal.

### Pré-requisitos (para compilação do código-fonte)

*   Rust (via rustup)
*   Linux recomendado (Ubuntu 22.04+)
*   `libseccomp-dev` (para o sandbox em C)

### Clone e build (do código-fonte)

```bash
git clone https://github.com/HPPeterSteve/Solo-Secure.git
cd Solo-Secure
cargo build --release
```

Binário gerado em:

```bash
target/release/Solo_sec
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

1.  **Argumento CLI**

    ```bash
    encrypt arquivo.txt senha123
    ```

2.  **stdin (automação)**

    ```bash
    echo "senha123" | Solo_sec encrypt arquivo.txt
    ```

3.  **Prompt seguro interativo**

### ⚠️ Aviso de Segurança

*   Senhas via argumento podem aparecer no histórico do terminal
*   Recomendado para produção:

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

## 🛡️ Segurança e Melhorias (v0.4.0)

Esta versão introduz melhorias significativas em segurança e funcionalidade:

*   **Filtros Seccomp no Sandbox**: O componente em C (`sandbox.c`) agora utiliza filtros `seccomp` para restringir chamadas de sistema perigosas (ex: `reboot`, `mount`, `ptrace`), aumentando drasticamente a segurança do isolamento de diretórios.
*   **Tratamento de Erros Aprimorado**: Melhor propagação de erros e feedback mais claro ao usuário em todas as operações, especialmente em criptografia e gerenciamento de cofres.
*   **Novos Comandos**: Adição dos comandos `status` e `remove-file` para um gerenciamento mais completo dos cofres.

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
*   [ ] Logs estruturados
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
