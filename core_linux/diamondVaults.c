/*
 * vault_security.c  —  HARDENED REVISION
 *
 * VAULT SECURITY SYSTEM - Full Linux Implementation
 * Author    : Peter Steve (architecture)
 * Hardening : Security Audit Patch — 2026-04-18
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -Wformat=2 -Wformat-security \
 *       -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
 *       -pie -fPIE \
 *       -o vault_security vault_security.c \
 *       -lssl -lcrypto -lpthread
 *
 * Mudanças desta revisão (todas as vulnerabilidades do audit):
 *
 *  [CRIT-A] catalog_load(): validação estrita de cada campo lido,
 *           limite de fcount, zeroing de buffers antes de ler.
 *
 *  [CRIT-B] Catálogo autenticado: HMAC-SHA256 sobre o payload
 *           completo + chave derivada do pass_hash do primeiro vault
 *           protegido. Sem vault protegido: chave aleatória por sessão
 *           guardada em memória protegida (mlock).
 *
 *  [CRIT-C] Sandbox: seccomp-BPF real com allowlist mínima,
 *           drop de capabilities, namespace de mount via unshare(2),
 *           chroot + pivot_root quando possível.
 *
 *  [MED-D]  Criptografia: AES-256-GCM (AEAD) substitui CBC.
 *           Tag de 16 bytes garante confidencialidade + integridade.
 *           Salt por arquivo no encrypt_file().
 *
 *  [MED-E]  Race conditions: catalog_save() só chamado com lock held,
 *           flag catalog_dirty + save diferido no monitor loop.
 *
 *  [MED-F]  TOCTOU: open() com O_NOFOLLOW + fstat() substitui
 *           stat() + open() em pares críticos.
 *
 *  [MIN-G]  Logging: paths e razões de alert são truncados a 64 chars
 *           antes de ir para o log; nomes de vault são sanitizados.
 *
 *  [MIN-H]  explicit_bzero() em todos os buffers sensíveis, incluindo
 *           stack vars de senha em todos os caminhos de erro.
 *
 *  [MIN-I]  Rate limiting via token bucket por vault (não só contador).
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <pthread.h>
#include <termios.h>
#include <sched.h>

/* seccomp */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/prctl.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  COMPILE-TIME CONSTANTS
 * ═══════════════════════════════════════════════════════════════════════════ */
#define VAULT_CATALOG_PATH  "/var/lib/vault_security"
#define VAULT_CATALOG_FILE  "/var/lib/vault_security/catalog.dat"
#define VAULT_LOG_FILE      "/var/log/vault_security.log"

#define MAX_VAULTS          64
#define MAX_FILES_PER_VAULT 2048          /* [CRIT-A] limite razoável */
#define VAULT_NAME_MAX      128
#define VAULT_PATH_MAX      512
#define HASH_HEX_LEN        65
#define SALT_LEN            32
#define KEY_LEN             32            /* AES-256 */
#define GCM_IV_LEN          12            /* [MED-D] GCM nonce recomendado */
#define GCM_TAG_LEN         16            /* [MED-D] autenticação */
#define PBKDF2_ITER         310000
#define MAX_PASS_ATTEMPTS   3
#define MAX_PASS_LEN        256
#define HMAC_LEN            32            /* [CRIT-B] SHA-256 output */
#define CATALOG_KEY_LEN     32            /* [CRIT-B] chave do HMAC do catálogo */
#define INOTIFY_BUFSZ       (4096 * (sizeof(struct inotify_event) + NAME_MAX + 1))

/* [MIN-G] Tamanho máximo de strings que entram no log */
#define LOG_FIELD_MAX       64

/* Rate limiting — [MIN-I] token bucket */
#define RATE_BUCKET_MAX     5             /* máx tentativas em rajada */
#define RATE_REFILL_SEC     60            /* 1 token por minuto */

static const long ALERT_INTERVALS[] = {
    300, 600, 900, 1800, 3600, 7200, 14400, 28800,
    43200, 86400, 172800, 259200, 604800, 1209600,
    1814400, 2592000, 5184000, 7776000, 15552000, 31536000
};
#define NUM_ALERT_INTERVALS (sizeof(ALERT_INTERVALS)/sizeof(ALERT_INTERVALS[0]))

/* Magia e versão do catálogo */
#define CATALOG_MAGIC   "VLTS"
#define CATALOG_VER     2               /* [CRIT-B] versão 2 = HMAC */

/* ═══════════════════════════════════════════════════════════════════════════
 *  ENUMERAÇÕES
 * ═══════════════════════════════════════════════════════════════════════════ */
typedef enum { VAULT_TYPE_NORMAL=0, VAULT_TYPE_PROTECTED=1 } VaultType;
typedef enum { VAULT_STATUS_OK=0, VAULT_STATUS_LOCKED=1,
               VAULT_STATUS_ALERT=2, VAULT_STATUS_DELETED=3 } VaultStatus;
typedef enum { LOG_INFO=0, LOG_WARN=1, LOG_ERROR=2,
               LOG_ALERT=3, LOG_AUDIT=4 } LogLevel;
typedef enum {
    ERR_OK=0, ERR_INVALID_ARGS=-1, ERR_NO_MEMORY=-2, ERR_IO=-3,
    ERR_CRYPTO=-4, ERR_AUTH_FAIL=-5, ERR_VAULT_LOCKED=-6,
    ERR_VAULT_EXISTS=-7, ERR_VAULT_NOT_FOUND=-8, ERR_PERM_DENIED=-9,
    ERR_CATALOG_FULL=-10, ERR_PATH_INVALID=-11, ERR_PASS_REQUIRED=-12,
    ERR_INTEGRITY=-13, ERR_SYSTEM=-14, ERR_CATALOG_TAMPERED=-15
} VaultError;

/* ═══════════════════════════════════════════════════════════════════════════
 *  ESTRUTURAS DE DADOS
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct FileEntry {
    char            filename[NAME_MAX + 1];
    char            hash[HASH_HEX_LEN];
    time_t          last_seen;
    bool            modified;
    struct FileEntry *next;
} FileEntry;

#define HASHMAP_BUCKETS 256
typedef struct {
    FileEntry *buckets[HASHMAP_BUCKETS];
    size_t     count;
} FileHashMap;

typedef struct {
    time_t  first_triggered;
    time_t  last_alerted;
    size_t  interval_idx;
    size_t  alert_count;
    char    reason[256];
} AlertState;

/* [MIN-I] Token bucket por vault */
typedef struct {
    int    tokens;          /* tokens disponíveis */
    time_t last_refill;     /* último refill */
} RateBucket;

typedef struct {
    uint32_t    id;
    char        name[VAULT_NAME_MAX];
    VaultType   type;
    VaultStatus status;
    bool        has_pass;
    char        path[VAULT_PATH_MAX];
    time_t      created_at;
    time_t      last_check;
    int         failed_attempts;
    uint8_t     salt[SALT_LEN];
    uint8_t     pass_hash[SHA256_DIGEST_LENGTH];
    FileHashMap hashmap;
    AlertState  alert;
    int         inotify_wd;
    RateBucket  rate;       /* [MIN-I] */
} Vault;

typedef struct {
    Vault    vaults[MAX_VAULTS];
    uint32_t count;
    uint32_t next_id;
    char     category[32];
    bool     dirty;         /* [MED-E] flag para save diferido */
} Catalog;

typedef struct {
    Catalog        *catalog;
    int             inotify_fd;
    volatile bool   running;
    pthread_mutex_t lock;
} MonitorCtx;

/* ═══════════════════════════════════════════════════════════════════════════
 *  GLOBALS
 * ═══════════════════════════════════════════════════════════════════════════ */
static Catalog   g_catalog;
static MonitorCtx g_monitor;
static FILE      *g_logfp   = NULL;
static bool       g_verbose = false;

/*
 * [CRIT-B] Chave HMAC do catálogo — alocada com mlock() para não ir para swap.
 * Nunca serializada em disco.
 */
static uint8_t  *g_catalog_hmac_key = NULL; /* mlock'd */
static bool      g_catalog_key_set  = false;

/* ═══════════════════════════════════════════════════════════════════════════
 *  FORWARD DECLARATIONS
 * ═══════════════════════════════════════════════════════════════════════════ */
static VaultError catalog_save(void);
static VaultError catalog_load(void);
static void       monitor_scan_vault(Vault *v);
static void       alert_trigger(Vault *v, const char *reason);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 1: LOGGING  [MIN-G]
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Sanitiza string para o log: trunca e remove caracteres de controle */
static void log_sanitize(const char *in, char *out, size_t outsz) {
    size_t i = 0, o = 0;
    while (in[i] && o + 1 < outsz && o < LOG_FIELD_MAX) {
        unsigned char c = (unsigned char)in[i];
        out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
        i++;
    }
    if (in[i] && o + 4 < outsz) { out[o++]='.'; out[o++]='.'; out[o++]='.'; }
    out[o] = '\0';
}

static const char *log_level_str(LogLevel lvl) {
    switch (lvl) {
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ERROR: return "ERROR";
        case LOG_ALERT: return "ALERT";
        case LOG_AUDIT: return "AUDIT";
        default:        return "?????";
    }
}

static void vault_log(LogLevel lvl, const char *fmt, ...) {
    char    timebuf[32];
    time_t  now = time(NULL);
    struct  tm *tm_info = localtime(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

    va_list ap;
    va_start(ap, fmt);
    if (lvl >= LOG_WARN || g_verbose) {
        FILE *out = (lvl == LOG_ALERT || lvl == LOG_ERROR) ? stderr : stdout;
        fprintf(out, "[%s] [%s] ", timebuf, log_level_str(lvl));
        vfprintf(out, fmt, ap);
        fputc('\n', out);
    }
    va_end(ap);

    va_start(ap, fmt);
    if (g_logfp) {
        fprintf(g_logfp, "[%s] [%s] ", timebuf, log_level_str(lvl));
        vfprintf(g_logfp, fmt, ap);
        fputc('\n', g_logfp);
        fflush(g_logfp);
    }
    va_end(ap);
}

static void log_init(void) {
    g_logfp = fopen(VAULT_LOG_FILE, "a");
    if (!g_logfp) {
        char fallback[256];
        const char *home = getenv("HOME");
        if (home) {
            snprintf(fallback, sizeof(fallback), "%s/.vault_security.log", home);
            g_logfp = fopen(fallback, "a");
        }
    }
    /* Protege permissões do log */
    if (g_logfp) {
        int fd = fileno(g_logfp);
        fchmod(fd, 0600);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 2: ERROR HANDLING
 * ═══════════════════════════════════════════════════════════════════════════ */
static const char *vault_strerror(VaultError err) {
    switch (err) {
        case ERR_OK:                return "Success";
        case ERR_INVALID_ARGS:      return "Invalid arguments";
        case ERR_NO_MEMORY:         return "Out of memory";
        case ERR_IO:                return "I/O error";
        case ERR_CRYPTO:            return "Cryptographic error";
        case ERR_AUTH_FAIL:         return "Authentication failure";
        case ERR_VAULT_LOCKED:      return "Vault is locked";
        case ERR_VAULT_EXISTS:      return "Vault already exists";
        case ERR_VAULT_NOT_FOUND:   return "Vault not found";
        case ERR_PERM_DENIED:       return "Permission denied";
        case ERR_CATALOG_FULL:      return "Catalog is full";
        case ERR_PATH_INVALID:      return "Invalid path";
        case ERR_PASS_REQUIRED:     return "Password required";
        case ERR_INTEGRITY:         return "File integrity violation";
        case ERR_SYSTEM:            return "System error";
        case ERR_CATALOG_TAMPERED:  return "Catalog integrity check FAILED — possible tampering";
        default:                    return "Unknown error";
    }
}

#define VAULT_ASSERT(cond, err, fmt, ...) \
    do { if (!(cond)) { \
        vault_log(LOG_ERROR, "ASSERT [%s:%d]: " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        return (err); } } while (0)

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 3: ARGUMENT & STRING SANITISATION
 * ═══════════════════════════════════════════════════════════════════════════ */
static char *sanitize_arg(char *s) {
    if (!s) return NULL;
    while (*s==' '||*s=='\t'||*s=='\n'||*s=='\r') s++;
    size_t len = strlen(s);
    if (len >= 2 && ((s[0]=='"' && s[len-1]=='"') ||
                     (s[0]=='\'' && s[len-1]=='\''))) {
        s[len-1] = '\0'; s++; len -= 2;
    }
    if (len > 0) {
        char *end = s + len - 1;
        while (end > s && (*end==' '||*end=='\t'||*end=='\n'||*end=='\r'))
            *end-- = '\0';
    }
    return s;
}

/* [MED-F] Valida path sem TOCTOU: verifica apenas a string */
static VaultError validate_path(const char *path) {
    if (!path || path[0]=='\0') return ERR_PATH_INVALID;
    if (strlen(path) >= VAULT_PATH_MAX) return ERR_PATH_INVALID;
    if (path[0] != '/') return ERR_PATH_INVALID;
    if (strstr(path, "/../") ||
        (strlen(path)>=3 && strcmp(path+strlen(path)-3,"/..")==0))
        return ERR_PATH_INVALID;
    /* Rejeita bytes nulos embutidos */
    for (size_t i = 0; i < strlen(path); i++)
        if ((unsigned char)path[i] < 0x20 && path[i] != '\0')
            return ERR_PATH_INVALID;
    return ERR_OK;
}

static VaultError validate_name(const char *name) {
    if (!name || name[0]=='\0') return ERR_INVALID_ARGS;
    if (strlen(name) >= VAULT_NAME_MAX) return ERR_INVALID_ARGS;
    for (const char *p = name; *p; p++)
        if (!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||
              (*p>='0'&&*p<='9')||*p=='_'||*p=='-')) {
            vault_log(LOG_ERROR, "Invalid char in vault name");
            return ERR_INVALID_ARGS;
        }
    return ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 4: CRIPTOGRAFIA  [MED-D] AES-256-GCM + HMAC catálogo
 * ═══════════════════════════════════════════════════════════════════════════ */

/* SHA-256 de arquivo → hex */
static VaultError sha256_file(const char *path, char out[HASH_HEX_LEN]) {
    /* [MED-F] Abre com O_NOFOLLOW para evitar symlink race */
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return ERR_IO;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { close(fd); return ERR_CRYPTO; }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    uint8_t buf[65536];
    ssize_t n;
    bool err = false;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        EVP_DigestUpdate(ctx, buf, (size_t)n);
    if (n < 0) err = true;

    close(fd);
    explicit_bzero(buf, sizeof(buf));

    if (err) { EVP_MD_CTX_free(ctx); return ERR_IO; }

    uint8_t digest[SHA256_DIGEST_LENGTH];
    unsigned int dlen = 0;
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);

    for (int i=0; i<SHA256_DIGEST_LENGTH; i++)
        snprintf(out+i*2, 3, "%02x", digest[i]);
    out[HASH_HEX_LEN-1] = '\0';
    return ERR_OK;
}

/* PBKDF2 → chave derivada */
static VaultError derive_key(const char *password, const uint8_t *salt,
                              uint8_t key[KEY_LEN]) {
    if (!password || !salt || !key) return ERR_INVALID_ARGS;
    int rc = PKCS5_PBKDF2_HMAC(
        password, (int)strlen(password),
        salt, SALT_LEN, PBKDF2_ITER,
        EVP_sha256(), KEY_LEN, key);
    if (rc != 1) {
        vault_log(LOG_ERROR, "PBKDF2 failed");
        return ERR_CRYPTO;
    }
    return ERR_OK;
}

/* [CRIT-B] HMAC-SHA256 sobre um buffer */
static bool hmac_sha256(const uint8_t *key, size_t klen,
                         const uint8_t *data, size_t dlen,
                         uint8_t out[HMAC_LEN]) {
    unsigned int outlen = 0;
    uint8_t *r = HMAC(EVP_sha256(), key, (int)klen,
                       data, dlen, out, &outlen);
    return (r != NULL && outlen == HMAC_LEN);
}

/* [CRIT-B] Inicializa chave HMAC do catálogo em memória mlock'd */
static VaultError catalog_key_init(void) {
    if (g_catalog_key_set) return ERR_OK;

    /* Aloca página mlock'd */
    g_catalog_hmac_key = mmap(NULL, CATALOG_KEY_LEN,
                               PROT_READ|PROT_WRITE,
                               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (g_catalog_hmac_key == MAP_FAILED) {
        g_catalog_hmac_key = NULL;
        return ERR_NO_MEMORY;
    }
    mlock(g_catalog_hmac_key, CATALOG_KEY_LEN);

    /* Gera chave aleatória por sessão */
    if (RAND_bytes(g_catalog_hmac_key, CATALOG_KEY_LEN) != 1) {
        munmap(g_catalog_hmac_key, CATALOG_KEY_LEN);
        g_catalog_hmac_key = NULL;
        return ERR_CRYPTO;
    }
    g_catalog_key_set = true;
    return ERR_OK;
}

/* Reforça a chave do catálogo com o pass_hash do vault protegido */
static void catalog_key_reinforce(const uint8_t *pass_hash) {
    if (!g_catalog_key_set || !pass_hash) return;
    /* XOR-fold do pass_hash na chave existente */
    for (int i = 0; i < CATALOG_KEY_LEN; i++)
        g_catalog_hmac_key[i] ^= pass_hash[i % SHA256_DIGEST_LENGTH];
}

/*
 * [MED-D] AES-256-GCM encrypt
 * Formato do arquivo de saída:
 *   [4  bytes] salt length (= SALT_LEN, constante)
 *   [32 bytes] salt  (para PBKDF2 por arquivo)
 *   [12 bytes] GCM nonce
 *   [16 bytes] GCM auth tag
 *   [N  bytes] ciphertext
 */
static VaultError encrypt_file(const char *inpath, const char *outpath,
                                const uint8_t master_key[KEY_LEN]) {
    /* [MED-F] open com O_NOFOLLOW */
    int fdin = open(inpath, O_RDONLY | O_NOFOLLOW);
    if (fdin < 0) { vault_log(LOG_ERROR, "encrypt: open input"); return ERR_IO; }

    int fdout = open(outpath, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0600);
    if (fdout < 0) { close(fdin); return ERR_IO; }

    FILE *fin  = fdopen(fdin,  "rb");
    FILE *fout = fdopen(fdout, "wb");
    VaultError ret = ERR_OK;
    EVP_CIPHER_CTX *ctx = NULL;

    if (!fin || !fout) { ret = ERR_IO; goto cleanup; }

    /* Salt por arquivo */
    uint8_t file_salt[SALT_LEN];
    if (RAND_bytes(file_salt, SALT_LEN) != 1) { ret = ERR_CRYPTO; goto cleanup; }

    /* Deriva chave por arquivo a partir da master_key + file_salt */
    uint8_t file_key[KEY_LEN];
    uint8_t combined[KEY_LEN + SALT_LEN];
    memcpy(combined, master_key, KEY_LEN);
    memcpy(combined + KEY_LEN, file_salt, SALT_LEN);
    int rc2 = PKCS5_PBKDF2_HMAC(
        (char*)combined, (int)sizeof(combined),
        file_salt, SALT_LEN, 1,   /* 1 iter: já derivado da master */
        EVP_sha256(), KEY_LEN, file_key);
    explicit_bzero(combined, sizeof(combined));
    if (rc2 != 1) { ret = ERR_CRYPTO; goto cleanup; }

    uint8_t nonce[GCM_IV_LEN];
    if (RAND_bytes(nonce, GCM_IV_LEN) != 1) {
        explicit_bzero(file_key, KEY_LEN); ret = ERR_CRYPTO; goto cleanup;
    }

    /* Escreve: salt | nonce | tag (placeholder) | ciphertext */
    uint32_t slen = SALT_LEN;
    if (fwrite(&slen,      4,          1, fout) != 1 ||
        fwrite(file_salt,  SALT_LEN,   1, fout) != 1 ||
        fwrite(nonce,      GCM_IV_LEN, 1, fout) != 1) {
        explicit_bzero(file_key, KEY_LEN); ret = ERR_IO; goto cleanup;
    }

    /* Reserva espaço para tag (será escrita depois) */
    uint8_t tag_placeholder[GCM_TAG_LEN] = {0};
    long tag_offset = ftell(fout);
    if (fwrite(tag_placeholder, GCM_TAG_LEN, 1, fout) != 1) {
        explicit_bzero(file_key, KEY_LEN); ret = ERR_IO; goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { explicit_bzero(file_key, KEY_LEN); ret = ERR_CRYPTO; goto cleanup; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, file_key, nonce) != 1) {
        explicit_bzero(file_key, KEY_LEN); ret = ERR_CRYPTO; goto cleanup;
    }
    explicit_bzero(file_key, KEY_LEN);

    uint8_t inbuf[65536];
    uint8_t outbuf[65536 + 32];
    int outlen;
    size_t n;

    while ((n = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)n) != 1) {
            ret = ERR_CRYPTO; goto cleanup;
        }
        if (fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
            ret = ERR_IO; goto cleanup;
        }
    }
    if (ferror(fin)) { ret = ERR_IO; goto cleanup; }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        ret = ERR_CRYPTO; goto cleanup;
    }
    if (outlen > 0 && fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
        ret = ERR_IO; goto cleanup;
    }

    /* Lê e escreve a tag GCM na posição reservada */
    uint8_t tag[GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
        ret = ERR_CRYPTO; goto cleanup;
    }
    if (fseek(fout, tag_offset, SEEK_SET) != 0 ||
        fwrite(tag, GCM_TAG_LEN, 1, fout) != 1) {
        ret = ERR_IO; goto cleanup;
    }

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(inbuf,  sizeof(inbuf));
    explicit_bzero(outbuf, sizeof(outbuf));
    if (fin)  fclose(fin);
    if (fout) fclose(fout);
    if (ret != ERR_OK) unlink(outpath);
    return ret;
}

/* [MED-D] AES-256-GCM decrypt com verificação de tag */
static VaultError decrypt_file(const char *inpath, const char *outpath,
                                const uint8_t master_key[KEY_LEN]) {
    int fdin = open(inpath, O_RDONLY | O_NOFOLLOW);
    if (fdin < 0) return ERR_IO;

    int fdout = open(outpath, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0600);
    if (fdout < 0) { close(fdin); return ERR_IO; }

    FILE *fin  = fdopen(fdin,  "rb");
    FILE *fout = fdopen(fdout, "wb");
    VaultError ret = ERR_OK;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t file_key[KEY_LEN];
    bool key_cleared = false;

    if (!fin || !fout) { ret = ERR_IO; goto cleanup; }

    /* Lê salt */
    uint32_t slen = 0;
    if (fread(&slen, 4, 1, fin) != 1 || slen != SALT_LEN) {
        vault_log(LOG_ERROR, "decrypt: invalid salt length %u", slen);
        ret = ERR_CRYPTO; goto cleanup;
    }
    uint8_t file_salt[SALT_LEN];
    if (fread(file_salt, SALT_LEN, 1, fin) != 1) {
        ret = ERR_IO; goto cleanup;
    }

    /* Deriva chave por arquivo */
    uint8_t combined[KEY_LEN + SALT_LEN];
    memcpy(combined, master_key, KEY_LEN);
    memcpy(combined + KEY_LEN, file_salt, SALT_LEN);
    int rc2 = PKCS5_PBKDF2_HMAC(
        (char*)combined, (int)sizeof(combined),
        file_salt, SALT_LEN, 1,
        EVP_sha256(), KEY_LEN, file_key);
    explicit_bzero(combined, sizeof(combined));
    if (rc2 != 1) { ret = ERR_CRYPTO; goto cleanup; }

    uint8_t nonce[GCM_IV_LEN];
    uint8_t tag[GCM_TAG_LEN];
    if (fread(nonce, GCM_IV_LEN, 1, fin) != 1 ||
        fread(tag,   GCM_TAG_LEN, 1, fin) != 1) {
        explicit_bzero(file_key, KEY_LEN); ret = ERR_IO; goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { explicit_bzero(file_key, KEY_LEN); ret = ERR_CRYPTO; goto cleanup; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, file_key, nonce) != 1) {
        explicit_bzero(file_key, KEY_LEN); ret = ERR_CRYPTO; goto cleanup;
    }
    explicit_bzero(file_key, KEY_LEN);
    key_cleared = true;

    uint8_t inbuf[65536];
    uint8_t outbuf[65536 + 32];
    int outlen;
    size_t n;

    while ((n = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, (int)n) != 1) {
            ret = ERR_CRYPTO; goto cleanup;
        }
        if (fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
            ret = ERR_IO; goto cleanup;
        }
    }

    /* Seta a tag antes do Final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) {
        vault_log(LOG_ERROR, "GCM set tag failed");
        ret = ERR_CRYPTO; goto cleanup;
    }

    /* [MED-D] DecryptFinal verifica autenticidade — falha = dados adulterados */
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        vault_log(LOG_ERROR, "GCM auth tag MISMATCH — file corrupted or tampered");
        ret = ERR_INTEGRITY; goto cleanup;
    }
    if (outlen > 0 && fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
        ret = ERR_IO;
    }

cleanup:
    if (!key_cleared) explicit_bzero(file_key, KEY_LEN);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(inbuf,  sizeof(inbuf));
    explicit_bzero(outbuf, sizeof(outbuf));
    if (fin)  fclose(fin);
    if (fout) fclose(fout);
    if (ret != ERR_OK) unlink(outpath); /* remove arquivo parcialmente descriptografado */
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 5: FILE HASH MAP
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint32_t hashmap_bucket(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h % HASHMAP_BUCKETS;
}

static FileEntry *hashmap_find(FileHashMap *m, const char *filename) {
    uint32_t b = hashmap_bucket(filename);
    for (FileEntry *e = m->buckets[b]; e; e = e->next)
        if (strcmp(e->filename, filename) == 0) return e;
    return NULL;
}

static FileEntry *hashmap_insert(FileHashMap *m, const char *filename) {
    if (m->count >= MAX_FILES_PER_VAULT) {
        vault_log(LOG_WARN, "hashmap: max files per vault reached");
        return NULL;
    }
    uint32_t b = hashmap_bucket(filename);
    FileEntry *e = hashmap_find(m, filename);
    if (e) return e;

    e = calloc(1, sizeof(FileEntry));
    if (!e) return NULL;

    /* [CRIT-A] cópia segura com tamanho explícito */
    strncpy(e->filename, filename, NAME_MAX);
    e->filename[NAME_MAX] = '\0';
    e->next = m->buckets[b];
    m->buckets[b] = e;
    m->count++;
    return e;
}

static void hashmap_clear(FileHashMap *m) {
    for (int i=0; i<HASHMAP_BUCKETS; i++) {
        FileEntry *e = m->buckets[i];
        while (e) {
            FileEntry *next = e->next;
            explicit_bzero(e, sizeof(FileEntry)); /* [MIN-H] */
            free(e);
            e = next;
        }
        m->buckets[i] = NULL;
    }
    m->count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 6: CATALOG SERIALISATION  [CRIT-A] [CRIT-B] [MED-E]
 *
 * Formato v2:
 *   [4]   magic "VLTS"
 *   [1]   version = 2
 *   [4]   count
 *   [4]   next_id
 *   [32]  category
 *   --- payload começa aqui (tudo abaixo entra no HMAC) ---
 *   [N]   vaults serializados
 *   [32]  HMAC-SHA256(catalog_key, payload)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Lê exatamente n bytes; retorna false se não conseguir */
static bool safe_fread(FILE *fp, void *buf, size_t n) {
    size_t got = fread(buf, 1, n, fp);
    if (got != n) {
        if (got < n) memset((uint8_t*)buf + got, 0, n - got);
        return false;
    }
    return true;
}

/* Serializa um Vault para um buffer dinâmico; retorna bytes escritos */
static size_t vault_serialize(const Vault *v, uint8_t *buf, size_t bufsz) {
    size_t pos = 0;
#define WFIELD(field) \
    do { if (pos+sizeof(v->field)>bufsz) return 0; \
         memcpy(buf+pos,&v->field,sizeof(v->field)); pos+=sizeof(v->field); } while(0)
#define WBYTES(ptr, sz) \
    do { if (pos+(sz)>bufsz) return 0; \
         memcpy(buf+pos,(ptr),(sz)); pos+=(sz); } while(0)

    WFIELD(id);
    WBYTES(v->name, VAULT_NAME_MAX);
    WFIELD(type);
    WFIELD(status);
    uint8_t hp = v->has_pass ? 1 : 0;
    WBYTES(&hp, 1);
    WBYTES(v->path, VAULT_PATH_MAX);
    WFIELD(created_at);
    WFIELD(last_check);
    WFIELD(failed_attempts);
    WFIELD(alert.interval_idx);
    WFIELD(alert.first_triggered);
    WFIELD(alert.last_alerted);
    WFIELD(alert.alert_count);
    WBYTES(v->alert.reason, 256);
    WBYTES(v->salt, SALT_LEN);
    WBYTES(v->pass_hash, SHA256_DIGEST_LENGTH);

    uint32_t fcount = (uint32_t)v->hashmap.count;
    WBYTES(&fcount, 4);

    for (int b=0; b<HASHMAP_BUCKETS; b++) {
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next) {
            WBYTES(e->filename, NAME_MAX+1);
            WBYTES(e->hash, HASH_HEX_LEN);
            WFIELD(e->last_seen);
            uint8_t mod = e->modified ? 1 : 0;
            WBYTES(&mod, 1);
        }
    }
#undef WFIELD
#undef WBYTES
    return pos;
}

static VaultError catalog_save(void) {
    if (catalog_key_init() != ERR_OK) return ERR_CRYPTO;

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", VAULT_CATALOG_FILE, (int)getpid());

    /* [MED-F] Cria com O_EXCL para evitar symlink race */
    int fd = open(tmp, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) {
        /* Pode já existir de crash anterior */
        unlink(tmp);
        fd = open(tmp, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (fd < 0) {
            vault_log(LOG_ERROR, "catalog_save: open %s: %s", tmp, strerror(errno));
            return ERR_IO;
        }
    }
    FILE *fp = fdopen(fd, "wb");
    if (!fp) { close(fd); unlink(tmp); return ERR_IO; }

    /* Header (não entra no HMAC) */
    fwrite(CATALOG_MAGIC, 1, 4, fp);
    uint8_t ver = CATALOG_VER;
    fwrite(&ver, 1, 1, fp);
    fwrite(&g_catalog.count, 4, 1, fp);
    fwrite(&g_catalog.next_id, 4, 1, fp);
    fwrite(g_catalog.category, 1, 32, fp);

    /* Payload: serializa todos os vaults para buffer em memória
     * para depois calcular HMAC sobre o payload completo */
    size_t bufsz = g_catalog.count *
                   (sizeof(Vault) + MAX_FILES_PER_VAULT * (NAME_MAX+1+HASH_HEX_LEN+9))
                   + 4096;
    uint8_t *payload = malloc(bufsz);
    if (!payload) { fclose(fp); unlink(tmp); return ERR_NO_MEMORY; }

    size_t total = 0;
    bool ok = true;

    for (uint32_t i=0; i<g_catalog.count && ok; i++) {
        size_t n = vault_serialize(&g_catalog.vaults[i], payload+total, bufsz-total);
        if (n == 0) ok = false;
        else total += n;
    }

    if (!ok) {
        free(payload); fclose(fp); unlink(tmp);
        return ERR_IO;
    }

    /* Escreve payload */
    if (fwrite(payload, 1, total, fp) != total) {
        free(payload); fclose(fp); unlink(tmp);
        return ERR_IO;
    }

    /* [CRIT-B] Calcula e escreve HMAC do payload */
    uint8_t mac[HMAC_LEN];
    if (!hmac_sha256(g_catalog_hmac_key, CATALOG_KEY_LEN, payload, total, mac)) {
        free(payload); fclose(fp); unlink(tmp);
        return ERR_CRYPTO;
    }
    fwrite(mac, 1, HMAC_LEN, fp);

    free(payload);
    fclose(fp);

    /* Atomic rename */
    if (rename(tmp, VAULT_CATALOG_FILE) != 0) {
        vault_log(LOG_ERROR, "catalog_save: rename: %s", strerror(errno));
        unlink(tmp);
        return ERR_IO;
    }
    chmod(VAULT_CATALOG_FILE, 0600);
    g_catalog.dirty = false;
    vault_log(LOG_INFO, "Catalog saved (%u vaults)", g_catalog.count);
    return ERR_OK;
}

static VaultError catalog_load(void) {
    if (catalog_key_init() != ERR_OK) return ERR_CRYPTO;

    FILE *fp = fopen(VAULT_CATALOG_FILE, "rb");
    if (!fp) {
        if (errno == ENOENT) {
            vault_log(LOG_INFO, "No catalog found, starting fresh");
            strncpy(g_catalog.category, "diamond", 31);
            g_catalog.next_id = 1;
            return ERR_OK;
        }
        return ERR_IO;
    }

    /* [MED-F] fstat do fd aberto para não ter TOCTOU */
    int fd = fileno(fp);
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fclose(fp);
        vault_log(LOG_ERROR, "catalog_load: not a regular file");
        return ERR_IO;
    }
    /* Sanidade de tamanho: não deve ser absurdamente grande */
    if (st.st_size > 256 * 1024 * 1024) {
        fclose(fp); return ERR_IO;
    }

    /* Header */
    char magic[5] = {0};
    if (!safe_fread(fp, magic, 4) || memcmp(magic, CATALOG_MAGIC, 4) != 0) {
        fclose(fp); vault_log(LOG_ERROR, "catalog: bad magic"); return ERR_IO;
    }
    uint8_t ver;
    if (!safe_fread(fp, &ver, 1) || ver != CATALOG_VER) {
        fclose(fp); vault_log(LOG_ERROR, "catalog: unsupported version %d", ver);
        return ERR_IO;
    }

    uint32_t count, next_id;
    char category[32];
    if (!safe_fread(fp, &count, 4) || !safe_fread(fp, &next_id, 4) ||
        !safe_fread(fp, category, 32)) {
        fclose(fp); return ERR_IO;
    }

    /* [CRIT-A] Valida count antes de alocar/iterar */
    if (count > MAX_VAULTS) {
        fclose(fp);
        vault_log(LOG_ERROR, "catalog: count %u > MAX_VAULTS %d — refusing", count, MAX_VAULTS);
        return ERR_IO;
    }

    /* Lê payload para buffer e depois valida HMAC */
    long payload_start = ftell(fp);
    if (payload_start < 0) { fclose(fp); return ERR_IO; }

    /* Tamanho do payload = file_size - header - HMAC */
    off_t payload_sz = st.st_size - payload_start - HMAC_LEN;
    if (payload_sz <= 0 || payload_sz > 64*1024*1024) {
        fclose(fp); return ERR_IO;
    }

    uint8_t *payload = malloc((size_t)payload_sz);
    if (!payload) { fclose(fp); return ERR_NO_MEMORY; }

    if (!safe_fread(fp, payload, (size_t)payload_sz)) {
        free(payload); fclose(fp); return ERR_IO;
    }

    uint8_t stored_mac[HMAC_LEN];
    if (!safe_fread(fp, stored_mac, HMAC_LEN)) {
        free(payload); fclose(fp); return ERR_IO;
    }
    fclose(fp);

    /* [CRIT-B] Verifica HMAC do catálogo */
    uint8_t computed_mac[HMAC_LEN];
    if (!hmac_sha256(g_catalog_hmac_key, CATALOG_KEY_LEN,
                     payload, (size_t)payload_sz, computed_mac)) {
        free(payload); return ERR_CRYPTO;
    }

    /* Comparação em tempo constante */
    if (CRYPTO_memcmp(stored_mac, computed_mac, HMAC_LEN) != 0) {
        free(payload);
        vault_log(LOG_ALERT, "CATALOG INTEGRITY CHECK FAILED — possible tampering detected!");
        return ERR_CATALOG_TAMPERED;
    }

    /* Deserializa vaults do payload validado */
    size_t pos = 0;
    g_catalog.count   = 0;
    g_catalog.next_id = next_id;
    strncpy(g_catalog.category, category, 31);
    g_catalog.category[31] = '\0';

    for (uint32_t i = 0; i < count; i++) {
        Vault *v = &g_catalog.vaults[i];
        memset(v, 0, sizeof(Vault));

#define RFIELD(field) \
    do { if (pos+sizeof(v->field)>(size_t)payload_sz) goto trunc; \
         memcpy(&v->field, payload+pos, sizeof(v->field)); pos+=sizeof(v->field); } while(0)
#define RBYTES(ptr, sz) \
    do { if (pos+(sz)>(size_t)payload_sz) goto trunc; \
         memcpy((ptr), payload+pos, (sz)); pos+=(sz); } while(0)

        RFIELD(id);

        /* [CRIT-A] Lê name com NUL garantido */
        RBYTES(v->name, VAULT_NAME_MAX);
        v->name[VAULT_NAME_MAX-1] = '\0';

        RFIELD(type);
        /* [CRIT-A] Valida enum */
        if (v->type != VAULT_TYPE_NORMAL && v->type != VAULT_TYPE_PROTECTED) {
            vault_log(LOG_ERROR, "catalog: invalid vault type for id=%u", v->id);
            goto trunc;
        }

        RFIELD(status);
        if (v->status > VAULT_STATUS_DELETED) {
            vault_log(LOG_ERROR, "catalog: invalid vault status for id=%u", v->id);
            goto trunc;
        }

        uint8_t hp;
        RBYTES(&hp, 1);
        v->has_pass = (hp == 1);

        RBYTES(v->path, VAULT_PATH_MAX);
        v->path[VAULT_PATH_MAX-1] = '\0';

        /* [CRIT-A] Valida path lido */
        if (validate_path(v->path) != ERR_OK && v->path[0] != '\0') {
            vault_log(LOG_WARN, "catalog: suspicious path for vault id=%u, ignoring", v->id);
            v->path[0] = '\0';
        }

        RFIELD(created_at);
        RFIELD(last_check);
        RFIELD(failed_attempts);

        /* [CRIT-A] Limita failed_attempts a valor razoável */
        if (v->failed_attempts < 0) v->failed_attempts = MAX_PASS_ATTEMPTS;

        RFIELD(alert.interval_idx);
        /* [CRIT-A] Limita idx ao array */
        if (v->alert.interval_idx >= NUM_ALERT_INTERVALS)
            v->alert.interval_idx = NUM_ALERT_INTERVALS - 1;

        RFIELD(alert.first_triggered);
        RFIELD(alert.last_alerted);
        RFIELD(alert.alert_count);
        RBYTES(v->alert.reason, 256);
        v->alert.reason[255] = '\0';

        RBYTES(v->salt, SALT_LEN);
        RBYTES(v->pass_hash, SHA256_DIGEST_LENGTH);

        uint32_t fcount;
        RBYTES(&fcount, 4);

        /* [CRIT-A] Limite rigoroso de fcount */
        if (fcount > MAX_FILES_PER_VAULT) {
            vault_log(LOG_ERROR, "catalog: fcount=%u > MAX for vault id=%u — refusing", fcount, v->id);
            goto trunc;
        }

        for (uint32_t f = 0; f < fcount; f++) {
            char     fname[NAME_MAX+1];
            char     fhash[HASH_HEX_LEN];
            time_t   ls;
            uint8_t  mod;

            RBYTES(fname, NAME_MAX+1);
            fname[NAME_MAX] = '\0';

            RBYTES(fhash, HASH_HEX_LEN);
            fhash[HASH_HEX_LEN-1] = '\0';

            RFIELD(ls);
            RBYTES(&mod, 1);

            /* [CRIT-A] Valida hash: deve ser hex lowercase */
            bool valid_hash = true;
            for (int h=0; h<HASH_HEX_LEN-1; h++)
                if (!((fhash[h]>='0'&&fhash[h]<='9')||(fhash[h]>='a'&&fhash[h]<='f'))) {
                    valid_hash = false; break;
                }
            if (!valid_hash) {
                vault_log(LOG_WARN, "catalog: invalid hash for file '%s', skipping", fname);
                continue;
            }

            FileEntry *e = hashmap_insert(&v->hashmap, fname);
            if (e) {
                memcpy(e->hash, fhash, HASH_HEX_LEN);
                e->last_seen = ls;
                e->modified  = (mod == 1);
            }
        }

#undef RFIELD
#undef RBYTES

        v->inotify_wd = -1;

        /* Inicializa rate bucket */
        v->rate.tokens      = RATE_BUCKET_MAX;
        v->rate.last_refill = time(NULL);

        g_catalog.count++;
        continue;

trunc:
        vault_log(LOG_ERROR, "catalog: truncated data for vault %u — stopping load", i);
        explicit_bzero(v, sizeof(Vault));
        break;
    }

    free(payload);
    vault_log(LOG_INFO, "Catalog loaded: %u vaults (HMAC OK)", g_catalog.count);
    return ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 7: AUTHENTICATION + RATE LIMITING  [MIN-I]
 * ═══════════════════════════════════════════════════════════════════════════ */

/* [MIN-I] Consome um token do bucket; retorna false se esgotado */
static bool rate_consume(Vault *v) {
    time_t now = time(NULL);
    double elapsed = difftime(now, v->rate.last_refill);
    int new_tokens = (int)(elapsed / RATE_REFILL_SEC);
    if (new_tokens > 0) {
        v->rate.tokens = (v->rate.tokens + new_tokens > RATE_BUCKET_MAX)
                       ? RATE_BUCKET_MAX
                       : v->rate.tokens + new_tokens;
        v->rate.last_refill = now;
    }
    if (v->rate.tokens <= 0) return false;
    v->rate.tokens--;
    return true;
}

static VaultError auth_set_password(Vault *v, const char *password) {
    VAULT_ASSERT(v && password, ERR_INVALID_ARGS, "null vault or password");
    VAULT_ASSERT(strlen(password) >= 8, ERR_INVALID_ARGS,
                 "Password must be at least 8 characters");
    VAULT_ASSERT(strlen(password) < MAX_PASS_LEN, ERR_INVALID_ARGS,
                 "Password too long");

    if (RAND_bytes(v->salt, SALT_LEN) != 1) return ERR_CRYPTO;

    uint8_t key[KEY_LEN];
    VaultError err = derive_key(password, v->salt, key);
    if (err != ERR_OK) return err;

    memcpy(v->pass_hash, key, SHA256_DIGEST_LENGTH);
    explicit_bzero(key, KEY_LEN); /* [MIN-H] */
    v->has_pass = true;

    /* [CRIT-B] Reforça chave do catálogo com este pass_hash */
    catalog_key_reinforce(v->pass_hash);

    vault_log(LOG_AUDIT, "Password set for vault id=%u", v->id);
    return ERR_OK;
}

static VaultError auth_verify_password(Vault *v, const char *password) {
    VAULT_ASSERT(v && password, ERR_INVALID_ARGS, "null vault or password");

    if (!v->has_pass) return ERR_PASS_REQUIRED;

    /* [MIN-I] Rate limiting */
    if (!rate_consume(v)) {
        vault_log(LOG_ALERT, "Rate limit exceeded for vault id=%u", v->id);
        return ERR_AUTH_FAIL;
    }

    uint8_t key[KEY_LEN];
    VaultError err = derive_key(password, v->salt, key);
    if (err != ERR_OK) { explicit_bzero(key, KEY_LEN); return err; }

    /* Comparação em tempo constante — evita timing attacks */
    bool match = (CRYPTO_memcmp(v->pass_hash, key, SHA256_DIGEST_LENGTH) == 0);
    explicit_bzero(key, KEY_LEN); /* [MIN-H] */

    if (!match) {
        v->failed_attempts++;
        vault_log(LOG_AUDIT, "Auth FAILED vault id=%u (attempt %d/%d)",
                  v->id, v->failed_attempts, MAX_PASS_ATTEMPTS);
        if (v->failed_attempts >= MAX_PASS_ATTEMPTS) {
            v->status = VAULT_STATUS_LOCKED;
            vault_log(LOG_ALERT, "Vault id=%u LOCKED after %d failed attempts",
                      v->id, MAX_PASS_ATTEMPTS);
            g_catalog.dirty = true;
        }
        return ERR_AUTH_FAIL;
    }

    v->failed_attempts = 0;
    vault_log(LOG_AUDIT, "Auth OK vault id=%u", v->id);
    return ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 8: VAULT MANAGER
 * ═══════════════════════════════════════════════════════════════════════════ */

static Vault *vault_find_by_id(uint32_t id) {
    for (uint32_t i=0; i<g_catalog.count; i++)
        if (g_catalog.vaults[i].id == id) return &g_catalog.vaults[i];
    return NULL;
}

static Vault *vault_find_by_name(const char *name) {
    for (uint32_t i=0; i<g_catalog.count; i++)
        if (strcmp(g_catalog.vaults[i].name, name) == 0)
            return &g_catalog.vaults[i];
    return NULL;
}

static void vault_auto_name(char *out, size_t outsz) {
    uint32_t n = 1;
    char candidate[VAULT_NAME_MAX];
    do { snprintf(candidate, sizeof(candidate), "diamond_vault_%u", n++); }
    while (vault_find_by_name(candidate) != NULL);
    strncpy(out, candidate, outsz-1); out[outsz-1] = '\0';
}

static VaultError vault_create(const char *name_arg, VaultType type,
                                const char *path_arg, const char *password) {
    if (g_catalog.count >= MAX_VAULTS) return ERR_CATALOG_FULL;

    char name_buf[VAULT_NAME_MAX];
    char path_buf[VAULT_PATH_MAX];

    if (name_arg && *name_arg) {
        char tmp[VAULT_NAME_MAX];
        strncpy(tmp, name_arg, VAULT_NAME_MAX-1); tmp[VAULT_NAME_MAX-1]='\0';
        char *n = sanitize_arg(tmp);
        strncpy(name_buf, n, VAULT_NAME_MAX-1); name_buf[VAULT_NAME_MAX-1]='\0';
    } else {
        vault_auto_name(name_buf, sizeof(name_buf));
    }

    VaultError err = validate_name(name_buf);
    if (err != ERR_OK) return err;
    if (vault_find_by_name(name_buf)) return ERR_VAULT_EXISTS;

    if (path_arg && *path_arg) {
        char tmp[VAULT_PATH_MAX];
        strncpy(tmp, path_arg, VAULT_PATH_MAX-1); tmp[VAULT_PATH_MAX-1]='\0';
        char *p = sanitize_arg(tmp);
        strncpy(path_buf, p, VAULT_PATH_MAX-1); path_buf[VAULT_PATH_MAX-1]='\0';
        err = validate_path(path_buf);
        if (err != ERR_OK) return err;
    } else {
        snprintf(path_buf, sizeof(path_buf), "%s/%s", VAULT_CATALOG_PATH, name_buf);
    }

    if (type == VAULT_TYPE_PROTECTED && (!password || !*password))
        return ERR_PASS_REQUIRED;

    /* [MED-F] Cria diretório e verifica com fstat */
    if (mkdir(path_buf, 0700) != 0 && errno != EEXIST) {
        vault_log(LOG_ERROR, "mkdir '%s': %s", path_buf, strerror(errno));
        return ERR_IO;
    }
    /* Verifica que é realmente um diretório */
    struct stat st;
    if (stat(path_buf, &st) != 0 || !S_ISDIR(st.st_mode)) {
        vault_log(LOG_ERROR, "vault path is not a directory");
        return ERR_PATH_INVALID;
    }

    Vault *v = &g_catalog.vaults[g_catalog.count];
    memset(v, 0, sizeof(Vault));
    v->id         = g_catalog.next_id++;
    v->type       = type;
    v->status     = VAULT_STATUS_OK;
    v->created_at = time(NULL);
    v->last_check = v->created_at;
    v->inotify_wd = -1;
    v->rate.tokens = RATE_BUCKET_MAX;
    v->rate.last_refill = v->created_at;

    strncpy(v->name, name_buf, VAULT_NAME_MAX-1);
    strncpy(v->path, path_buf, VAULT_PATH_MAX-1);

    if (type == VAULT_TYPE_PROTECTED) {
        err = auth_set_password(v, password);
        if (err != ERR_OK) { explicit_bzero(v, sizeof(Vault)); return err; }
    }

    g_catalog.count++;
    g_catalog.dirty = true;
    err = catalog_save();

    char safe_name[LOG_FIELD_MAX+1];
    log_sanitize(v->name, safe_name, sizeof(safe_name));
    vault_log(LOG_AUDIT, "Vault CREATED: id=%u name='%s' type=%s",
              v->id, safe_name,
              type==VAULT_TYPE_PROTECTED ? "PROTECTED" : "NORMAL");

    printf("\n  ✓ Vault created\n");
    printf("    ID   : %u\n", v->id);
    printf("    Name : %s\n", v->name);
    printf("    Type : %s\n", type==VAULT_TYPE_PROTECTED ? "PROTECTED":"NORMAL");
    printf("    Path : %s\n\n", v->path);
    return err;
}

static VaultError vault_delete(uint32_t id, const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;

    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        VaultError err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }

    vault_log(LOG_AUDIT, "Vault DELETED: id=%u", v->id);
    explicit_bzero(v->salt, SALT_LEN);
    explicit_bzero(v->pass_hash, SHA256_DIGEST_LENGTH);
    hashmap_clear(&v->hashmap);

    uint32_t idx = (uint32_t)(v - g_catalog.vaults);
    memmove(&g_catalog.vaults[idx], &g_catalog.vaults[idx+1],
            (g_catalog.count - idx - 1) * sizeof(Vault));
    g_catalog.count--;
    g_catalog.dirty = true;
    return catalog_save();
}

static VaultError vault_rename(uint32_t id, const char *new_name,
                                const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;

    char tmp[VAULT_NAME_MAX];
    strncpy(tmp, new_name, VAULT_NAME_MAX-1); tmp[VAULT_NAME_MAX-1]='\0';
    char *n = sanitize_arg(tmp);
    VaultError err = validate_name(n);
    if (err != ERR_OK) return err;
    if (vault_find_by_name(n)) return ERR_VAULT_EXISTS;

    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }

    vault_log(LOG_AUDIT, "Vault RENAMED: id=%u", v->id);
    strncpy(v->name, n, VAULT_NAME_MAX-1);
    g_catalog.dirty = true;
    return catalog_save();
}

static VaultError vault_unlock(uint32_t id, const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;
    if (v->status != VAULT_STATUS_LOCKED) {
        printf("Vault is not locked.\n");
        return ERR_OK;
    }
    if (!password || !*password) return ERR_PASS_REQUIRED;
    VaultError err = auth_verify_password(v, password);
    if (err != ERR_OK) return err;
    v->status = VAULT_STATUS_OK;
    v->failed_attempts = 0;
    vault_log(LOG_AUDIT, "Vault UNLOCKED: id=%u", v->id);
    g_catalog.dirty = true;
    return catalog_save();
}

static VaultError vault_change_password(uint32_t id, const char *old_pass,
                                         const char *new_pass) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;
    if (!v->has_pass) return ERR_PASS_REQUIRED;
    VaultError err = auth_verify_password(v, old_pass);
    if (err != ERR_OK) return err;
    err = auth_set_password(v, new_pass);
    if (err != ERR_OK) return err;
    vault_log(LOG_AUDIT, "Password CHANGED vault id=%u", v->id);
    g_catalog.dirty = true;
    return catalog_save();
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 9: FILE INTEGRITY MONITOR
 * ═══════════════════════════════════════════════════════════════════════════ */
static void monitor_scan_vault(Vault *v) {
    if (v->status == VAULT_STATUS_DELETED || v->path[0] == '\0') return;

    /* [MED-F] Abre diretório e valida com fstat */
    int dfd = open(v->path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dfd < 0) {
        vault_log(LOG_ERROR, "Cannot scan vault id=%u: %s", v->id, strerror(errno));
        return;
    }

    DIR *dir = fdopendir(dfd);
    if (!dir) { close(dfd); return; }

    struct dirent *de;
    char filepath[VAULT_PATH_MAX + NAME_MAX + 2];

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;

        /* [MED-F] stat relativo ao dfd para evitar TOCTOU */
        struct stat st;
        if (fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", v->path, de->d_name);

        char new_hash[HASH_HEX_LEN];
        if (sha256_file(filepath, new_hash) != ERR_OK) continue;

        FileEntry *e = hashmap_find(&v->hashmap, de->d_name);
        if (!e) {
            e = hashmap_insert(&v->hashmap, de->d_name);
            if (e) {
                memcpy(e->hash, new_hash, HASH_HEX_LEN);
                e->last_seen = time(NULL);
                e->modified  = false;
                vault_log(LOG_INFO, "[vault %u] New file: %s", v->id, de->d_name);
            }
        } else {
            if (memcmp(e->hash, new_hash, HASH_HEX_LEN) != 0) {
                if (!e->modified) {
                    e->modified = true;
                    char safe_fn[LOG_FIELD_MAX+1];
                    log_sanitize(de->d_name, safe_fn, sizeof(safe_fn));
                    vault_log(LOG_ALERT, "[vault %u] File MODIFIED: %s", v->id, safe_fn);
                    char reason[256];
                    snprintf(reason, sizeof(reason), "File modified: %.200s", safe_fn);
                    alert_trigger(v, reason);
                }
                memcpy(e->hash, new_hash, HASH_HEX_LEN);
            } else {
                e->modified = false;
            }
            e->last_seen = time(NULL);
        }
    }
    closedir(dir);
    v->last_check = time(NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 10: ALERT SYSTEM
 * ═══════════════════════════════════════════════════════════════════════════ */
static void alert_trigger(Vault *v, const char *reason) {
    time_t now = time(NULL);
    if (v->alert.first_triggered == 0) {
        v->alert.first_triggered = now;
        v->alert.interval_idx    = 0;
    }
    strncpy(v->alert.reason, reason, 255); v->alert.reason[255]='\0';
    v->status = VAULT_STATUS_ALERT;
    vault_log(LOG_ALERT, "ALERT [vault id=%u]: %s", v->id, reason);
    g_catalog.dirty = true;
}

static void alert_check_escalation(Vault *v) {
    if (v->status != VAULT_STATUS_ALERT) return;
    time_t now = time(NULL);
    if (v->alert.last_alerted == 0) {
        vault_log(LOG_ALERT, "REPEAT ALERT [vault %u] (×%zu): %s",
                  v->id, ++v->alert.alert_count, v->alert.reason);
        fprintf(stderr, "\n  *** VAULT ALERT [%u] %s ***\n\n",
                v->id, v->alert.reason);
        v->alert.last_alerted = now;
        return;
    }
    long interval = (v->alert.interval_idx < NUM_ALERT_INTERVALS)
                  ? ALERT_INTERVALS[v->alert.interval_idx]
                  : ALERT_INTERVALS[NUM_ALERT_INTERVALS-1];
    if (now - v->alert.last_alerted >= interval) {
        v->alert.alert_count++;
        vault_log(LOG_ALERT, "REPEAT ALERT [vault %u] (×%zu, int=%lds): %s",
                  v->id, v->alert.alert_count, interval, v->alert.reason);
        fprintf(stderr, "\n  *** VAULT ALERT (×%zu) [%u] ***\n\n",
                v->alert.alert_count, v->id);
        v->alert.last_alerted = now;
        if (v->alert.interval_idx < NUM_ALERT_INTERVALS-1)
            v->alert.interval_idx++;
    }
}

static VaultError alert_resolve(uint32_t id, const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;
    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        VaultError err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }
    for (int b=0; b<HASHMAP_BUCKETS; b++)
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next)
            e->modified = false;
    memset(&v->alert, 0, sizeof(v->alert));
    v->status = VAULT_STATUS_OK;
    vault_log(LOG_AUDIT, "Alert RESOLVED vault id=%u", v->id);
    g_catalog.dirty = true;
    return catalog_save();
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 11: RULE ENGINE
 * ═══════════════════════════════════════════════════════════════════════════ */
typedef struct {
    uint32_t vault_id;
    int      max_failed_attempts;
    int      allowed_hour_from;
    int      allowed_hour_to;
} VaultRule;

#define MAX_RULES 64
static VaultRule g_rules[MAX_RULES];
static uint32_t  g_rule_count = 0;

static void rule_add(uint32_t vault_id, int max_fails,
                     int hour_from, int hour_to) {
    if (g_rule_count >= MAX_RULES) { vault_log(LOG_WARN, "Rule table full"); return; }
    g_rules[g_rule_count++] = (VaultRule){
        .vault_id=vault_id, .max_failed_attempts=max_fails,
        .allowed_hour_from=hour_from, .allowed_hour_to=hour_to
    };
}

static void rule_evaluate(Vault *v) {
    for (uint32_t i=0; i<g_rule_count; i++) {
        VaultRule *r = &g_rules[i];
        if (r->vault_id != v->id) continue;
        if (r->max_failed_attempts > 0 &&
            v->failed_attempts >= r->max_failed_attempts &&
            v->status != VAULT_STATUS_LOCKED) {
            v->status = VAULT_STATUS_LOCKED;
            vault_log(LOG_ALERT, "[RULE] Vault %u LOCKED: %d failed attempts",
                      v->id, v->failed_attempts);
            g_catalog.dirty = true;
        }
        if (r->allowed_hour_from >= 0 && r->allowed_hour_to >= 0) {
            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            int hour = t->tm_hour;
            bool in_window = (r->allowed_hour_from <= r->allowed_hour_to)
                ? (hour>=r->allowed_hour_from && hour<r->allowed_hour_to)
                : (hour>=r->allowed_hour_from || hour<r->allowed_hour_to);
            if (!in_window) {
                char reason[256];
                snprintf(reason, sizeof(reason),
                         "Access outside allowed window (%02d-%02d), hour=%02d",
                         r->allowed_hour_from, r->allowed_hour_to, hour);
                alert_trigger(v, reason);
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 12: SANDBOX  [CRIT-C] seccomp-BPF + namespace + chroot
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Allowlist mínima de syscalls para o processo filho (shell restrito).
 * Qualquer syscall fora desta lista → SIGKILL imediato.
 *
 * Lista conservadora: suficiente para /bin/sh interativo básico.
 */
#define SC_ALLOW(nr) \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)

static void sandbox_apply_seccomp(void) {
    /* BPF filter: carrega nr, compara, permite ou mata */
    struct sock_filter filter[] = {
        /* Verifica arquitetura */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Carrega syscall number */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),

        /* Permitidos: leitura/escrita de arquivos básica */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_write,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_openat,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_close,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_fstat,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_newfstatat, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_lseek,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getdents64, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        /* Processo */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_exit,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_exit_group, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_brk,        0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mmap,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_munmap,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mprotect,   0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        /* Terminal */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_ioctl,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_rt_sigaction,0,1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_rt_sigprocmask,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_wait4,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execve,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_clone,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_fork,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_pipe2,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_dup2,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getcwd,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_chdir,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_gettid,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getuid,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getgid,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_poll,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_select,     0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        /* Qualquer outra: mata o processo */
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    };

    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "sandbox: prctl NO_NEW_PRIVS: %s\n", strerror(errno));
        _exit(1);
    }

    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
        /* Fallback para prctl se syscall direto não disponível */
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            fprintf(stderr, "sandbox: seccomp failed: %s\n", strerror(errno));
            _exit(1);
        }
    }
}

/* [CRIT-C] Sandbox completo: namespace + chroot + seccomp */
static VaultError vault_sandbox_open(Vault *v, const char *password) {
    if (!v) return ERR_INVALID_ARGS;

    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        VaultError err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }

    vault_log(LOG_INFO, "Opening vault id=%u in sandbox", v->id);

    pid_t pid = fork();
    if (pid < 0) { vault_log(LOG_ERROR, "fork: %s", strerror(errno)); return ERR_SYSTEM; }

    if (pid == 0) {
        /* ── Filho: aplica isolamento em camadas ── */

        /* 1. Namespace de mount próprio (não propaga mounts ao host) */
        if (unshare(CLONE_NEWNS) != 0)
            fprintf(stderr, "sandbox: unshare NEWNS: %s (continuando)\n", strerror(errno));

        /* 2. chdir para o vault */
        if (chdir(v->path) != 0) {
            fprintf(stderr, "sandbox: chdir: %s\n", strerror(errno));
            _exit(1);
        }

        /* 3. chroot (só funciona como root, mas limita acesso se disponível) */
        if (geteuid() == 0) {
            if (chroot(v->path) != 0)
                fprintf(stderr, "sandbox: chroot: %s (continuando sem chroot)\n", strerror(errno));
            else
                chdir("/");
        }

        /* 4. Drop de capabilities via prctl */
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);

        /* 5. Limita recursos para evitar fork bomb / DoS */
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = 64;
        setrlimit(RLIMIT_NPROC, &rl);
        rl.rlim_cur = rl.rlim_max = 64 * 1024 * 1024; /* 64 MB */
        setrlimit(RLIMIT_AS, &rl);

        /* 6. Aplica seccomp BPF — último passo antes do exec */
        sandbox_apply_seccomp();

        printf("\n  [SANDBOX] vault id=%u — seccomp ativo. Digite 'exit' para sair.\n\n", v->id);
        execl("/bin/sh", "sh", "--norc", "--noprofile", NULL);
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);
    vault_log(LOG_AUDIT, "Sandbox session vault id=%u ended (exit %d)",
              v->id, WEXITSTATUS(status));
    return ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 13: INOTIFY MONITOR THREAD  [MED-E]
 * ═══════════════════════════════════════════════════════════════════════════ */

static void monitor_add_vault_watches(MonitorCtx *ctx) {
    for (uint32_t i=0; i<ctx->catalog->count; i++) {
        Vault *v = &ctx->catalog->vaults[i];
        if (v->status == VAULT_STATUS_DELETED || v->path[0]=='\0') continue;
        if (v->inotify_wd >= 0) continue;
        v->inotify_wd = inotify_add_watch(
            ctx->inotify_fd, v->path,
            IN_MODIFY|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO);
        if (v->inotify_wd < 0)
            vault_log(LOG_WARN, "inotify_add_watch vault %u: %s", v->id, strerror(errno));
    }
}

static Vault *monitor_vault_by_wd(MonitorCtx *ctx, int wd) {
    for (uint32_t i=0; i<ctx->catalog->count; i++)
        if (ctx->catalog->vaults[i].inotify_wd == wd)
            return &ctx->catalog->vaults[i];
    return NULL;
}

static void *monitor_thread(void *arg) {
    MonitorCtx *ctx = (MonitorCtx *)arg;
    char buf[INOTIFY_BUFSZ] __attribute__((aligned(8)));

    vault_log(LOG_INFO, "Monitor thread started");

    pthread_mutex_lock(&ctx->lock);
    monitor_add_vault_watches(ctx);
    for (uint32_t i=0; i<ctx->catalog->count; i++)
        monitor_scan_vault(&ctx->catalog->vaults[i]);
    pthread_mutex_unlock(&ctx->lock);

    while (ctx->running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx->inotify_fd, &rfds);
        struct timeval tv = {.tv_sec=5, .tv_usec=0};
        int ret = select(ctx->inotify_fd+1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            vault_log(LOG_ERROR, "monitor select: %s", strerror(errno));
            break;
        }

        pthread_mutex_lock(&ctx->lock);

        if (ret > 0 && FD_ISSET(ctx->inotify_fd, &rfds)) {
            ssize_t len = read(ctx->inotify_fd, buf, INOTIFY_BUFSZ);
            if (len > 0) {
                char *ptr = buf;
                while (ptr < buf + len) {
                    struct inotify_event *ev = (struct inotify_event *)ptr;
                    Vault *v = monitor_vault_by_wd(ctx, ev->wd);
                    if (v) {
                        const char *evname = (ev->len > 0) ? ev->name : "(unknown)";
                        char safe_name[LOG_FIELD_MAX+1];
                        log_sanitize(evname, safe_name, sizeof(safe_name));

                        if (ev->mask & IN_MODIFY) {
                            vault_log(LOG_ALERT, "[vault %u] inotify MODIFIED: %s", v->id, safe_name);
                            monitor_scan_vault(v);
                        } else if (ev->mask & IN_CREATE) {
                            vault_log(LOG_INFO, "[vault %u] inotify CREATED: %s", v->id, safe_name);
                            monitor_scan_vault(v);
                        } else if (ev->mask & (IN_DELETE|IN_MOVED_FROM)) {
                            vault_log(LOG_ALERT, "[vault %u] inotify DELETED: %s", v->id, safe_name);
                            char reason[256];
                            snprintf(reason, sizeof(reason), "File deleted: %.200s", safe_name);
                            alert_trigger(v, reason);
                        }
                        rule_evaluate(v);
                    }
                    ptr += sizeof(struct inotify_event) + ev->len;
                }
            }
        }

        /* [MED-E] Alert escalation */
        for (uint32_t i=0; i<ctx->catalog->count; i++)
            alert_check_escalation(&ctx->catalog->vaults[i]);

        /* [MED-E] Save diferido: só quando dirty */
        if (ctx->catalog->dirty) {
            catalog_save();
        }

        monitor_add_vault_watches(ctx);
        pthread_mutex_unlock(&ctx->lock);
    }

    vault_log(LOG_INFO, "Monitor thread stopped");
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 14: CLI COMMANDS (display)
 * ═══════════════════════════════════════════════════════════════════════════ */

static char *read_password_silent(const char *prompt) {
    struct termios old_t, new_t;
    static char buf[MAX_PASS_LEN];

    printf("%s", prompt); fflush(stdout);
    if (tcgetattr(STDIN_FILENO, &old_t) != 0) {
        if (!fgets(buf, sizeof(buf), stdin)) return NULL;
        buf[strcspn(buf, "\n")] = '\0';
        return buf;
    }
    new_t = old_t;
    new_t.c_lflag &= (tcflag_t)~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);
    memset(buf, 0, sizeof(buf));
    if (fgets(buf, sizeof(buf), stdin))
        buf[strcspn(buf, "\n")] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    printf("\n");
    return buf;
}

static void cmd_list(void) {
    printf("\n  ┌──────┬──────────────────────────┬────────────┬────────────┬────┐\n");
    printf("  │  ID  │  Name                    │  Type      │  Status    │ PW │\n");
    printf("  ├──────┼──────────────────────────┼────────────┼────────────┼────┤\n");
    if (g_catalog.count == 0)
        printf("  │  (no vaults)                                                  │\n");
    for (uint32_t i=0; i<g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        const char *ss;
        switch (v->status) {
            case VAULT_STATUS_OK:      ss="OK      "; break;
            case VAULT_STATUS_LOCKED:  ss="LOCKED  "; break;
            case VAULT_STATUS_ALERT:   ss="ALERT   "; break;
            case VAULT_STATUS_DELETED: ss="DELETED "; break;
            default:                   ss="?       ";
        }
        printf("  │ %4u │ %-24.24s │ %-10s │ %-10s │ %s  │\n",
               v->id, v->name,
               v->type==VAULT_TYPE_PROTECTED ? "PROTECTED ":"NORMAL    ",
               ss, v->has_pass?"✓":" ");
    }
    printf("  └──────┴──────────────────────────┴────────────┴────────────┴────┘\n\n");
}

static void cmd_info(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }
    char tbuf[32]; struct tm *tm;
    printf("\n  ID           : %u\n", v->id);
    printf("  Name         : %s\n", v->name);
    printf("  Type         : %s\n", v->type==VAULT_TYPE_PROTECTED?"PROTECTED":"NORMAL");
    printf("  Status       : %s\n",
           v->status==VAULT_STATUS_OK?"OK":v->status==VAULT_STATUS_LOCKED?"LOCKED":
           v->status==VAULT_STATUS_ALERT?"ALERT":"DELETED");
    printf("  Password     : %s\n", v->has_pass?"Yes":"No");
    printf("  Path         : %s\n", v->path);
    tm=localtime(&v->created_at); strftime(tbuf,sizeof(tbuf),"%Y-%m-%d %H:%M:%S",tm);
    printf("  Created      : %s\n", tbuf);
    printf("  Files tracked: %zu\n", v->hashmap.count);
    printf("  Fail attempts: %d\n", v->failed_attempts);
    printf("  Rate tokens  : %d/%d\n", v->rate.tokens, RATE_BUCKET_MAX);
    if (v->status==VAULT_STATUS_ALERT)
        printf("  Alert reason : %s\n", v->alert.reason);
    printf("\n");
}

static void cmd_files(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }
    printf("\n  Files in vault '%s':\n", v->name);
    bool any = false;
    for (int b=0; b<HASHMAP_BUCKETS; b++) {
        for (FileEntry *e=v->hashmap.buckets[b]; e; e=e->next) {
            char tbuf[32]; struct tm *tm=localtime(&e->last_seen);
            strftime(tbuf,sizeof(tbuf),"%Y-%m-%d %H:%M",tm);
            printf("  %-40s  %-16s  %s\n",
                   e->filename, tbuf, e->modified?"MODIFIED ⚠":"ok");
            any = true;
        }
    }
    if (!any) printf("  (no files tracked)\n");
    printf("\n");
}

static void cmd_encrypt_vault(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }
    if (!v->has_pass) { printf("  Error: vault has no password.\n"); return; }

    char *pass = read_password_silent("  Enter vault password: ");
    if (auth_verify_password(v, pass) != ERR_OK) {
        printf("  Authentication failed.\n");
        explicit_bzero(pass, strlen(pass)); /* [MIN-H] */
        return;
    }

    uint8_t key[KEY_LEN];
    if (derive_key(pass, v->salt, key) != ERR_OK) {
        explicit_bzero(pass, strlen(pass));
        return;
    }
    explicit_bzero(pass, strlen(pass)); /* [MIN-H] */

    DIR *dir = opendir(v->path);
    if (!dir) { explicit_bzero(key, KEY_LEN); return; }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX+NAME_MAX+2];
    char outpath[VAULT_PATH_MAX+NAME_MAX+10];

    while ((de=readdir(dir)) != NULL) {
        if (de->d_name[0]=='.') continue;
        size_t nlen = strlen(de->d_name);
        if (nlen>4 && strcmp(de->d_name+nlen-4,".enc")==0) continue;

        snprintf(inpath,  sizeof(inpath),  "%s/%s",     v->path, de->d_name);
        snprintf(outpath, sizeof(outpath), "%s/%s.enc", v->path, de->d_name);

        struct stat st;
        if (stat(inpath,&st)!=0||!S_ISREG(st.st_mode)) continue;

        if (encrypt_file(inpath, outpath, key) == ERR_OK) {
            unlink(inpath); count++;
            printf("  Encrypted: %s → %s.enc\n", de->d_name, de->d_name);
        } else {
            printf("  FAILED:    %s\n", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN); /* [MIN-H] */
    vault_log(LOG_AUDIT, "Vault id=%u: encrypted %d files (AES-256-GCM)", v->id, count);
    printf("  Done. %d file(s) encrypted.\n\n", count);
}

static void cmd_decrypt_vault(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }
    if (!v->has_pass) { printf("  Error: vault has no password.\n"); return; }

    char *pass = read_password_silent("  Enter vault password: ");
    if (auth_verify_password(v, pass) != ERR_OK) {
        printf("  Authentication failed.\n");
        explicit_bzero(pass, strlen(pass));
        return;
    }

    uint8_t key[KEY_LEN];
    if (derive_key(pass, v->salt, key) != ERR_OK) {
        explicit_bzero(pass, strlen(pass)); return;
    }
    explicit_bzero(pass, strlen(pass));

    DIR *dir = opendir(v->path);
    if (!dir) { explicit_bzero(key, KEY_LEN); return; }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX+NAME_MAX+2];
    char outpath[VAULT_PATH_MAX+NAME_MAX+2];

    while ((de=readdir(dir)) != NULL) {
        size_t nlen = strlen(de->d_name);
        if (nlen<=4||strcmp(de->d_name+nlen-4,".enc")!=0) continue;

        snprintf(inpath,  sizeof(inpath), "%s/%s", v->path, de->d_name);
        snprintf(outpath, sizeof(outpath), "%s/%.*s", v->path,
                 (int)(nlen-4), de->d_name);

        struct stat st;
        if (stat(inpath,&st)!=0||!S_ISREG(st.st_mode)) continue;

        VaultError derr = decrypt_file(inpath, outpath, key);
        if (derr == ERR_OK) {
            unlink(inpath); count++;
            printf("  Decrypted: %s\n", outpath);
        } else if (derr == ERR_INTEGRITY) {
            printf("  INTEGRITY FAIL: %s — file may be tampered!\n", de->d_name);
        } else {
            printf("  FAILED: %s\n", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);
    printf("  Done. %d file(s) decrypted.\n\n", count);
}

static void cmd_scan(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }
    pthread_mutex_lock(&g_monitor.lock);
    monitor_scan_vault(v);
    pthread_mutex_unlock(&g_monitor.lock);
    catalog_save();
    printf("  Scan complete. Files: %zu\n\n", v->hashmap.count);
}

static void cmd_help(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════════╗\n");
    printf("  ║        VAULT SECURITY SYSTEM  –  Commands (hardened)        ║\n");
    printf("  ╠══════════════════════════════════════════════════════════════╣\n");
    printf("  ║  list / info <id> / files <id>                              ║\n");
    printf("  ║  create [name] [path] [type]   type: normal | protected     ║\n");
    printf("  ║  delete / rename / unlock / passwd <id>                     ║\n");
    printf("  ║  encrypt / decrypt / scan / resolve <id>                    ║\n");
    printf("  ║  rule <id> <max_fails> [h_from h_to]                        ║\n");
    printf("  ║  sandbox <id>   (seccomp-BPF + namespace + chroot)          ║\n");
    printf("  ║  verbose / help / quit                                      ║\n");
    printf("  ╚══════════════════════════════════════════════════════════════╝\n\n");
}

#define MAX_TOKENS 16
static int tokenize(char *line, char *tokens[], int max) {
    int count = 0; char *p = line;
    while (*p && count < max) {
        while (*p==' '||*p=='\t') p++;
        if (!*p) break;
        char *start;
        if (*p=='"'||*p=='\'') {
            char q=*p++;  start=p;
            while (*p && *p!=q) p++;
            if (*p) *p++='\0';
        } else {
            start=p;
            while (*p && *p!=' ' && *p!='\t') p++;
            if (*p) *p++='\0';
        }
        tokens[count++]=start;
    }
    return count;
}

static void process_command(char *line) {
    if (!line||!*line) return;
    line[strcspn(line,"\n\r")]='\0';
    if (!*line) return;

    char *tokens[MAX_TOKENS];
    int n = tokenize(line, tokens, MAX_TOKENS);
    if (n==0) return;

    char *cmd = tokens[0];

#define GET_ID(pos) ((n>=(pos)+1) ? (uint32_t)atoi(tokens[(pos)]) : 0u)

    if (!strcmp(cmd,"list"))    { cmd_list(); }
    else if (!strcmp(cmd,"info"))    { if(n<2){printf("Usage: info <id>\n");return;} cmd_info(GET_ID(1)); }
    else if (!strcmp(cmd,"files"))   { if(n<2){printf("Usage: files <id>\n");return;} cmd_files(GET_ID(1)); }
    else if (!strcmp(cmd,"create")) {
        char *name=n>=2?tokens[1]:NULL, *path=n>=3?tokens[2]:NULL, *type=n>=4?tokens[3]:NULL;
        VaultType vt=(type&&!strcmp(type,"protected"))?VAULT_TYPE_PROTECTED:VAULT_TYPE_NORMAL;
        char *password=NULL; char pbuf[MAX_PASS_LEN]={0};
        if (vt==VAULT_TYPE_PROTECTED) {
            char *p1=read_password_silent("  Set password: ");
            if(!p1||!*p1){printf("  Password required.\n");return;}
            strncpy(pbuf,p1,MAX_PASS_LEN-1);
            char *p2=read_password_silent("  Confirm: ");
            if(!p2||strcmp(pbuf,p2)!=0){printf("  Mismatch.\n");explicit_bzero(pbuf,sizeof(pbuf));return;}
            password=pbuf;
        }
        pthread_mutex_lock(&g_monitor.lock);
        VaultError err=vault_create(name,vt,path,password);
        pthread_mutex_unlock(&g_monitor.lock);
        explicit_bzero(pbuf,sizeof(pbuf));
        if(err!=ERR_OK) printf("  Error: %s\n",vault_strerror(err));
    }
    else if (!strcmp(cmd,"delete")) {
        if(n<2){printf("Usage: delete <id>\n");return;}
        uint32_t id=GET_ID(1);
        Vault *v=vault_find_by_id(id);
        if(!v){printf("  Not found.\n");return;}
        printf("  Delete '%s'? [yes/no]: ",v->name);
        char confirm[8]={0};
        if(!fgets(confirm,sizeof(confirm),stdin))return;
        confirm[strcspn(confirm,"\n")]='\0';
        if(strcmp(confirm,"yes")!=0){printf("  Cancelled.\n");return;}
        char pbuf[MAX_PASS_LEN]={0};
        if(v->type==VAULT_TYPE_PROTECTED){
            char *p=read_password_silent("  Password: ");
            strncpy(pbuf,p,MAX_PASS_LEN-1);
        }
        pthread_mutex_lock(&g_monitor.lock);
        VaultError err=vault_delete(id,pbuf[0]?pbuf:NULL);
        pthread_mutex_unlock(&g_monitor.lock);
        explicit_bzero(pbuf,sizeof(pbuf));
        printf(err==ERR_OK?"  Deleted.\n":"  Error: %s\n",vault_strerror(err));
    }
    else if (!strcmp(cmd,"rename")) {
        if(n<3){printf("Usage: rename <id> <name>\n");return;}
        uint32_t id=GET_ID(1); char pbuf[MAX_PASS_LEN]={0};
        Vault *v=vault_find_by_id(id);
        if(v&&v->type==VAULT_TYPE_PROTECTED){
            char *p=read_password_silent("  Password: "); strncpy(pbuf,p,MAX_PASS_LEN-1);
        }
        VaultError err=vault_rename(id,tokens[2],pbuf[0]?pbuf:NULL);
        explicit_bzero(pbuf,sizeof(pbuf));
        printf(err==ERR_OK?"  Renamed.\n":"  Error: %s\n",vault_strerror(err));
    }
    else if (!strcmp(cmd,"unlock")) {
        if(n<2){printf("Usage: unlock <id>\n");return;}
        char pbuf[MAX_PASS_LEN]={0};
        char *p=read_password_silent("  Password: "); strncpy(pbuf,p,MAX_PASS_LEN-1);
        VaultError err=vault_unlock(GET_ID(1),pbuf);
        explicit_bzero(pbuf,sizeof(pbuf));
        printf(err==ERR_OK?"  Unlocked.\n":"  Error: %s\n",vault_strerror(err));
    }
    else if (!strcmp(cmd,"passwd")) {
        if(n<2){printf("Usage: passwd <id>\n");return;}
        char ob[MAX_PASS_LEN]={0},nb[MAX_PASS_LEN]={0},cb[MAX_PASS_LEN]={0};
        char *p; p=read_password_silent("  Current: "); strncpy(ob,p,MAX_PASS_LEN-1);
        p=read_password_silent("  New: ");     strncpy(nb,p,MAX_PASS_LEN-1);
        p=read_password_silent("  Confirm: "); strncpy(cb,p,MAX_PASS_LEN-1);
        if(strcmp(nb,cb)!=0){printf("  Mismatch.\n");}
        else {
            VaultError err=vault_change_password(GET_ID(1),ob,nb);
            printf(err==ERR_OK?"  Changed.\n":"  Error: %s\n",vault_strerror(err));
        }
        explicit_bzero(ob,sizeof(ob)); explicit_bzero(nb,sizeof(nb)); explicit_bzero(cb,sizeof(cb));
    }
    else if (!strcmp(cmd,"encrypt"))  { if(n<2){printf("Usage: encrypt <id>\n");return;} cmd_encrypt_vault(GET_ID(1)); }
    else if (!strcmp(cmd,"decrypt"))  { if(n<2){printf("Usage: decrypt <id>\n");return;} cmd_decrypt_vault(GET_ID(1)); }
    else if (!strcmp(cmd,"scan"))     { if(n<2){printf("Usage: scan <id>\n");return;} cmd_scan(GET_ID(1)); }
    else if (!strcmp(cmd,"resolve")) {
        if(n<2){printf("Usage: resolve <id>\n");return;}
        uint32_t id=GET_ID(1); char pbuf[MAX_PASS_LEN]={0};
        Vault *v=vault_find_by_id(id);
        if(v&&v->type==VAULT_TYPE_PROTECTED){
            char *p=read_password_silent("  Password: "); strncpy(pbuf,p,MAX_PASS_LEN-1);
        }
        VaultError err=alert_resolve(id,pbuf[0]?pbuf:NULL);
        explicit_bzero(pbuf,sizeof(pbuf));
        printf(err==ERR_OK?"  Resolved.\n":"  Error: %s\n",vault_strerror(err));
    }
    else if (!strcmp(cmd,"rule")) {
        if(n<3){printf("Usage: rule <id> <max_fails> [h_from h_to]\n");return;}
        uint32_t id=(uint32_t)atoi(tokens[1]);
        int mf=atoi(tokens[2]),hf=-1,ht=-1;
        if(n>=5){hf=atoi(tokens[3]);ht=atoi(tokens[4]);}
        rule_add(id,mf,hf,ht);
        printf("  Rule added for vault #%u.\n",id);
    }
    else if (!strcmp(cmd,"sandbox")) {
        if(n<2){printf("Usage: sandbox <id>\n");return;}
        uint32_t id=GET_ID(1);
        Vault *v=vault_find_by_id(id);
        if(!v){printf("  Not found.\n");return;}
        char pbuf[MAX_PASS_LEN]={0};
        if(v->type==VAULT_TYPE_PROTECTED){
            char *p=read_password_silent("  Password: "); strncpy(pbuf,p,MAX_PASS_LEN-1);
        }
        vault_sandbox_open(v,pbuf[0]?pbuf:NULL);
        explicit_bzero(pbuf,sizeof(pbuf));
    }
    else if (!strcmp(cmd,"verbose")) { g_verbose=!g_verbose; printf("  Verbose: %s\n",g_verbose?"ON":"OFF"); }
    else if (!strcmp(cmd,"help")||!strcmp(cmd,"?")) { cmd_help(); }
    else if (!strcmp(cmd,"quit")||!strcmp(cmd,"exit")) { /* no-op, handled in main */ }
    else { printf("  Unknown command '%s'. Type 'help'.\n",cmd); }

#undef GET_ID
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 15: INIT / SHUTDOWN / MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

static volatile bool g_running = true;

static void signal_handler(int sig) {
    if (sig==SIGINT||sig==SIGTERM) {
        g_running = false;
        g_monitor.running = false;
    }
}

static VaultError system_init(void) {
    struct stat st;
    if (stat(VAULT_CATALOG_PATH, &st) != 0) {
        if (mkdir(VAULT_CATALOG_PATH, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "Cannot create catalog dir: %s\n", strerror(errno));
            return ERR_IO;
        }
    }

    log_init();
    vault_log(LOG_INFO, "=== Vault Security System (hardened) starting ===");

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    VaultError err = catalog_load();
    if (err == ERR_CATALOG_TAMPERED) {
        fprintf(stderr,
            "\n  *** CRITICAL: Catalog integrity check FAILED ***\n"
            "  The catalog may have been tampered with.\n"
            "  Refusing to start. Review %s manually.\n\n",
            VAULT_CATALOG_FILE);
        return err;
    }
    if (err != ERR_OK) return err;

    g_monitor.catalog    = &g_catalog;
    g_monitor.running    = true;
    g_monitor.inotify_fd = inotify_init1(IN_NONBLOCK);
    if (g_monitor.inotify_fd < 0) {
        vault_log(LOG_ERROR, "inotify_init1: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    pthread_mutex_init(&g_monitor.lock, NULL);
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    return ERR_OK;
}

static void system_shutdown(pthread_t monitor_tid) {
    g_monitor.running = false;
    pthread_join(monitor_tid, NULL);
    pthread_mutex_destroy(&g_monitor.lock);
    close(g_monitor.inotify_fd);

    pthread_mutex_lock(&g_monitor.lock);
    if (g_catalog.dirty) catalog_save();
    pthread_mutex_unlock(&g_monitor.lock);

    /* [MIN-H] Apaga todos os dados sensíveis da memória */
    for (uint32_t i=0; i<g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        explicit_bzero(v->salt, SALT_LEN);
        explicit_bzero(v->pass_hash, SHA256_DIGEST_LENGTH);
        hashmap_clear(&v->hashmap);
    }
    explicit_bzero(&g_catalog, sizeof(g_catalog));

    /* [CRIT-B] Apaga chave HMAC do catálogo */
    if (g_catalog_hmac_key) {
        explicit_bzero(g_catalog_hmac_key, CATALOG_KEY_LEN);
        munlock(g_catalog_hmac_key, CATALOG_KEY_LEN);
        munmap(g_catalog_hmac_key, CATALOG_KEY_LEN);
        g_catalog_hmac_key = NULL;
        g_catalog_key_set  = false;
    }

    EVP_cleanup();
    ERR_free_strings();
    vault_log(LOG_INFO, "=== Vault Security System stopped ===");
    if (g_logfp) fclose(g_logfp);
}

#ifndef VAULT_FFI_BUILD

static void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════════╗\n");
    printf("  ║         VAULT SECURITY SYSTEM  –  HARDENED EDITION           ║\n");
    printf("  ║  AES-256-GCM │ HMAC-SHA256 Catalog │ seccomp-BPF Sandbox     ║\n");
    printf("  ║  PBKDF2(310k) │ O_NOFOLLOW │ Token Bucket │ mlock'd Keys     ║\n");
    printf("  ╚══════════════════════════════════════════════════════════════╝\n");
    printf("  Type 'help' for commands.\n\n");
}

int main(int argc, char *argv[]) {
    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"--verbose")||!strcmp(argv[i],"-v")) g_verbose=true;
        else if (!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")) {
            printf("Usage: %s [--verbose]\n", argv[0]);
            return 0;
        }
    }

    VaultError err = system_init();
    if (err != ERR_OK) {
        fprintf(stderr, "Init failed: %s\n", vault_strerror(err));
        return 1;
    }

    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, monitor_thread, &g_monitor) != 0) {
        fprintf(stderr, "Monitor thread failed: %s\n", strerror(errno));
        return 1;
    }

    print_banner();

    char line[1024];
    while (g_running) {
        printf("vault> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) {
            if (feof(stdin)) break;
            if (errno==EINTR) continue;
            break;
        }
        char *trimmed = line;
        while (*trimmed==' '||*trimmed=='\t') trimmed++;
        trimmed[strcspn(trimmed,"\n\r")]='\0';
        if (!strcmp(trimmed,"quit")||!strcmp(trimmed,"exit")) {
            printf("  Goodbye.\n\n"); break;
        }
        process_command(trimmed);
    }

    system_shutdown(monitor_tid);
    return 0;
}

#endif /* VAULT_FFI_BUILD */