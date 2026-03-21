#define _GNU_SOURCE
#include "sandbox.h"
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <seccomp.h>          // libseccomp

static int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

bool try_hard_isolate(const char *app_path) {
    if (!app_path || !*app_path) {
        errno = EINVAL;
        return false;
    }

    // ───────────────────────────────────────────────
    // 0. no_new_privs (impede setuid, capabilities gain etc.)
    // ───────────────────────────────────────────────
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        return false;
    }

    // ───────────────────────────────────────────────
    // 1. User namespace → root fake com CAP_SYS_ADMIN
    // ───────────────────────────────────────────────
    if (unshare(CLONE_NEWUSER) == -1) {
        return false;
    }

    char buf[128];
    int uid = getuid();
    int gid = getgid();

    int fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0) return false;
    snprintf(buf, sizeof(buf), "0 %d 1\n", uid);
    if (write(fd, buf, strlen(buf)) == -1) { close(fd); return false; }
    close(fd);

    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0) return false;
    snprintf(buf, sizeof(buf), "0 %d 1\n", gid);
    if (write(fd, buf, strlen(buf)) == -1) { close(fd); return false; }
    close(fd);

    // ───────────────────────────────────────────────
    // 2. Todos os namespaces (incluindo NET)
    // ───────────────────────────────────────────────
    unsigned long ns_flags =
        CLONE_NEWNS     |
        CLONE_NEWIPC    |
        CLONE_NEWUTS    |
        CLONE_NEWPID    |
        CLONE_NEWCGROUP |
        CLONE_NEWNET;

    if (unshare(ns_flags) == -1) {
        return false;
    }

    // ───────────────────────────────────────────────
    // 3. Mount namespace: tudo privado
    // ───────────────────────────────────────────────
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        return false;
    }

    // ───────────────────────────────────────────────
    // 4. Cria tmpfs como novo root (RAM-only)
    // ───────────────────────────────────────────────
    const char *new_root = "/tmp/sandbox-root";  // ou use memfd + mkdirat se quiser evitar disco
    if (mkdir(new_root, 0700) != 0 && errno != EEXIST) {
        return false;
    }

    if (mount("tmpfs", new_root, "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "size=32m,mode=755") == -1) {
        return false;
    }

    // ───────────────────────────────────────────────
    // 5. Monta o app_path dentro do tmpfs (bind)
    //    → permite executar binário do host, mas isolado
    // ───────────────────────────────────────────────
    char app_mount[PATH_MAX];
    snprintf(app_mount, sizeof(app_mount), "%s/app", new_root);

    if (mkdir(app_mount, 0755) != 0 && errno != EEXIST) {
        return false;
    }

    if (mount(app_path, app_mount, NULL, MS_BIND | MS_REC, NULL) == -1) {
        return false;
    }

    // ───────────────────────────────────────────────
    // 6. pivot_root para o tmpfs
    // ───────────────────────────────────────────────
    char old_root[PATH_MAX];
    snprintf(old_root, sizeof(old_root), "%s/oldroot", new_root);

    if (mkdir(old_root, 0700) != 0 && errno != EEXIST) {
        return false;
    }

    if (chdir(new_root) == -1) {
        return false;
    }

    if (pivot_root(new_root, old_root) == -1) {
        return false;
    }

    // Desmonta o antigo root agressivamente
    if (umount2(old_root, MNT_DETACH) == -1) {
        // ignora falhas parciais — comum
    }
    rmdir(old_root);

    // ───────────────────────────────────────────────
    // 7. Monta mínimos essenciais (senão muita coisa quebra)
    // ───────────────────────────────────────────────
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) == -1) {
        // continue mesmo assim
    }

