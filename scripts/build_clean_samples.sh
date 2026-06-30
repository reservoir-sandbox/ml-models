#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="samples/clean"
CC="${CC:-gcc}"
CFLAGS=(
  -D_GNU_SOURCE
  -std=c11
  -Wall
  -Wextra
  -O0
  -fno-inline
  -fno-builtin
)
KEEP_C_SOURCES="${KEEP_C_SOURCES:-0}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script is intended to build Linux ELF samples. Please run it on Ubuntu Linux or Docker." >&2
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

cat > "$OUT_DIR/clean_hello.c" <<'EOF_C'
#include <stdio.h>

int main(void) {
    puts("Reservoir clean sample: hello");
    puts("This program only prints a benign message.");
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_math.c" <<'EOF_C'
#include <stdio.h>

int main(void) {
    int values[] = {3, 7, 11, 18, 29, 42};
    int total = 0;
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        total += values[i];
    }
    printf("Reservoir clean sample: total=%d average=%.2f\n",
           total, total / 6.0);
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_string_counter.c" <<'EOF_C'
#include <ctype.h>
#include <stdio.h>

int main(void) {
    const char *text = "Reservoir clean sample with ordinary words";
    int letters = 0;
    int spaces = 0;
    for (const char *p = text; *p; ++p) {
        letters += isalpha((unsigned char)*p) ? 1 : 0;
        spaces += (*p == ' ') ? 1 : 0;
    }
    printf("letters=%d spaces=%d\n", letters, spaces);
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_sort_numbers.c" <<'EOF_C'
#include <stdio.h>

static void swap_int(int *a, int *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int main(void) {
    int values[] = {8, 5, 3, 9, 1, 4};
    size_t count = sizeof(values) / sizeof(values[0]);
    for (size_t i = 0; i < count; ++i) {
        for (size_t j = i + 1; j < count; ++j) {
            if (values[j] < values[i]) {
                swap_int(&values[i], &values[j]);
            }
        }
    }
    for (size_t i = 0; i < count; ++i) {
        printf("%d%s", values[i], i + 1 == count ? "\n" : " ");
    }
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_fibonacci.c" <<'EOF_C'
#include <stdio.h>

int main(void) {
    unsigned long a = 0;
    unsigned long b = 1;
    for (int i = 0; i < 12; ++i) {
        printf("%lu%s", a, i == 11 ? "\n" : " ");
        unsigned long next = a + b;
        a = b;
        b = next;
    }
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_prime_checker.c" <<'EOF_C'
#include <stdio.h>

static int is_prime(int n) {
    if (n < 2) {
        return 0;
    }
    for (int d = 2; d * d <= n; ++d) {
        if (n % d == 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    int primes = 0;
    for (int n = 2; n <= 50; ++n) {
        primes += is_prime(n);
    }
    printf("prime count up to 50: %d\n", primes);
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_table.c" <<'EOF_C'
#include <stdio.h>

int main(void) {
    puts("name,score");
    puts("alpha,83");
    puts("beta,91");
    puts("gamma,77");
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_temperature.c" <<'EOF_C'
#include <stdio.h>

static double c_to_f(double celsius) {
    return celsius * 9.0 / 5.0 + 32.0;
}

int main(void) {
    for (int c = 0; c <= 30; c += 10) {
        printf("%d C = %.1f F\n", c, c_to_f((double)c));
    }
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_word_stats.c" <<'EOF_C'
#include <ctype.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *text = "static analysis can also process ordinary clean utilities";
    int words = 0;
    int in_word = 0;
    for (size_t i = 0; i < strlen(text); ++i) {
        if (isalpha((unsigned char)text[i])) {
            if (!in_word) {
                ++words;
            }
            in_word = 1;
        } else {
            in_word = 0;
        }
    }
    printf("word count: %d\n", words);
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_checksum.c" <<'EOF_C'
#include <stdint.h>
#include <stdio.h>

int main(void) {
    const unsigned char data[] = {12, 44, 91, 2, 73, 19, 8, 5};
    uint32_t checksum = 0;
    for (size_t i = 0; i < sizeof(data); ++i) {
        checksum = (checksum * 33U) ^ data[i];
    }
    printf("checksum=%u\n", checksum);
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_argument_echo.c" <<'EOF_C'
#include <stdio.h>

int main(int argc, char **argv) {
    printf("argument count: %d\n", argc);
    for (int i = 0; i < argc; ++i) {
        printf("arg[%d]=%s\n", i, argv[i]);
    }
    return 0;
}
EOF_C

cat > "$OUT_DIR/clean_state_machine.c" <<'EOF_C'
#include <stdio.h>

typedef enum {
    STATE_START,
    STATE_RUNNING,
    STATE_DONE
} state_t;

int main(void) {
    state_t state = STATE_START;
    for (int step = 0; step < 3; ++step) {
        if (state == STATE_START) {
            state = STATE_RUNNING;
        } else if (state == STATE_RUNNING) {
            state = STATE_DONE;
        }
        printf("step=%d state=%d\n", step, state);
    }
    return 0;
}
EOF_C

build_one() {
  local name="$1"
  echo "Building $OUT_DIR/$name"
  "$CC" "${CFLAGS[@]}" "$OUT_DIR/$name.c" -o "$OUT_DIR/$name"
}

build_one clean_hello
build_one clean_math
build_one clean_string_counter
build_one clean_sort_numbers
build_one clean_fibonacci
build_one clean_prime_checker
build_one clean_table
build_one clean_temperature
build_one clean_word_stats
build_one clean_checksum
build_one clean_argument_echo
build_one clean_state_machine

if [[ "$KEEP_C_SOURCES" != "1" ]]; then
  rm -f "$OUT_DIR"/*.c
fi

echo
echo "Verifying compiled clean samples:"
file "$OUT_DIR"/clean_hello \
     "$OUT_DIR"/clean_math \
     "$OUT_DIR"/clean_string_counter \
     "$OUT_DIR"/clean_sort_numbers \
     "$OUT_DIR"/clean_fibonacci \
     "$OUT_DIR"/clean_prime_checker \
     "$OUT_DIR"/clean_table \
     "$OUT_DIR"/clean_temperature \
     "$OUT_DIR"/clean_word_stats \
     "$OUT_DIR"/clean_checksum \
     "$OUT_DIR"/clean_argument_echo \
     "$OUT_DIR"/clean_state_machine

echo
echo "Done. Clean ELF samples are in $OUT_DIR"
