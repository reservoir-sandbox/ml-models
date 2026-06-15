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
     "$OUT_DIR"/clean_temperature

echo
echo "Done. Clean ELF samples are in $OUT_DIR"
