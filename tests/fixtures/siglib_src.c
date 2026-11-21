// siglib_src.c — imza motoru (sig export/import) fixture'ı
// Ayni kaynak iki kez derlenir:
//   g++ -no-pie -O0 -o siglib_sym.elf siglib_src.c      (sembollü → sig export)
//   g++ -no-pie -O0 -s -o siglib_strip.elf siglib_src.c (strip → sig import)
#include <stdio.h>

static int ortak_topla(int a, int b) { return a + b + 17; }

static int ortak_max3(int a, int b, int c) {
    int m = a;
    if (b > m) m = b;
    if (c > m) m = c;
    return m;
}

static int ortak_parite(int v) {
    int p = 0;
    while (v) { p ^= 1; v >>= 1; }
    return p;
}

int main() {
    printf("%d %d %d\n", ortak_topla(3, 4), ortak_max3(1, 9, 4), ortak_parite(0x3f));
    return 0;
}
