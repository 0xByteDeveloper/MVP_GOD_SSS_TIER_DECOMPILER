// kurban3.cpp — v4 yapilastirma + derin kesif + obfuscation kurbanı
// Derleme (fixture yeniden uretirken):
//   g++ -no-pie -O0 -o kurban3.elf kurban3_src.cpp
//   g++ -no-pie -O0 -s -o kurban3s.elf kurban3_src.cpp   (strip — deepscan hedefi)
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// 1) OPAQUE PREDICATE — inline asm ile derleyicinin silemeyecegi ölü kod
//    (xor r12d,r12d; test r12d,r12d -> kosul daima DOGRU, junk erisilmez)
// ---------------------------------------------------------------------------
__attribute__((noinline))
int opak_toplam(const int* d, int n) {
    int s = 0;
    asm volatile(
        "xor  %%r12d, %%r12d\n\t"
        "test %%r12d, %%r12d\n\t"
        "jz   1f\n\t"
        ".byte 0xE8, 0x11, 0x22, 0x33, 0x44\n\t"   // 5 bayt olum kod (junk)
        "1:\n\t"
        :
        :
        : "r12"
    );
    for (int i = 0; i < n; ++i) s += d[i];
    return s;
}

// ---------------------------------------------------------------------------
// 2) do-while dongusu
// ---------------------------------------------------------------------------
__attribute__((noinline))
int kac_defa(int n) {
    int k = 0, t = 0;
    do { t += k * k; ++k; } while (k < n);
    return t;
}

// ---------------------------------------------------------------------------
// 3) break / continue / kisa devre || / kisa devre && / ternary
// ---------------------------------------------------------------------------
__attribute__((noinline))
int karma_toplam(const int* d, int n) {
    int s = 0;
    for (int i = 0; i < n; ++i) {
        if (d[i] < 0 || i == 7) continue;              // || + continue
        if (d[i] > 100 && d[i] < 200) { s += 1000; break; }   // && + break
        s += (d[i] > 50) ? d[i] * 2 : d[i] + 1;        // ternary
    }
    return s;
}

// ---------------------------------------------------------------------------
// 4) FONKSIYON ISARETCISI TABLOSU — strip sonrasi yalniz veri referansi
//    (deepscan "veri-referansi" stratejisinin kurbanı)
// ---------------------------------------------------------------------------
__attribute__((noinline)) int islem_ekle(int a, int b)  { return a + b; }
__attribute__((noinline)) int islem_cikar(int a, int b) { return a - b; }
__attribute__((noinline)) int islem_carp(int a, int b)  { return a * b; }

typedef int (*IslemFn)(int, int);
IslemFn islem_tablosu[3] = { islem_ekle, islem_cikar, islem_carp };

__attribute__((noinline))
int uygula(int i, int a, int b) { return islem_tablosu[i](a, b); }

// ---------------------------------------------------------------------------
// 5) HIC CAGRILMAYAN fonksiyon — strip sonrasi yalniz prolog taramasi bulur
//    (deepscan "prolog" stratejisinin kurbanı — Ghidra aggressive finder dengi)
// ---------------------------------------------------------------------------
__attribute__((noinline, used))
static int gizli_sifrele(int v) {
    int k = 0x5A;
    int r = v ^ k;
    r = (r << 3) | (r >> 29);
    return r + 7;
}

int main() {
    int dizi[10] = { 3, -1, 9, 42, 77, 130, 5, 8, 210, 64 };
    printf("opak_toplam = %d\n", opak_toplam(dizi, 10));
    printf("kac_defa    = %d\n", kac_defa(5));
    printf("karma       = %d\n", karma_toplam(dizi, 10));
    printf("uygula      = %d %d %d\n", uygula(0, 10, 3), uygula(1, 10, 3), uygula(2, 10, 3));
    // gizli_sifrele BURADA KASITLI OLARAK ÇAĞRILMAZ: strip sonrası yalnız
    // prolog taraması (aggressive instruction finder muadili) bulabilir
    return 0;
}
