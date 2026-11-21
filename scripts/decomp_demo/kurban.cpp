// ============================================================================
// kurban.cpp — GodTier decompiler testi için gerçek kurban program
// Bilinçli olarak "analiz edilesi" özellikler içerir:
//   struct, çok yerden çağrılan yardımcı fonksiyon, döngü, koşul,
//   aritmetik, string referansı, özyineleme (recursive)
// ============================================================================
#include <cstdio>
#include <cstring>

struct Ogrenci {
    int   numara;
    int   notlar[8];
    float ortalama;
    char  isim[24];
};

// ---- 1) Çok yerden çağrılan saf yardımcı (xref hedefi) ----
int toplama(const int* dizi, int adet) {
    int toplam = 0;
    for (int i = 0; i < adet; i++) {
        toplam += dizi[i];
    }
    return toplam;
}

// ---- 2) Struct alan erişimi + koşul ----
float ortalama_hesapla(const Ogrenci* o) {
    int toplam = toplama(o->notlar, 8);
    if (toplam == 0) {
        return 0.0f;
    }
    return (float)toplam / 8.0f;
}

// ---- 3) Özyineleme (recursive) ----
long faktoriyel(int n) {
    if (n <= 1) return 1;
    return n * faktoriyel(n - 1);
}

// ---- 4) String + çağrı zinciri + if/else ----
void rapor_yaz(const Ogrenci* o) {
    printf("Ogrenci %d: %s ort=%.2f\n", o->numara, o->isim, o->ortalama);
    long f = faktoriyel(o->numara);
    if (f > 1000) {
        printf("buyuk faktoriyel: %ld\n", f);
    } else {
        printf("kucuk faktoriyel: %ld\n", f);
    }
}

int main() {
    Ogrenci ali;
    ali.numara = 7;
    memset(ali.isim, 0, sizeof(ali.isim));
    strcpy(ali.isim, "Ali");
    for (int i = 0; i < 8; i++) {
        ali.notlar[i] = (i * 13) % 100;
    }
    ali.ortalama = ortalama_hesapla(&ali);
    rapor_yaz(&ali);
    return 0;
}
