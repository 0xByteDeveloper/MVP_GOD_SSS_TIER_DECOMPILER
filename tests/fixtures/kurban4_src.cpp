// kurban4.cpp — v5 kurbanı: phi-SSA + devirtualizasyon + SIMD skaler geri açma
// + süper blok birleştirme hedefleri.
// Derleme (fixture yeniden uretirken):
//   g++ -no-pie -O0 -g -o kurban4.elf kurban4_src.cpp
//   g++ -no-pie -O2 -g -mssse3 -o kurban4_o2.elf kurban4_src.cpp
#include <stdio.h>

// ---------------------------------------------------------------------------
// 1) PHI: üç yollu birleşim, değer YAZMAÇTA kalır (O2'de stack'a dökülmez)
//    return tarafında r üç yoldan gelir -> phi düğümü kanıtı
// ---------------------------------------------------------------------------
__attribute__((noinline))
int phi_ucyol(int x) {
    int r;
    if (x > 100)      r = x * 3;
    else if (x > 50)  r = x * 2;
    else              r = -x;
    return r + 7;
}

// ---------------------------------------------------------------------------
// 2) PHI (döngü katsayısı): k hem başlangıç değeri hem artış alır
// ---------------------------------------------------------------------------
__attribute__((noinline))
int phi_dongu(int n) {
    int k = 3;
    for (int i = 0; i < n; ++i) k = k + i;
    return k;
}

// ---------------------------------------------------------------------------
// 3) DEVIRTUALİZASYON — tek impl: slot'ta binary çapında TEK fonksiyon
// ---------------------------------------------------------------------------
struct Tek {
    virtual int deger() { return 42; }
};
__attribute__((noinline))
int devirt_tek(Tek* t) { return t->deger(); }

// ---------------------------------------------------------------------------
// 4) DEVIRTUALİZASYON — yerel nesne: kurucu vtable'ı [rbp-D]'ye yazar,
//    somut sınıf bellidir -> çağrı statik çözülür
// ---------------------------------------------------------------------------
struct Hayvan {
    virtual int ses() { return 1; }
};
struct Kopek : Hayvan {
    int ses() override { return 2; }
    virtual int oyun() { return 20; }
};
__attribute__((noinline))
int devirt_yerel() {
    Kopek k;
    return k.ses() + k.oyun();
}

// çok impl'li slot: dürüst kalan sanal çağrı (devirtualize EDİLMEMELİ)
__attribute__((noinline))
int sanal_kalir(Hayvan* h) { return h->ses(); }

// ---------------------------------------------------------------------------
// 5) SIMD SKALER GERİ AÇMA — vektörleştirilmiş nokta çarpımı
//    (gcc -O3 -mssse3: movups + mulps + shufps/unpckhps yatay indirme zinciri)
// ---------------------------------------------------------------------------
__attribute__((noinline))
float simd_dot(const float* a, const float* b, int n) {
    float s = 0;
    for (int i = 0; i < n; ++i) s += a[i] * b[i];
    return s;
}

// ---------------------------------------------------------------------------
// 6) SÜPER BLOK — erken dönüş zinciri: O2'de jmp-üzerinden-jmp blokları üretir
// ---------------------------------------------------------------------------
__attribute__((noinline))
int erken_donus(int x) {
    if (x < 0)   return -1;
    if (x == 0)  return 0;
    if (x > 100) return 100;
    return x;
}

// goto ile paylaşılan son blok (birleşim + trambolin üreteci)
__attribute__((noinline))
int trambolin(int a, int b) {
    if (a == 1) { a += 5; goto son; }
    if (b == 2) { a -= 3; goto son; }
    a *= 2;
son:
    return a + 1;
}

int main() {
    Tek t;
    Hayvan* h = new Kopek();
    float d[4] = { 1.5f, 2.5f, 3.5f, 4.5f };
    float e[4] = { 2.0f, 1.0f, 0.5f, 4.0f };
    printf("phi_ucyol   = %d\n", phi_ucyol(75));
    printf("phi_dongu   = %d\n", phi_dongu(5));
    printf("devirt_tek  = %d\n", devirt_tek(&t));
    printf("devirt_yerel= %d\n", devirt_yerel());
    printf("sanal_kalir = %d\n", sanal_kalir(h));
    printf("simd_dot    = %.2f\n", simd_dot(d, e, 4));
    printf("erken       = %d\n", erken_donus(42));
    printf("trambolin   = %d\n", trambolin(1, 9));
    delete h;
    return 0;
}
