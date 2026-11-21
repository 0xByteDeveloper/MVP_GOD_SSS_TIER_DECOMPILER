// kurban2.cpp — v3 özellik test kurbanı: switch/jump-table + sanal sınıf (vtable)
// Derleme:
//   g++ -O0 -g -o kurban2_O0 kurban2.cpp
//   g++ -O2 -s -o kurban2_O2s kurban2.cpp -fno-inline-small-functions
#include <cstdio>
#include <cstring>

// ---- vtable hedefi: sanal sınıf hiyerarşisi ----
class Sekil {
public:
    virtual double alan() const { return 0.0; }
    virtual const char* isim() const { return "Sekil"; }
    virtual ~Sekil() {}
};

class Dikdortgen : public Sekil {
    double en_, boy_;
public:
    Dikdortgen(double e, double b) : en_(e), boy_(b) {}
    double alan() const override { return en_ * boy_; }
    const char* isim() const override { return "Dikdortgen"; }
};

class Daire : public Sekil {
    double r_;
public:
    explicit Daire(double r) : r_(r) {}
    double alan() const override { return 3.14159 * r_ * r_; }
    const char* isim() const override { return "Daire"; }
};

// ---- switch / jump-table hedefi ----
static const char* mevsim_adi(int ay) {
    switch (ay) {
        case 12: case 1: case 2:  return "Kis";
        case 3: case 4: case 5:   return "Ilkbahar";
        case 6: case 7: case 8:   return "Yaz";
        case 9: case 10: case 11: return "Sonbahar";
        default: return "Bilinmiyor";
    }
}

// ---- polimorfik çağrı zinciri ----
static double toplam_alan(const Sekil* s1, const Sekil* s2) {
    return s1->alan() + s2->alan();
}

int main() {
    Dikdortgen d(3.0, 4.0);
    Daire c(1.5);

    for (int ay = 0; ay <= 13; ++ay) {
        printf("ay %d -> %s\n", ay, mevsim_adi(ay));
    }

    printf("%s alan=%.3f\n", d.isim(), d.alan());
    printf("%s alan=%.3f\n", c.isim(), c.alan());
    printf("toplam=%.3f\n", toplam_alan(&d, &c));
    return 0;
}
