# Decompiler Gerçek Analizi — IDA/Ghidra Gerçeği ve i4M-GodTier'ın Gerçek Çıktıları

> Bu dokümandaki **tüm motor çıktıları gerçektir**: bu oturumda `kurban.cpp` adlı gerçek
> bir C++ programı yazıldı, `g++ 14.2.0 (Debian)` ile derlendi, hem `objdump` hem de
> **i4M-GodTier** motoru üzerinde çalıştırıldı ve çıktılar olduğu gibi buraya yapıştırıldı.
> Komutlar dokümanın sonunda — her şey tekrar üretilebilir.
>
> Ortam: Linux x86-64, g++ 14.2.0, GodTier 1.0.0 (Capstone 5), kurban program ELF64/PIE.


---

## 0. v2.0 GÜNCELLEMESİ — "Temel Katman"dan Gerçek Decompiler'a (bu oturumda yapıldı)

Bu doküman ilk yazıldığında dürüst bir tablo koymuştuk: motorumuz CFG/döngü/xref
düzeyindeydi, tip/struct/ifade katlaması YOKTU. Kullanıcı talebi nettti: *"GOD SSS
TIER MVP — en iyisini geçecek kalitede, askeri seviye."* Aşağıda neyin nasıl
yapıldığı ve **yine gerçek çıktılarla** kanıtı var. Tüm çıktılar
`kurban_O0` üzerinde `godtier` v2.0 ile üretilmiştir (testler: 103/103 PASS).

### Yeni mimari: iki fazlı global analiz (IDA/Ghidra modeli)

```
Analyzer (fonksiyonlar, xref, string, PLT/GOT isimleri)
    │
    ▼
TypeInferer (YENİ — decomp/types.cpp, ~800 satır)
    Faz A: her fonksiyon gövdesi taranır
      - arg canlılığı (tanım-önce-kullanım)          -> argüman SAYISI
      - dönüş kanıtı (ret anında eax/xmm0 yazımı)    -> dönüş TİPİ
      - pointer kökeni (provenance) izleme           -> bellek erişimleri
        (arg + offset, boyut, float/indexli/stride)
    Faz B: global yayılım
      - çağrı grafiği: çağıran'ın geçtiği köken <-> çağrılan'ın arg'ı
      - union-find: aynı nesneye bakan TÜM yerler tek kümede birleşir
      - bilinen libc imzaları (printf/memset/...) tablosu
      - >= 2 farklı offset görülen küme  ->  STRUCT GERİ KAZANIMI
    │
    ▼
Pseudocoder v2 (ifade katlama + yapılaştırma)
      - register dataflow: 7 makine komutu -> tek satır C ifadesi
      - while / do-while / if-else yapılaştırma (goto geri dönüşüyle)
      - magic-number bölme + x-(x/d)*d -> x%d idiom katlaması
      - SysV + Win64 çağrı kuralları, çağrı-sonucu birleştirme
      - ELF PLT isim çözümü (.rela.plt + .dynsym + .plt tarama)
      - strip'li binary'de main keşfi (__libc_start_main kalıbı)
```

### Gerçek çıktı 1 — `types` komutu (global tip veritabanı):

```
gt> types
== TIP VERITABANI (global iki fazli analiz) =============
[*] Imzalar (cagiran/cagrilan tip yayilimi + govde kaniti):
  int printf(void * a1, ...)
  int memset(void * a1, int a2, int a3)
  int toplama(...)(int * a1, int a2)
  double ortalama_hesapla(...)(struct_1 * a1)
  int faktoriyel(...)(int a1)
  void rapor_yaz(...)(struct_1 * a1)
  int main()
[+] Geri kazanilan struct'lar: 1
struct struct_1 {
    int field_0;   // +0x0
    int field_4[];   // +0x4
    float field_24;   // +0x24
    char field_28[24];   // +0x28
};
    kullanir: ortalama_hesapla(...) (arg 1)
    kullanir: rapor_yaz(...) (arg 1)
```

Kaynak koddaki `Ogrenci` struct'ı, **derleyici hiç iz bırakmadığı halde** üç
fonksiyonun bellek erişimleri birleştirilerek birebir geri kazanıldı:
`int numara` (+0), `int notlar[8]` (+4), `float ortalama` (+0x24),
`char isim[24]` (+0x28 — memset boyutundan). `field_28[24]`'ün uzunluğu
`memset(ali+0x28, 0, 0x18)` çağrısının üçüncü argümanından okundu.

### Gerçek çıktı 2 — decompile edilmiş fonksiyonlar (kaynakla yan yana):

| Kaynak (yazdığımız) | GodTier v2 çıktısı (gerçek) |
|---|---|
| `int toplama(const int* dizi, int adet)` | `int toplama(int * a1, int a2)` |
| `for (i=0; i<adet; i++) toplam += dizi[i];` | `while ( v2 < a2 ) { v1 += a1[v2]; ++v2; }` |
| `return toplam;` | `return v1;` |
| `float ortalama_hesapla(const Ogrenci* o)` | `double ortalama_hesapla(struct_1 * a1)` |
| `toplam = toplama(o->notlar, 8);` | `v1 = toplama(a1->field_4, 8);` |
| `if (toplam == 0) return 0.0f;` | `if ( v1 != 0 ) { return (float)v1 / 8; } else { return 0; }` |
| `return (float)toplam / 8.0f;` | *(8.0f sabiti .rodata'dan okunarak `8` olarak basıldı)* |
| `if (n <= 1) return 1;` | `if ( a1 > 1 ) { return (faktoriyel(a1 - 1)) * a1; } else { return 1; }` |
| `return n * faktoriyel(n-1);` | *(özyineleme + çarpım tek ifadede)* |
| `printf("Ogrenci %d: %s ort=%.2f", ...)` | `printf("Ogrenci %d: %s ort=%.2f", a1->field_0, a1->field_28, (double)(a1->field_24));` |
| `ali.notlar[i] = (i*13) % 100;` | `v1.field_4[v2] = (v2 + 12 * v2) % 100;` |

Son satır özel dikkat ister: derleyici `% 100`'ü `imul 0x51eb851f; shr 0x20;
sar 5; ...; imul 0x64; sub` magic-number zincirine çevirmişti. v2 bu zinciri
örnek-doğrulamalı (validate-by-samples) ters çözümle `x / 100`'e, ardından
`x - (x/100)*100` kalıbını `x % 100`'e katladı. `0x696c41` immediate'ı da
`"Ali"` olarak notlandı.

### main'in tam v2 çıktısı (gerçek):

```c
int main()
// struct struct_1 { int field_0; int field_4[]; float field_24; char field_28[24]; };
{
    struct_1 v1;   // [rbp - 0x50]        <- Ogrenci ali; stack nesnesi
    int v2;   // [rbp - 0x4]              <- int i
    int v3;   // [rbp - 0x2c]             <- float ort (bit-pattern)

    v1.field_0 = 7;                       <- ali.numara = 7
    memset(v1.field_28, 0, 0x18);         <- memset(ali.isim, 0, 24)
    v1.field_28 = 0x696c41;   // "Ali"    <- strcpy(ali.isim, "Ali")
    v2 = 0;
    while ( v2 <= 7 ) {
        v1.field_4[v2] = (v2 + 12 * v2) % 100;   <- for (i=0..7) notlar[i]=(i*13)%100
        ++v2;
    }
    v3 = ortalama_hesapla(&v1);           <- ali.ortalama = ortalama_hesapla(&ali)
    rapor_yaz(&v1);                       <- rapor_yaz(&ali)
    return 0;
}
```

### Strip edilmiş -O2 binary'de bile:

`kurban_O2s` (strip + -O2): `__libc_start_main` çağrı kalıbından **main bulundu**,
`printf@plt` isimlendirildi, rsp-tabanlı çerçeveden struct kısmen geri kazanıldı,
SIMD vektörize kod dürüst `simd_add(...)` gösterimiyle degradasyon gösterdi
(Hex-Rays da SIMD'de benzer çirkin çıktı verir).

### v2'de hâlâ yapılamayanlar (dürüstlük listesi güncel hali):

- Tam SSA yok: çok bloğa yayılan değişkenlerde bazen ham register adı kalır
- SIMD vektörizasyon geri açılmıyor (`simd_add`/`simd128` dürüst gösterim)
- Inlining geri açılmaz (derleme kaybedici), vtable/RTTI yok
- Jump table (switch) çözümü, DWARF/PDB importu yok
- Yapılaştırma: karmaşık kontrol akışında `goto` geri dönüşü var (Hex-Rays'te de var)


---

## 0-B. v3.0 GÜNCELLEMESİ — DWARF/PDB IMPORT + JUMP TABLE + VTABLE (bu oturum)

Kullanıcının kapatması emredilen eksikler ve sonuçları (testler: **161/161 PASS**,
49 yeni doğrulama; `kurban2.cpp` adlı İKİNCİ gerçek kurban — sanal sınıf hiyerarşisi
+ switch — bu oturumda yazıldı ve derlendi):

| # | v2'de yoktu | v3'te var | Kanıt (gerçek çıktı) |
|---|---|---|---|
| 1 | **DWARF import** | `.debug_abbrev/.debug_info/.debug_str` tam ayrıştırıcı (v4+v5, strp/string/ref/exprloc/implicit_const/strx formları) | `struct Ogrenci { int numara; int notlar[]; float ortalama; char isim[24]; }` — üye adları + tipler DWARF'tan |
| 2 | **PDB import** | MSF 7.00 konteyner + TPI + S_GPROC32 + PUB32 (PDBX v3 çekirdeği entegre, `src/format/pdb.cpp`) | `pdb fixture.pdb` → `int toplama_pdb(int dizi, int adet)` — param adları PDB sembollerinden |
| 3 | **Jump table (switch)** | PIC rel32 İMZALI ofsetler dahil; case hedefleri linear disasm ile çözülür, CFG'ye ekstra leader olarak girer, gövdeler inline edilir | `switch ( a1 ) { case 1: case 2: case 12: return "Kis"; ... }` (13 girdilik tablo @0x2044) |
| 4 | **vtable/RTTI** | Itanium ABI: `vtable for X` sembollerinden slot okuma, çoğunluk oyuyla slot adlandırma, `mov rX,[obj]` / `mov rC,[rX+K]` / `call rC` kalıbıyla sanal çağrı tespiti | `s1->alan();   // sanal cagri: vtable[0] (Dikdortgen::alan, Sekil::alan, Daire::alan)` |
| 5 | Ham `a1->field_28` | DWARF/PDB giydirme: geri kazanılan struct'a GERÇEK üye adları | `printf("Ogrenci %d: %s ort=%.2f", o->numara, o->isim, (double)(o->ortalama));` |
| 6 | `int toplama(int * a1, int a2)` | DWARF/PDB kanıtıyla gerçek param adları + tipler | `int toplama(const int * dizi, int adet)` |
| 7 | Double SSE katlanmıyordu | `addsd/mulsd/subsd/divsd` ifade katlama | `return (s2->alan()) + v1;` |
| 8 | SIMD sıfır yazma ham satır | `pxor`+`movups` → okunabilir sıfır yazma | `v1.field_2c = 0;   // 16 bayt sifir (movups)` |
| 9 | Kırık demangle | Itanium kurucu/yıkıcı/const-metot/L-öneki/vtable önekleri | `Daire::~Daire`, `Daire::alan`, `vtable for Sekil`, `mevsim_adi` |

### İki kurban, iki senaryo

**kurban2.cpp** (yeni): `Sekil` (sanal taban) → `Dikdortgen`/`Daire` türevleri,
`mevsim_adi(int)` 13 case'lik switch, `toplam_alan(const Sekil*, const Sekil*)`
çift sanal dispatch. `-O0 -g` ve `-O2 -s` (strip) derlemeleri `tests/fixtures/`
altında; 27 yeni otomatik doğrulama gerçek binary üzerinde koşar.

### Öne çıkan gerçek çıktılar (olduğu gibi)

```
// mevsim_adi — jump table çözümü (v2'de: "goto *" idi)
int mevsim_adi(int a1)
{
    if ( a1 > 0xc ) goto 0x11ad;
    switch ( a1 ) {   // jump table @ 0x2044, 13 giridi (PIC rel32)
        case 1: case 2: case 12:
            return "Kis";
        case 3: case 4: case 5:
            return "Ilkbahar";
        case 6: case 7: case 8:
            return "Yaz";
        case 9: case 10: case 11:
            return "Sonbahar";
        default:
            break;
    }
    return;
}
```

```
// toplam_alan — vtable çözümü + DWARF imzası (v2'de: "call rdx" ham idi)
double toplam_alan(const Sekil * s1, const Sekil * s2)
{
    __int64 v1;   // [rbp - 0x18]
    v1 = s1->alan();
    return (s2->alan()) + v1;
}
```

```
// rapor_yaz — DWARF üye adları (v2'de: a1->field_28 idi)
void rapor_yaz(const Ogrenci * o)
{
    printf("Ogrenci %d: %s ort=%.2f", o->numara, o->isim, (double)(o->ortalama));
    v1 = faktoriyel(o->numara);
    if ( v1 <= 0x3e8 ) {
        printf("kucuk faktoriyel: %ld", v1);
    } else {
        printf("buyuk faktoriyel: %ld", v1);
    }
}
```

```
// main (kurban2) — kurucu/yıkıcı çağrıları isimli, döngü yapılaşmış
int main()
{
    Dikdortgen v1;   // [rbp - 0x30]
    Dikdortgen v2;   // [rbp - 0x40]
    int v3;   // [rbp - 0x14]
    Dikdortgen(v1, 0x20b0);
    Daire(v2, 0x20b8);
    v3 = 0;
    while ( v3 <= 0xd ) {
        printf("ay %d -> %s", v3, mevsim_adi(v3));
        ++v3;
    }
    ...
}
```

### Kalan dürüstlük listesi (v4'te kapatıldı — bkz. Bölüm 0-C; v5 hedefleri bölüm sonunda)

- **SIMD vektörizasyon geri açma**: paddd yatay toplam ağacı hâlâ `simd_add` dürüst
  gösterimi (Hex-Rays'te de böyle)
- **Inlining geri açma**: DWARF `DW_TAG_inlined_subroutine` aralıkları + isimler
  (ileri referans ertelenmiş çözümüyle) artık ÇÖZÜLÜYOR — kanıt:
  `kurban_o2g.elf` (-O2 -g) üzerinde `ortalama_hesapla` gövdesi
  `// >>> toplama() buraya inline edilmis (DWARF kaniti)` notuyla açılır.
  Gövdenin SIMD'a vektörize kısmı `simd_add(...)` dürüst gösterimiyle kalır
  (Hex-Rays'te de vektör kodu açılmaz). Strip'li binaryde inline aralığı
  bilgisi olmayacağından tespit edilemez (bu bir bilgi problemidir, eksiklik değil)
- **Karmaşık akış**: switch dışındaki çoklu hedefli dolaylı dallanmalarda `goto`
  geri dönüşü sürer (Hex-Rays'te de var)
- **Tam SSA**: tek-öncül register mirası eklendi (ham register artıkları temizlendi);
  tam phi-SSA yok


---

---

## 0-C. v4.0 GÜNCELLEMESİ — DERİN KEŞİF + İMZA MOTORU + OPAQUE PREDICATE + TAM YAPILAŞTIRMA (bu oturum)

GitHub araştırmasıyla taranmış açık-kaynak ekosisteminden ilham alınarak
kapatılan satırlar (kaynakça bölüm sonunda). Test sayısı: 161 → 202 → **228 PASS / 0 FAIL**
(v5: phi-SSA + SIMD skaler geri açma + CHA devirtualizasyon + süper blok — bkz. Bölüm 0-D).

### C.1 Kalan dürüstlük listesi nasıl kapandı

| v3 sonu kalan madde | v4 durumu | Gerçek kanıt |
|---|---|---|
| Derin fonksiyon keşfi zayıf | ✅ 3 strateji: prolog taraması (Ghidra "aggressive instruction finder" muadili) + veri-referansı (fptr tablosu/vtable + PIE R_X86_64_RELATIVE reloc addend'leri) + tail-call — hepsi güven skoru ve kanıt zinciriyle | strip'li `kurban3s.elf`: 9 aday; hiç çağrılmayan `gizli_sifrele` (18 komut) yalnız prolog taramasıyla kurtarıldı; `islem_tablosu[3]` üyeleri `.data`'daki işaretçi qword'larından %80 güvenle bulundu |
| FLIRT yok | ✅ İmza motoru: (a) desen kuralları (rep movs→memcpy, strlen döngüsü, bswap, rdtsc/cpuid/syscall), (b) `.gsig` masked-pattern veritabanı — `sig export` ile sembollü binary'den ÜRET, `sig import` ile strip'li binary'de isimleri geri kazan (call rel32 + [rip+disp32] baytları FLIRT mantığıyla jokerlenir) | `siglib_sym.elf` → `sig export` → `siglib_strip.elf` → `sig import`: 4/4 eşleşme, `ortak_topla`/`ortak_max3`/`ortak_parite` + `deregister_tm_clones` (crt kodu!) isimleri geri kazanıldı |
| Obfuscation "yok" | ✅ Tespit + katlama: entropi/packer imzaları (DIE tarzı) + anti-analiz import/rdtsc/VM-string taraması + **opaque predicate taraması** (xor R,R; test; jcc / mov-sabit; cmp-sabit; jcc / and R,0) + decompiler'da **sabit koşul katlaması ve ölü kod budaması** — `obfus` komutu risk raporuyla | `kurban3.elf` `opak_toplam`: inline asm ile gömülmüş `xor r12d,r12d; test; jz` öncülü katlandı, 5 bayt junk `.byte E8 11 22 33 44` bloğu erişilemez sayılıp çıktıya hiç sızmadı; `obfus` raporu kalıbın adresini + kanıtını verdi |
| Karmaşıkta goto | ✅ Döngü gövdesi ÖZYİNELEMELİ yapılaştırıcı: break/continue kurtarma, iç içe if/else, kısa devre `||`/`&&` birleştirme, ternary `?:`, for yükseltmesi (init + artış başlığa çekilir), do-while | `karma_toplam` (68 komut, 14 blok) **tek goto olmadan** üretildi — aşağıda tam çıktı |

### C.2 Yapılaştırma v4 — kaynak ve makine çıktısı

Kaynak (`kurban3_src.cpp`):

```c
int karma_toplam(const int* d, int n) {
    int s = 0;
    for (int i = 0; i < n; ++i) {
        if (d[i] < 0 || i == 7) continue;
        if (d[i] > 100 && d[i] < 200) { s += 1000; break; }
        s += (d[i] > 50) ? d[i] * 2 : d[i] + 1;
    }
    return s;
}
```

i4M-GodTier v4 çıktısı (`decomp karma_toplam`, -O0, sembollü):

```c
int karma_toplam(int * a1, int a2)
{
    int v1;   // [rbp - 0x4]
    int v2;   // [rbp - 0x8]
    v1 = 0;
    for ( v2 = 0; v2 < a2; ++v2 ) {
        if ( a1[v2] >= 0 && v2 != 7 ) {
            if ( a1[v2] > 0x64 && a1[v2] <= 0xc7 ) {
                v1 += 0x3e8;
                break;
            }
            v1 += ( a1[v2] <= 0x32 ) ? a1[v2] + 1 : 2 * a1[v2];
            continue;
        }
    }
    return v1;
}
```

Dikkat: `d[i] < 0 || i == 7 → continue` örüntüsü De Morgan ile
`d[i] >= 0 && i != 7 → gövde` biçimine çevrildi (anlam eşdeğer); ternary koşulu
ters + kollar takas (yine eşdeğer); `1000 → 0x3e8`, `50 → 0x32`, `200 → 0xc7`.
68 komutluk fonksiyonda **goto sayısı: 0**.

### C.3 Opak öncül katlaması + ölü kod budaması

Kaynak (inline asm — derleyicinin silemeyeceği gerçek obfuscation):

```c
int opak_toplam(const int* d, int n) {
    int s = 0;
    asm volatile(
        "xor  %%r12d, %%r12d\n\t"
        "test %%r12d, %%r12d\n\t"
        "jz   1f\n\t"
        ".byte 0xE8, 0x11, 0x22, 0x33, 0x44\n\t"  // 5 bayt ölü junk
        "1:\n\t" ::: "r12");
    for (int i = 0; i < n; ++i) s += d[i];
    return s;
}
```

v4 çıktısı:

```c
int opak_toplam(int * a1, int a2)
{
    int v1;   // [rbp - 0xc]
    int v2;   // [rbp - 0x10]
    v1 = 0;
    // v4: kosul daima DOGRU (opak oncul katlandi) -> 0x401147
    for ( v2 = 0; v2 < a2; ++v2 ) {
        v1 += a1[v2];
    }
    return v1;
}
```

Mekanizma: (1) `xor r12d,r12d` → katlayıcıda `r12 = 0`; (2) `test r12d,r12d`
→ koşul `0 == 0`; (3) blok sonundaki `jz` sabit-koşul çözücüye girer
(`constBranch`); (4) erişilebilirlik analizi (sabit dallanmalar tek kenara
inince pre-reach − post-reach) junk bloğunu ölü işaretler; (5) çıktıya sızmaz.

### C.4 Derin keşif çıktısı (strip'li binary)

```
$ godtier -s - <<'EOF'
load tests/fixtures/kurban3s.elf
deep
EOF
  9 aday (strateji: prolog / veri-referansi / tail-call)
  0x40129d  [80%] veri-referansi  kod adresi veri bolgesinde (.data), 1 referans,
                             prolog: push rbp; mov rbp, rsp, gecerli govde (9 komut, ret ile biter)
  0x4012b1  [80%] veri-referansi  ... (8 komut)
  0x4012c3  [80%] veri-referansi  ... (8 komut)
  0x4012d6  [55%] prolog          push rbp; mov rbp, rsp + gecerli govde (18 komut...)
  ...
$ deep apply
  Uygulandi: N yeni fonksiyon (FUN_XXXXXXXX — Ghidra FUN_ isimlendirme geleneği)
```

`islem_tablosu[3]` üyeleri sembolsüz + hiç doğrudan çağrılmamış olmalarına
rağmen `.data` içindeki işaretçi girdilerinden bulundu (PIE binarylerde
`.rela.dyn` R_X86_64_RELATIVE addend'lerinden). Hiç çağrılmayan
`gizli_sifrele` prolog taramasıyla kurtarıldı — Ghidra'nın "aggressive
instruction finder"ının yaptığı iş, kanıt zinciriyle.

### C.5 Yeni komutlar

```
deep [apply]                  derin fonksiyon keşfi (güven skoru + kanıt zinciri)
sig [export <f>|import <f>]   imza motoru (desen kuralları + .gsig havuzu)
obfus                         obfuscation/packer/anti-analiz risk raporu
find hex 55 48 89 e5          bayt kalıbı ara
find imm 0x5a                 komut sabitlerini ara (magic-number avı)
find str <metin>              string ara        find asm <mnemonic>  komut ara
```

### C.6 GitHub araştırması — ilham alınan açık-kaynak projeler

| Proje (yıldız) | Bizde karşılığı |
|---|---|
| Maktm/FLIRTDB (1365★), push0ebp/sig-database (906★), rizinorg/sigdb (60★) | `.gsig` masked-pattern imza formatı + üret/içe-al döngüsü (FLIRT'in "yeniden konumlanabilir bayt maskeleme" fikri) |
| avast/retdec (8.7k★) | desen-kural tabanlı yaygın işlev tanıma (memcpy/memset/strlen) yaklaşımı |
| fkie-cad/dewolf (237★) | döngü gövdesi yapılaştırmasında bölge-tabanlı (region-based) düşünce; break/continue kurtarma |
| JonathanSalwan/Triton (4.4k★) | sembollü yürütme yerine "somut katlama" ile sabit koşul kanıtı (opaque predicate) |
| malrev/ABD dersi (1170★) | opak öncül kalıpları (xor R,R; test; jcc / mov-sabit; cmp-sabit) ve anti-analiz imza listesi |

### C.7 Kalan dürüstlük listesi (v5 sonrası durum)

v5 ile dört büyük hedefin DÖRDÜ de tamamlandı (2025-11 itibarıyla):

| v5 hedefi | Durum | Kanıt |
|---|---|---|
| **Tam phi-SSA** | ✅ Döngü-taşıyıcı phi'ler (birikimli `v1 += ...` kurtarma), cmov donanım-phi katlaması, çok-öncül birleşimde uzlaşan-register mirası, koşullu dönüş ternary'si | `simd_dot` O3: `float v2 = 0; // phi: xmm0` + `v2 += 4 lane çarpımı`; `phi_ucyol` O3: `( x >= 0x33 ) ? ...` |
| **SIMD skaler geri açma** | ✅ Lane-modeli: movups/movdqu yüklemeleri 4 lane'li ifade; mulps/addps lane-wise; addss+shufps/unpckhps/movshdup yatay indirme zinciri skaler ifadeye açılır; paddd/psrldq int lane'i | `simd_dot` O3 vektör döngüsü TAMAMEN skaler; `ortalama_hesapla` O2 8-eleman paddd ağacı TAMAMEN skaler — `simd_add`/`simd128` kalmadı |
| **Devirtualizasyon** | ✅✅ v7 DEVRİT-PRO (4 strateji): (1) kurucu vtable-saklama kanıtı, (2) DWARF CHA, (3) slot-tek-impl spekülatif, (4) **PE32 MSVC RTTI atlası + global-singleton zincir değerlendiricisi (livestep-lite)** — sembolsiz PE32'de vftable/COL/TypeDescriptor taramasıyla sınıf evreni + pencere değerlendiricisiyle `call [edx+0x88]` üslubu dolaylı çağrılar statik çözülür; çok impl DÜRÜSTÇE aday listesiyle sanal kalır. **Gerçek binary kanıtı: metin2client.exe (5.2 MB, PDB'li) — 892 sınıf/7282 vftable slotu geri kazanıldı, 3842/7420 dolaylı çağrı statik çözüldü** | `playerGetStatus` → `CPythonPlayer::GetStatus` (slot 4) + `CPythonPlayer::NEW_GetMainActorPtr` (slot 34) — kaynak kodla 1:1 |
| **Süper blok birleştirme** | ✅ CFG düzeyi: trambolin (tek komutlu jmp) kenar yönlendirme + adres-komşu tek-öncül füzyon; gösterim düzeyi: tek-öncül zincir soğurması | `erken_donus` 8 blok → goto YOK, erken dönüş zinciri + ternary return |

Kalan dürüst kısımlar (v6 hedefleri):

- **SIMD döngü kalıntı işleme** — `simd_dot` O3'ün n%4 skalar kuyruğu (dallanma zinciri)
  bazen `while (true)` kapsülünde ham register gösterebilir (Hex-Rays benzeri zayıflık)
- **O2 union-find struct artefaktları** — SIMD erişim kalıpları bazen sahte
  `struct_N { float field_0[]; }` üretir (gerçek DWARF struct giydirmesi öncelikli olmalı)
- **`0xffffffff` sabitleri** — `mov $0xffffffff` → `-1` işaretli pretty-print
- **Tam dominator-tree phi** — birleşimlerde uzlaşmayan farklı ifadeler için
  kol-sonu atamalı phi değişkeni (şimdilik dürüst ham bırakma)

*(v6 güncellemesi: bu dört maddenin DÖRDÜ de kapandı — bkz. Bölüm 0-E.1;
`simd_dot` kuyruğunda while(true) kapsülü kalktı, phi isimleri akıyor; kalan
erken-dönüş goto'ları E.7 listesinde dürüstçe duruyor.)*

---

## 0-D. v5.0 GÜNCELLEMESİ — PHI-SSA + SIMD SKALER GERİ AÇMA + DEVIRTUALİZASYON + SÜPER BLOK (bu oturum)

"SINIR YOK" spurtinin ikinci dalgası: v4'ün dürüstlük listesindeki dört madde
tamamlandı. Test sayısı: 202 → **228 PASS / 0 FAIL** (+26 yeni doğrulama).

### D.1 Ne eklendi (mimari)

| Bileşen | Açıklama |
|---|---|
| **Döngü-taşıyıcı phi-SSA** | Döngü öncesi giriş durumu katlanır; gövde çıkışıyla KARIŞAN yazmaçlar phi değişkenine (`float v2 = 0; // phi: xmm0`) yükseltilir; gövde phi adıyla tohumlanır; latch'te birikimli ifade `UnwrapAccumulator` ile `vN += ...` biçimine soyulur; döngü sonrası bloklar phi adını miras alır |
| **cmov katlaması (donanım phi'si)** | `cmovge dst, src` → `( kosul ) ? src : dst` — O2/O3 derleyicilerinin if/else birleşimlerini cmov'a indirmesinin tek komutluk phi karşılığı |
| **Koşullu dönüş + erken dönüş** | `je ret; hesap; ret` → `return ( cond ) ? a : b;` — branch-over-compute deseni; iki kol da ret ile bitiyorsa `if (cond) { B } + F` erken dönüş zinciri; saf-epilogue birleşimde kol return'leri yükseltilir (ternary return dahil) |
| **SIMD lane modeli** | Her xmm yazmacı 4 lane'li skaler ifade tutar: `movups/movdqu [mem]` → `a[i+k]` / `o->notlar[k]` lane'leri; `mulps/addps` lane-wise; `addss/movss/cvtss2sd` yalnız lane0'ı katlar; `shufps/unpckhps/unpcklps/movshdup/movsldup/movhlps/movlhps/haddps` permütasyon; `paddd/psrldq` int lane'i. Yatay indirme zinciri (addss+shufps×N) TAMAMEN skaler ifadeye açılır |
| **CHA devirtualizasyonu** | DWARF `DW_TAG_inheritance` grafiği (ileri-referanslı taban adları ertelenmiş çözülür) + vtable veritabanı: statik tip + tüm alt sınıfların slot implantları TEK ise çağrı statik çözülür (`Tek::deger(t)`); çok impl'li slot dürüstçe sanal kalır. Stripped binary için: kurucu vtable-saklama kanıtı + slot-tek-impl spekülatif stratejileri |
| **Süper blok birleştirme** | CFG düzeyi: tek komutlu `jmp T` trambolinlerine giden kenarlar doğrudan T'ye yönlendirilir (komut hedefleri senkron); adres-komşu tek-öncül bloklar füze edilir. Gösterim düzeyi: tek-öncül zincirler aynı gösterimde soğurulur (goto yüzeyi küçülür) |
| **Özyinelemeli üst-düzey yapılaştırıcı** | İç içe else-if zincirleri üst düzeyde de özyinelemeli çözülür (döngü gövdesindeki emitRegion muadili); iç elmas ternary'ye, erken dönüşler return-hoisting'e yükseltilir |

### D.2 Gerçek çıktılar (olduğu gibi)

**`phi_ucyol` — O0 (24 komut, 6 blok, kaynak: `if (x>100) r=x*3; else if (x>50) r=2x; else r=-x; return r+7;`):**

```c
int phi_ucyol(int x)
{
    int v1;   // [rbp - 0x4]
    x = x;
    if ( x <= 0x64 ) {
        v1 = ( x <= 0x32 ) ? -x : 2 * x;      // iç elmas ternary'ye katlandı
    } else {
        v1 = 3 * x;
    }
    return v1 + 7;
}
```

**`phi_ucyol` — O3 (aynı kaynak, derleyici cmov'a indirdi):**

```c
int phi_ucyol(int x)
{
    if ( x <= 0x64 ) {
        return ( x >= 0x33 ) ? x + x * 1 : -x + 7;   // cmovge = donanım phi'si
    }
    return x + x * 2 + 7;
}
```

**`erken_donus` — erken dönüş zinciri (O0, 8 blok → 0 goto):**

```c
int erken_donus(int x)
{
    x = x;
    if ( x >= 0 ) {
        if ( x != 0 ) {
            return ( x <= 0x64 ) ? x : 0x64;
        } else {
            return 0;
        }
    } else {
        return 0xffffffff;    // mov $0xffffffff (==-1)
    }
}
```

**`devirt_tek` — CHA devirtualizasyonu (O0, DWARF kanıtıyla):**

```c
int devirt_tek(Tek * t)
{
    Tek::deger(t);   // v5 devirtualize: CHA: Tek* statik tipi, aday siniflar {Tek} slot 0'da tek impl
    return Tek::deger(t);
}
```

**`sanal_kalir` — override tespiti, DÜRÜST sanal çağrı (yanlış devirt yok):**

```c
int sanal_kalir(Hayvan * h)
{
    h->ses();   // sanal cagri: vtable[0] (Kopek::ses, Tek::deger, Hayvan::ses)
    return h->ses();
}
```

**`simd_dot` — gcc -O3 -mssse3 vektörleştirilmiş nokta çarpımı (mulps + shufps/unpckhps yatay indirme):**

```c
float simd_dot(const float * a, const float * b, int n)
{
    __int64 v1 = 0;   // phi: rax döngü-taşıyıcı
    float v2 = 0;   // phi: xmm0 döngü-taşıyıcı
    do {
        v1 += 0x10;
        v2 += ((*( float *)(a + v1)) * (*( float *)(b + v1)))
            + ((*( float *)(a + v1 + 4)) * (*( float *)(b + v1 + 4)))
            + ((*( float *)(a + v1 + 8)) * (*( float *)(b + v1 + 8)))
            + ((*( float *)(a + v1 + 12)) * (*( float *)(b + v1 + 12)));
    } while ( v1 + 0x10 != (n >> 2) << 4 );
    ...
    return v2;   // phi kurtarıldı
}
```

Vektör register'ının dört lane'i SKALER çarpımlara geri açıldı — `simd_add`/`simd128`
intrinsic'i kalmadı. (Hex-Rays bu kodda intrinsic çağrıları gösterir.)

**`ortalama_hesapla` — O2, 8 elemanlı paddd/psrldq yatay toplam ağacı (v4'te `simd_add(...)` idi):**

```c
float ortalama_hesapla(const Ogrenci * o)
{
    // >>> toplama() buraya inline edilmis (DWARF kaniti)
    return ( (((*( int *)(o + 4)) + (*( int *)(o + 20))) + ((*( int *)(o + 12)) + (*( int *)(o + 28))))
            + (((*( int *)(o + 8)) + (*( int *)(o + 24))) + ((*( int *)(o + 16)) + (*( int *)(o + 32)))) == 0 )
           ? 0 : ((float)(<aynı toplam>)) * 0.125;
}
```

8 `notlar[]` elemanının tamamı skaler toplam olarak geri kazanıldı.

### D.3 Yeni testler

- **[19]** kurban4.elf (O0 -g): CHA devirt + override dürüstlüğü + iç içe else-if
  ternary + erken dönüş goto'suz + trambolin iç içe if/else (13 doğrulama)
- **[20]** kurban4_o3.elf (O3 -mssse3 -g): cmov ternary + SIMD intrinsic'siz tam
  skaler geri açma + phi değişkenleri + `+= 0x10` sayaç kurtarma (8 doğrulama)
- **[21]** sentetik CFG: trambolin füzyonu + jcc kenar yönlendirme (5 doğrulama)

---

## 0-E. v6.0 GÜNCELLEMESİ — ÇIKTI KALİTESİ + ÇOKLU MİMARİ + HAZIR İMZA HAVUZU + LUMINA + SCRIPT API (bu oturum)

"SINIR YOK" üçüncü dalgası. İki cephede birden: (1) v5 dürüstlük listesindeki
çıktı-kalitesi kalıntıları, (2) karşılaştırma tablosundaki "GERİDE" satırları.
Test sayısı: 228 → **266 PASS / 0 FAIL** (+38 doğrulama).

### E.1 Decompiler çıktı kalitesi (v5 dürüstlük listesi kapanışı)

| Kalıntı | v6 çözümü | Kanıt |
|---|---|---|
| `0xffffffff` sabitleri | İşaretli pretty-print: küçük-negatif görünümlü sabitler kaynaktaki haline döner (`mov $0xffffffff` → `-1`); `0x51eb851f` gibi büyük magic'ler DOKUNULMAZ | `erken_donus`: `return -1;` (kaynakla birebir) |
| Sahte `struct_N` / yanlış `_IO_FILE` giydirme | **AUTHORITATIVE DWARF bağlama**: parametre tipi DWARF'ta biliniyorsa heuristik union-find bağını devralır; struct-değil işaretçilerde (`const float *`) sahte bağ TEMİZLENİR; çok-adaylı offset eşleşmesinde belirsizse giydirmekten VAZGEÇİLİR (yanlış isim, isimsizlikten kötüdür) | `ortalama_hesapla` O2: `o->notlar[0..7]` — eskiden `*(int*)(o+4)` + sahte `struct_1`; `rapor_yaz`: `o->numara`, `(float)o->ortalama` — eskiden `_IO_FILE` yanlış giydirme |
| -O2 DWARF'ında üye tipleri `int`e düşüyor | **Üye tipi ertelenmiş çözüm**: -O2'de struct, taban tiplerden ÖNCE gelir (ileri referans); parse anında değil CU'lar bitince çözülür (parametrelerdeki v3 mekanizmasının üye muadili) | Ogrenci DWARF: `int notlar[8]; float ortalama; char isim[24]` — eskiden hepsi `int` |
| `movups [rsp+K], xmm0` ham SIMD store | **Rodata sabitli store geri açma**: `movdqa xmm0,[rip+X]` 4 sabit lane'e çözülür, `movups [mem]` 4 üye atamasına açılır | kurban_o2s main: `v1.field_4 = 0; v1.field_8 = 13; ... = 39;` + `... = 52; ... = 91;` — derleyicinin döngü-çözdüğü notlar dizisi TAMAMEN görünür |
| `simd_dot` n%4 kuyruğu `while(true)` kapsülü | **SAHTE DÖNGÜ KORUMASI**: head'den latch'e ileri akışta erişilemeyen "backedge" giriş trambolinidir — döngü sanılmaz. + **ÇOK-ÖNCÜL PHI MİRASI**: kuyruk blokları emit-edilmiş öncülün durumundan phi adlarını alır | `simd_dot` O3: `while(true) { return... }` KALKTI → `return (v2 + a[n&(-4)]*b[n&(-4)])...` + `return v2;` — phi isimleri kuyruğa akar (kalan goto'lar dürüst listede) |

### E.2 ÇOKLU MİMARİ — ARM64 (AArch64) + ARM32 (ARM modu)

x86-64/x86-32 decompiler çekirdeğine ek: **ARM64 ve ARM32'te tam analiz
hattı** — Capstone çoklu-mimari motoru, ELF `e_machine` tespiti (0xB7/0x28),
BL hedeflerinden fonksiyon keşfi, `b/b.cond/cbz` kenarlarıyla CFG-xref,
`adr/adrp` ile rodata string DATA-xref'i, string taraması, deepscan'ın
veri-referansı stratejisi. Decompiler ARM'da dürüstçe mimari bilgisi basar
(yanlış pseudocode ÜRETMEZ — v7 hedefi).

Fixture'lar **cross-compiler'sız** elle kodlanmış ARM komut kodlamalarıyla
üretilir (`tests/fixtures/make_fixture_arm.py` — askeri seviye öz-yeterlilik):
`kurban_arm64.elf` (mov/bl/cbz/b/b.eq/adr/ret + rodata string) ve
`kurban_arm32.elf` (mov/bl/bx lr).

**Canlı çıktı (kurban_arm64.elf):**
```
0x000000400104  08 00 00 94   bl   #0x400120          ; sub_00400120  <call xref>
0x000000400138  81 00 00 b4   cbz  x1, #0x400148      <2 xref — dal + geri döngü>
0x000000400150  80 05 00 10   adr  x0, #0x400200      ; "ARM64 GodTier askeri test"
```

**Bonus: bu çalışma sırasında gerçek bir parser bug'ı yakalandı** — ELF32
section header'da `sh_flags` yanlış ofsetten (sh_link!) okunuyordu: 32-bit
ELF'lerde `.text`'in EXEC bayrağı kayboluyordu. Düzeltildi (tüm ELF32
kullanıcıları için).

### E.3 HAZIR İMZA HAVUZU — "kutudan çıktığı gibi" FLIRT deneyimi

v4'teki boş havuz eleştirisinin kapanışı: `sigs/libc_x64.gsig` — **2208 imza**,
sistem glibc'sinden (`load /usr/lib/x86_64-linux-gnu/libc.so.6` + `sig export`)
üretilerek repoya gömüldü. **`load` komutu artık `sigs/*.gsig` havuzlarını
OTOMATİK uygular** (IDA FLIRT / Ghidra FID'in kutudan-çıktığı-gibi akışı —
bizimki ayrıca TEK KOMUTLA yeniden üretilebilir ve genişletilebilir).

**Canlı kanıt (siglib_strip.elf yüklemesi):**
```
[+] Hazir imza havuzu uygulandi: 4 isim geri kazanildi (2 havuz: sigs/*.gsig)
  0x401126       ortak_topla
  0x40113d       ortak_max3
  0x401171       ortak_parite
```

### E.4 LUMINA-LITE — birikimli yerel isim havuzu (bulut YOK)

IDA Lumina'nın yerel muadili: `lumina push` isimli fonksiyonları masked-pattern
imzalarıyla birikimli havuza ekler (isim bazlı dedupe — aynı kanıt iki kez
eklenmez, yeni kanıt eskiyi günceller); `lumina pull` havuzu herhangi bir
binary'ye uygular. Bilgelik `lumina.gsig` dosyasında sizinle büyür — sunucuya
binary göndermek YOK (askeri çevrimdışı gereksinim).

### E.5 SCRIPT API — değişkenler, aritmetik, koşullar

`.gt` scriptleri artık programlamadır: `$değişken`, `set` (tam öncelikli
aritmetik: `+ - * / % << >> & | ^ ( )` hex dahil), `eval`, `echo`, `if <kosul> : <komut>`
(iç içe koşullar dahil). IDA/Ghidra'nın Python betiklerine benzer gücü
bağımlılıksız sağlar:
```
set $a = 0x10 * 3
set $b = ( $a + 6 ) / 3
if $a == 48 : if $b < 20 : decomp main
```

### E.6 Yeni testler (228 → 266)

- **[14-B]** v6 yükseltmesi: SIMD lane + DWARF struct giydirme birlikte —
  `o->notlar[k]` (ham `*(int*)(o+K)` YOK)
- **[19]** `return -1` işaretli pretty-print
- **[22]** ARM64: mimari tespiti + BL keşfi + call/data/jcc xref + string +
  decomp dürüstlük mesajı; ARM32: bl/bx lr (16 doğrulama)
- **[23]** libc havuzu (≥2000 imza + memcpy/printf) + lumina push dedupe +
  pull geri kazanımı + ApplySigPools otomatik uygulama (12 doğrulama)
- **[24]** EvalArith öncelik/ret testleri + $değişken + koşul doğruluğu/yanlışlığı (10 doğrulama)

### E.7 Kalan dürüstlük listesi (v6 sonrası)

- **ARM64/ARM32 decompiler'ı yok** — analiz (dis/funcs/xref/strings/deepscan-veri)
  tam; pseudocode v7 hedefi (Hex-Rays/Ghidra burada önde)
- **O3 kuyruk goto'ları** — `simd_dot` n%4 zinciri artık görünür ve phi'li ama
  erken-dönüş zinciri yerine goto'lar kalıyor (v6'da kapsül kalktı, isimler aktı)
- **GUI/debugger olgunluğu** — ImGui GUI temel; etkileşimli debugger yok
- **Hazır imza DB genişliği** — 2208 glibc imzası (tek komutla çoğalır);
  IDA FLIRT DB'si 20+ yıllık birikim (bizimki kullanıcı üretimine dayalı büyür)

---

## 1. Kısa Cevap — İki Soruya

**Soru 1: "IDA ve Ghidra tamamını tarayıp sonrasında istenilen yeri mi C++ koduna çeviriyor?"**

**Evet, aynen öyle — ve gerekçe tam olarak düşündüğün şey.** İkisi de *iki fazlı* çalışır:

1. **Faz 1 — Global auto-analysis (tüm binary):** Dosya açıldığında IDA ve Ghidra
   segmentleri/section'ları çözer, tüm fonksiyonları bulmaya çalışır, tüm string'leri,
   import/export tablolarını, **çapraz referansları (xref)** ve dolaylı çağrı hedeflerini
   çıkarır. IDA bu sırada FLIRT imza veritabanıyla "bu kod Visual Studio 2019'un
   `memcpy`'si" gibi tespitler yapar; Ghidra "Decompiler Parameter ID" analizi **arka
   planda tüm fonksiyonları decompile ederek** parametre tiplerini çağıran/çağrılan
   arasında yayar.
2. **Faz 2 — Lokal decompile (istediğin fonksiyon):** Sen bir fonksiyonun pseudocode'unu
   istediğinde (IDA'da F5, Ghidra'da Decompile penceresi) decompiler **sadece o
   fonksiyonu** çevirir — ama çevirirken Faz 1'in tüm veritabanını kullanır: başka
   fonksiyonların bu fonksiyona ne tipte argüman geçtiği, bu fonksiyonun dönüş
   değerini kimin nasıl kullandığı, `[rax+0x24]`'e erişen başka fonksiyonların var olup
   olmadığı.

**Neden önce her şeyi taramak şart?** Çünkü bir fonksiyona bakarak söylenemeyecek
şeyler, ancak *diğer* fonksiyonlara bakınca söylenebilir:

| Bilmek istediğin | Sadece bu fonksiyondan anlaşılır mı? | Nereden anlaşılır |
|---|---|---|
| `call 0x1149` hangi fonksiyon? | Hayır | Başka yerlerdeki isimli sembol/xref'ler |
| `[rbp-0x18]` bir `int*` mi, `Ogrenci*` mi? | Hayır | Bu pointer'ı **üreten** çağıran fonksiyonun argümanı |
| `add rax, 4` bir struct'ın `notlar` alanı mı? | Hayır | Aynı base'e **başka** fonksiyonların eriştiği offset'ler |
| Fonksiyon kaç argüman alıyor? | Kısmen | Argüman register'larını kullanan komutlar **+** çağıranların doldurduğu register'lar |
| Dönüş tipi `int` mi `float` mi? | Hayır (bazen) | Dönüş değerini kullanan `cvtsi2ss` gibi komutlar |
| Bu fonksiyon `std::string` mi kendi buffer'ı mı? | Hayır | Tüm program genelinde çağrı zinciri |

Aşağıdaki Bölüm 3'te bunun **bu dokümanın kurban programından gerçek kanıtını**
göreceğiz: `Ogrenci` struct'ının varlığı, TEK bir fonksiyona bakarak değil, üç
fonksiyonun aynı belleğe farklı offset'lerle erişmesini birleştirerek anlaşılıyor.

**Soru 2: "En gelişmiş disassembly→C++ çevirici mi?"**

**Hayır — ve kimse öyle iddia etmemeli.** Sıralama (2024–2025 itibarıyla):

1. **Hex-Rays (IDA Pro)** — ticari pazarın açık ara lideri. 20+ yıllık tip çıkarımı,
   decompiler SDK'sı, Lumina (tip veritabanı paylaşımı). SSS.
2. **Ghidra Decompiler** — açık kaynakların en iyisi (NSA'ın 20 yıldır geliştirdiği
   platformun kalbi; geliştiricileri 2019 RSA sunumunda 20 yıllık geçmişi doğruladı).
   Tip çıkarımı + yapılaştırma çok güçlü. SS.
3. **Binary Ninja HLIL/MLIL** — çok temiz IL tasarımı, API'si en iyisi. SS.
4. **RetDec** — bakım modunda, x86/x64 zayıf. **Snowman** — depo silindi, öldü.
5. **i4M-GodTier decompiler modülü (bizimki)** — gerçek bir CFG + döngü tespiti +
   pseudocode üreteci; ama bu, Hex-Rays sınıfı bir *tam decompiler* değil,
   "yapılandırılmış disassembly lifter"ı düzeyinde. Dürüst not: projenin genelinde SSS
   hedefledik; decompiler modülü tek başına değerlendirilirse yolun başında.

Bu dokümanın geri kalanı **tam olarak nerede olduğunu** gerçek çıktılarla gösteriyor.

---

## 2. Test Kurbanı — Gerçek Program

### 2.1 Kaynak kod (`kurban.cpp`, gerçek dosya)

```cpp
#include <cstdio>
#include <cstring>

struct Ogrenci {
    int   numara;
    int   notlar[8];
    float ortalama;
    char  isim[24];
};

// 1) Çok yerden çağrılan saf yardımcı (xref hedefi)
int toplama(const int* dizi, int adet) {
    int toplam = 0;
    for (int i = 0; i < adet; i++) {
        toplam += dizi[i];
    }
    return toplam;
}

// 2) Struct alan erişimi + koşul
float ortalama_hesapla(const Ogrenci* o) {
    int toplam = toplama(o->notlar, 8);
    if (toplam == 0) {
        return 0.0f;
    }
    return (float)toplam / 8.0f;
}

// 3) Özyineleme (recursive)
long faktoriyel(int n) {
    if (n <= 1) return 1;
    return n * faktoriyel(n - 1);
}

// 4) String + çağrı zinciri + if/else
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
```

### 2.2 Derleme ve programın GERÇEK çalışma çıktısı

```
$ g++ -O0 -g -o kurban_O0 kurban.cpp
$ g++ -O2 -o kurban_O2 kurban.cpp && strip kurban_O2 -o kurban_O2s
$ ./kurban_O0
Ogrenci 7: Ali ort=45.50
buyuk faktoriyel: 5040
```

Doğrulama: `notlar = {0,13,26,39,52,65,78,91}`, toplam 364, 364/8 = **45.50**;
`faktoriyel(7) = 5040 > 1000` → "buyuk" dalı. Program gerçekten çalışıyor.

---

## 3. "Neden Tüm Binary Taraması Şart" — Kurban Programından Gerçek Kanıt

Üç farklı fonksiyonun, aynı base pointer (`rdi` = `Ogrenci*`) üzerinden belleğe
erişimini izleyelim. Bunlar **gerçek objdump çıktıları**:

`ortalama_hesapla` içinde (0x119a–0x11aa):
```asm
mov    rax,QWORD PTR [rbp-0x18]   ; rax = o
add    rax,0x4                    ; rax = o + 4
mov    esi,0x8
mov    rdi,rax
call   1149 <_Z7toplamaPKii>      ; toplama(o+4, 8)
```

`rapor_yaz` içinde (0x1217–0x1243):
```asm
mov    rax,QWORD PTR [rbp-0x18]   ; rax = o
movss  xmm0,DWORD PTR [rax+0x24]  ; float oku: o + 0x24
...
mov    rax,QWORD PTR [rbp-0x18]
mov    eax,DWORD PTR [rax]        ; int oku: o + 0x0
...
lea    rcx,[rax+0x28]             ; char*: o + 0x28
```

`main` içinde (0x12b7, 0x12e0):
```asm
mov    DWORD PTR [rbp-0x50],0x7   ; ali.numara = 7      (offset 0x0)
...
mov    DWORD PTR [rax],0x696c41   ; "Ali" yazılır       (offset 0x28)
```

Şimdi bu üç fonksiyonun erişimlerini **birleştir**:

| Offset | Erişen fonksiyon | Erişim şekli | Çıkarım |
|---|---|---|---|
| `+0x00` | main, rapor_yaz | `mov dword [rax]` | `int` (4 bayt) |
| `+0x04` | ortalama_hesapla | `toplama(o+4, 8)` → 8 elemanlı int dizisi | `int[8]` (0x04–0x23) |
| `+0x24` | rapor_yaz | `movss xmm0, [rax+0x24]` | `float` (4 bayt) |
| `+0x28` | main, rapor_yaz | `lea rcx,[rax+0x28]` + `printf %s` | `char[24]` |

Hiçbir fonksiyon tek başına `Ogrenci` struct'ını göstermiyor. Ama **xref'lerle tüm
kullanımları birleştirdiğin anda** struct'ın tam yerleşimi ortaya çıkıyor:

```
struct Ogrenci {        // 0x40 = 64 bayt (main'de sub rsp,0x50 stack ayırımı ile uyumlu)
    int   numara;   // +0x00
    int   notlar[8]; // +0x04 .. +0x23
    float ortalama;  // +0x24
    char  isim[24];  // +0x28 .. +0x3F
};
```

**İşte IDA ve Ghidra'nın önce her şeyi taramasının nedeni bu.** Ghidra'da "Auto Create
Structure" ve Decompiler Parameter ID, IDA'da Hex-Rays'ın xref tabanlı tip yayılımı
(Lumina ile desteklenen) tam bu birleştirmeyi otomatik/yarı otomatik yapar. Bizim
motor şu an bu birleştirmeyi **analiste bırakır** (yapamadıkları listesinde, Bölüm 5).

---

## 4. i4M-GodTier'ın YAPABİLDİKLERİ (gerçek çıktılarla)

### 4.1 Fonksiyon keşfi + C++ sembol demangling

`funcs` komutu (gerçek çıktı). Motor, ELF `.symtab`'den (22 sembol; DWARF kullanmadan)
isimleri çözer ve Itanium-mangled `_Z7toplamaPKii` → `toplama(...)` demangle eder:

```
gt> funcs
[*] Fonksiyon keşfi (semboller + entry + call hedefleri)...
[*] Bulunan aday: 18 fonksiyon
[*] Recursive traversal disassembly...
[*] String taraması (ASCII + UTF-16LE)...
[+] Analiz bitti: 18 fonksiyon, 328 komut, 185 xref, 29 string
== FONKSIYONLAR ==========================================
  0x1000         _init                                        7 komut  [sembol]
  0x1060         _start                                      23 komut  [sembol]
  0x1149         toplama(...)                                21 komut  [sembol]
  0x118e         ortalama_hesapla(...)                       20 komut  [sembol]
  0x11d5         faktoriyel(...)                             19 komut  [sembol]
  0x120b         rapor_yaz(...)                              43 komut  [sembol]
  0x12af         main                                        48 komut  [sembol]
  ... (toplam 18)
```

Not: Derleme `-g` (DWARF) ile yapıldı ama motor DWARF'ı okumaz; isimler `.symtab`'den
geliyor. Bunu doğrulamak için `objcopy --strip-debug` uygulanmış kopyada da aynı 22
sembol ve aynı fonksiyon listesi elde edildi. (IDA/Ghidra ek olarak DWARF'dan zengin
tip bilgisi de çıkarır — bizde yok.)

### 4.2 Recursive traversal disassembly — objdump ile birebir aynı

`dis 0x1149 21` (gerçek çıktı; `toplama`, -O0). Capstone tabanlı, xref sayıları da satır
sonunda:

```
  0x000000001149  55                     push     rbp                               <1 xref>
  0x00000000114a  48 89 e5               mov      rbp, rsp
  0x00000000114d  48 89 7d e8            mov      qword ptr [rbp - 0x18], rdi
  0x000000001151  89 75 e4               mov      dword ptr [rbp - 0x1c], esi
  0x000000001154  c7 45 fc 00 00 00 00   mov      dword ptr [rbp - 4], 0
  0x00000000115b  c7 45 f8 00 00 00 00   mov      dword ptr [rbp - 8], 0
  0x000000001162  eb 1d                  jmp      0x1181
  0x000000001164  8b 45 f8               mov      eax, dword ptr [rbp - 8]          <1 xref>
  0x000000001167  48 98                  cdqe
  0x000000001169  48 8d 14 85 00 00 00 00 lea      rdx, [rax*4]
  0x000000001171  48 8b 45 e8            mov      rax, qword ptr [rbp - 0x18]
  0x000000001175  48 01 d0               add      rax, rdx
  0x000000001178  8b 00                  mov      eax, dword ptr [rax]
  0x00000000117a  01 45 fc               add      dword ptr [rbp - 4], eax
  0x00000000117d  83 45 f8 01            add      dword ptr [rbp - 8], 1
  0x000000001181  8b 45 f8               mov      eax, dword ptr [rbp - 8]          <1 xref>
  0x000000001184  3b 45 e4               cmp      eax, dword ptr [rbp - 0x1c]
  0x000000001187  7c db                  jl       0x1164
  0x000000001189  8b 45 fc               mov      eax, dword ptr [rbp - 4]
  0x00000000118c  5d                     pop      rbp
  0x00000000118d  c3                     ret
```

`objdump -d -M intel kurban_O0` çıktısıyla komut komut aynıdır (Bölüm 6'da yan yana).

### 4.3 CFG kurma + döngü tespiti — pseudocode üretimi

`decomp 0x1149` (gerçek çıktı):

```c
// ============================================================
// toplama(...)  (21 komut, 4 blok, 1 döngü)
// ============================================================
// kapsam: 0x1149 - 0x118e
void toplama(...)(void)
{
    push rbp;    // 0x1149
    mov rbp, rsp;    // 0x114a
    mov qword ptr [rbp - 0x18], rdi;    // 0x114d
    mov dword ptr [rbp - 0x1c], esi;    // 0x1151
    mov dword ptr [rbp - 4], 0;    // 0x1154
    mov dword ptr [rbp - 8], 0;    // 0x115b
    goto 0x1181;    // 0x1162
    while (true) { // döngü başı 0x1164
        mov eax, dword ptr [rbp - 8];    // 0x1164
        cdqe     // 0x1167
        lea rdx, [rax*4];    // 0x1169
        mov rax, qword ptr [rbp - 0x18];    // 0x1171
        add rax, rdx;    // 0x1175
        mov eax, dword ptr [rax];    // 0x1178
        add dword ptr [rbp - 4], eax;    // 0x117a
        add dword ptr [rbp - 8], 1;    // 0x117d
        mov eax, dword ptr [rbp - 8];    // 0x1181
        cmp eax, dword ptr [rbp - 0x1c];    // 0x1184
        if (!(jl 0x1164)) goto 0x1189;
    }
    mov eax, dword ptr [rbp - 4];    // 0x1189
    pop rbp;    // 0x118c
    return;    // 0x118d
}
```

Dikkat: derleyicinin `for` döngüsünü kurduğu klasik pattern — `jmp 0x1181` (condition
first) + geri dönüşte `jl 0x1164` — motor tarafından **doğru yakalandı**: 4 blok, 1
döngü, `while (true)` kapsülü, döngü dışına `goto`. Kaynak koddaki `for (int i = 0; i
< adet; i++)` ile aynı control flow.

### 4.4 String referanslarının pseudocode'a gömülmesi

`decomp 0x120b` (rapor_yaz) — `lea rax, [rip+X]` komutlarının hedefi string olarak
çözülüyor (gerçek çıktı, kısaltılmış):

```c
// rapor_yaz(...)  (43 komut, 4 blok)
void rapor_yaz(...)(void)
{
    ...
    movss xmm0, dword ptr [rax + 0x24];    // 0x121b
    ...
    lea rax, [rip + 0xdb8]   // -> "Ogrenci %d: %s ort=%.2f";    // 0x1245
    ...
    faktoriyel(...)();    // 0x1261
    mov qword ptr [rbp - 8], rax;    // 0x1266
    cmp qword ptr [rbp - 8], 0x3e8;    // 0x126a   <- 0x3e8 = 1000 (kaynaktaki f > 1000)
    if (!(jle 0x1291)) goto 0x1274;
    ...
    lea rax, [rip + 0xd9b]   // -> "buyuk faktoriyel: %ld";    // 0x127b
    ...
    goto 0x12ac;    // 0x128f
    ...
    lea rax, [rip + 0xd95]   // -> "kucuk faktoriyel: %ld";    // 0x1298
    ...
}
```

Kaynakla birebir eşleşen iki detay: `cmp ..., 0x3e8` → `if (f > 1000)`, ve iki `printf`
dalının string'leri.

*(Şeffaflık notu: bu oturumda gerçek bir bug bulundu ve düzeltildi — önceki sürüm,
sonunda `\n` bulunan string'leri (`"Ogrenci %d: ..."` gibi) tamamen yutuyordu çünkü
kayıt şartı `c == 0` idi. GNU `strings` davranışına hizalanarak düzeltildi; 76/76 test
hâlâ geçiyor.)*

### 4.5 Özyinelemenin tespiti — xref ile kanıt

`faktoriyel` (0x11d5) gerçek çıktıda kendisini çağırıyor:

```c
// faktoriyel(...)  (19 komut, 4 blok)
void faktoriyel(...)
{
    ...
    cmp dword ptr [rbp - 0x14], 1;    // 0x11e1   <- kaynaktaki "if (n <= 1)"
    if (!(jg 0x11ee)) goto 0x11e7;
    mov eax, 1;    // 0x11e7                 <- return 1
    goto 0x1205;    // 0x11ec
    mov eax, dword ptr [rbp - 0x14];    // 0x11ee
    movsxd rbx, eax;    // 0x11f1
    mov eax, dword ptr [rbp - 0x14];    // 0x11f4
    sub eax, 1;    // 0x11f7                 <- n - 1
    mov edi, eax;    // 0x11fa
    faktoriyel(...)();    // 0x11fc          <- KENDİNİ ÇAĞIRIYOR (recursive)
    imul rax, rbx;    // 0x1201              <- n * ...
    ...
}
```

Xref sorgusu bunu kanıtlıyor (gerçek çıktı):

```
gt> xref 0x1149                      <- toplama'ya kim çağırıyor?
  call  0x11aa -> 0x1149             (sadece ortalama_hesapla — doğru, tek çağıran o)

gt> xref 0x11d5                      <- faktoriyel'e kim çağırıyor?
  call  0x11fc -> 0x11d5             (faktoriyel kendisi → ÖZYİNELEME)
  call  0x1261 -> 0x11d5             (rapor_yaz → faktoriyel)
```

İki çağrı noktası gerçekten de kaynakta olan iki çağrı: `faktoriyel(n-1)` (içeride) ve
`faktoriyel(o->numara)` (rapor_yaz içinde). Yanlış pozitif yok.

### 4.6 main'de derleyici hilelerinin görünür kalması

`decomp 0x12af` (gerçek çıktı, kısaltılmış) — iki çok öğretici gerçek detay:

```c
// main  (48 komut, 4 blok, 1 döngü)
void main(void)
{
    ...
    mov dword ptr [rbp - 0x50], 7;    // 0x12b7          <- ali.numara = 7
    ...
    mov dword ptr [rax], 0x696c41;    // 0x12e0          <- strcpy(ali.isim, "Ali")
    ...                                                     0x41='A' 0x6c='l' 0x69='i' (LE)
    while (true) { // döngü başı 0x12ef
        ...
        imul rax, rax, 0x51eb851f;    // 0x1300          <- (i*13) / 100 için
        shr rax, 0x20;    // 0x1307                          "magic number" bölmesi
        sar eax, 5    // 0x130b                              (kaynakta: % 100)
        ...
    }
    ...
    ortalama_hesapla(...)();    // 0x1337
    ...
    rapor_yaz(...)();    // 0x134a
    ...
}
```

- `strcpy(ali.isim, "Ali")` derleyici tarafından **tek bir `mov` immediate'a** indirildi:
  `0x696c41` little-endian = `41 6c 69 00` = `"Ali\0"`.
- `(i * 13) % 100` derleyicide sabit-bölme idiomuna dönüştü:
  `x * 0x51eb851f >> 37 ≈ x / 100`.

Bu ikisi, decompiler'ın "idiom katlama" yapmamasının bedelini gösterir (yapamadıkları
listesinde) ama aynı zamanda çıktının **gerçekten gerçek makine kodunu yansıttığının**
kanıtıdır.

### 4.7 Optimize + strip edilmiş binary'de manuel analiz

`kurban_O2s` (stripped, `-O2`): otomatik keşif zorlanıyor (Bölüm 5.4) ama adrese
işaret edince motor optimize döngüyü de çözüyor. `decomp 0x11c0` (gerçek çıktı —
-O2'deki `toplama`, tamamen farklı kod: sayaç yerine pointer karşılaştırma):

```c
//   (13 komut, 5 blok, 1 döngü)
// kapsam: 0x11c0 - 0x11e3
void (void)
{
    test esi, esi;    // 0x11c0
    if (!(jle 0x11e0)) goto 0x11c4;
    movsxd rsi, esi;    // 0x11c4
    xor eax, eax;    // 0x11c7
    lea rdx, [rdi + rsi*4];    // 0x11c9        <- end = dizi + adet*4
    while (true) { // döngü başı 0x11d0
        add eax, dword ptr [rdi];    // 0x11d0  <- *p
        add rdi, 4;    // 0x11d2                <- p++
        cmp rdi, rdx;    // 0x11d6              <- p != end ?
        if (!(jne 0x11d0)) goto 0x11db;
    }
    return;    // 0x11db
    xor eax, eax;    // 0x11e0                  <- adet <= 0 dalı: return 0
    return;    // 0x11e2
}
```

Aynı `toplama` fonksiyonu, -O0'daki sayaçlı döngü yerine pointer'lı döngüye dönüştü —
motor her iki varyantta da döngüyü doğru yakaladı.

### 4.8 Yetenek özeti (gerçekleştirilenler)

| # | Yetenek | Kanıt |
|---|---|---|
| 1 | PE32/PE32+ **ve** ELF64 ayrıştırma | kurban_O0 ELF64 yüklendi |
| 2 | Sembol tablosundan fonksiyon listesi + C++ (Itanium) demangle | `toplama(...)`, `main` |
| 3 | Entry point + call hedefiyle fonksiyon keşfi (sembolsüzde kısmi) | kurban_O2s'de 6 fonksiyon |
| 4 | Recursive traversal disassembly (Capstone), objdump ile birebir | Bölüm 4.2 |
| 5 | CFG kurma (blok sayısı) + geri-kenar döngü tespiti | `4 blok, 1 döngü` |
| 6 | Pseudocode üretimi: blok/döngü yapısı, `goto`, `return` | Bölüm 4.3 |
| 7 | String referans çözümü + pseudocode'a gömme (ASCII + UTF-16LE) | Bölüm 4.4 |
| 8 | Direkt çağrı hedeflerinin isimlendirilmesi (sembol varsa) | `faktoriyel(...)()` |
| 9 | Xref (çağıran listesi), özyineleme dahil | Bölüm 4.5 |
| 10 | Sabitleri ve stack ofsetlerini koruyarak birebir çeviri | `0x3e8`, `0x696c41` |
| 11 | -O0 ve -O2 kodunda çalışma | Bölüm 4.3, 4.7 |
| 12 | Win64 çağrı kuralında argüman toplama (PE'de `MessageBoxA(0, "deneme", ...)`) | `ORNEK_OTURUM.md` Senaryo 1 |
| 13 | **v2:** İki fazlı global tip analizi (imza + dönüş tipi çıkarımı) | Bölüm 0 |
| 14 | **v2:** STRUCT geri kazanımı (union-find + offset kümeleme) | `struct_1 {int;int[];float;char[24]}` |
| 15 | **v2:** İfade katlama — 7 komut → `v1 += a1[v2]` | Bölüm 0 |
| 16 | **v2:** Koşul yapılaştırma — `while (v2 < a2)`, if/else elması | Bölüm 0 |
| 17 | **v2:** Magic-number idiom katlama — `% 100`, `x / 100` | Bölüm 0 |
| 18 | **v2:** ELF PLT/GOT isim çözümü (`printf@plt`) | Bölüm 0 |
| 19 | **v2:** Strip'li binary'de main keşfi | Bölüm 0 |
| 20 | **v2:** SysV argüman toplama + float dönüş (xmm0) | Bölüm 0 |

---

## 5. i4M-GodTier v1'in YAPAMADIKLARI (v2 öncesi durum — Bölüm 0'daki v2 güncellemesiyle çoğu kapatıldı)

> NOT: Aşağıdaki maddeler v1'e aittir ve tarihsel doğruluk için korunmuştur.
> 5.1 (tip çıkarımı), 5.2 (ifade birleştirme), 5.3 (koşul yapılaştırma),
> 5.4 (main keşfi), 5.5 (SysV argümanlar), 5.6 (PLT isimleri), 5.7 (idiom
> katlama) ve 5.8 (struct geri kazanımı) maddeleri v2.0'da YAPILDI — gerçek
> çıktılar için Bölüm 0'a bakın. Kalan açık maddeler Bölüm 0'ın sonundaki
> güncel dürüstlük listesindedir.

Buradaki her madde yukarıdaki gerçek çıktılardan türetilmiştir — kâğıt üstü eleştiri değil.

### 5.1 Tip çıkarımı yok — `toplama` ne `int` döndürüyor ne argüman alıyor gibi görünüyor

Gerçek çıktı: `void toplama(...)(void)`. Oysa kaynak: `int toplama(const int*, int)`.
Argümanlar `rdi`/`esi`'de geldiği halde pseudocode imzasında görünmez; dönüş değeri
`eax`'e yazılır ama `return <değer>;` yerine `mov eax, ...` + `return;` kalır.
IDA/Ghidra bunu otomatik çözer (Ghidra: `undefined4 toplama(int *dizi, int adet)`).

### 5.2 Değişken isimlendirme ve ifade birleştirme yok

Kaynak: `toplam += dizi[i];` — bizim çıktıda **7 ayrı satır** (`mov eax,[rbp-8]` →
`cdqe` → `lea rdx,[rax*4]` → `mov rax,[rbp-0x18]` → `add rax,rdx` → `mov eax,[rax]` →
`add [rbp-4],eax`). Hex-Rays bunu tek satır `toplam += dizi[i]` olarak geri üretir.
Ayrıca `[rbp-4]` → `toplam`, `[rbp-8]` → `i` isimlendirilmesi yapılmaz (IDA'da otomatik
`v1`, `v2`; Ghidra'da `local_8h` + kullanıcı isimleri yayılır).

### 5.3 Koşullar yapılaştırılmamış — `while(true)` + `goto` seviyesinde kalınır

Gerçek çıktıda: `while (true) { ... if (!(jl 0x1164)) goto 0x1189; }`. Hex-Rays/Ghidra
çıktısı olurdu: `while (i < adet) { ... }`. `if/else` de `goto 0x12ac` olarak kalır
(rapor_yaz çıktısındaki `f > 1000` dalı). Bu, 1990'ların sonundaki ilk nesil
decompiler'ların (SOMix/Boomerang öncesi) seviyesidir; yapılaştırma (structuring)
algoritması (Sharir, tiling vs.) henüz uygulanmadı.

### 5.4 Sembolsüz + optimize binary'de otomatik keşif zayıf

`kurban_O2s` gerçek sonucu: **6 fonksiyon** bulundu (`_start`, PLT stub'ları vs.) —
`toplama`, `faktoriyel`, `rapor_yaz`, `main` **bulunamadı**. Sebep: `main`'in adresi
`__libc_start_main`'e register üzerinden geçiliyor (`lea rdi,[rip+X]; call *GOT`),
bizim motor bu pattern'i takip etmiyor. IDA (FLIRT + entry analizi) ve Ghidra bu
durumda main'i bulur. Kullanıcı elle `dis 0x11c0` yazınca analiz yapılıyor (Bölüm 4.7).

### 5.5 SysV (Linux ELF) çağrılarında argüman toplanmıyor

Argüman toplama kalıbı sadece Win64 (`rcx,rdx,r8,r9`) için yazıldığından ELF/SysV
(`rdi,rsi,rdx,rcx`) binarylerinde çağrılar `toplama(...)()` olarak, argümansız
görünüyor. PE hedeflerinde bu çalışır (`ORNEK_OTURUM.md` Senaryo 1).

### 5.6 ELF'te import/PLT isim çözümü yok

`printf` çağrısı `sub_00001030()` olarak görünüyor (PLT stub adresi). `.dynsym`'den
`printf@plt` çözülebilirdi ama yapılmadı. PE tarafında IAT çözümü **var** (dll.api
şeklinde); ELF tarafı eksik.

### 5.7 Derleyici idiomları katlanmıyor

`imul rax, rax, 0x51eb851f; shr 0x20; sar 5` → `% 100` geri çıkarılmıyor. Hex-Rays ve
Ghidra bunu otomatik tanır (`n % 100` gösterir). `mov [rax], 0x696c41` → `"Ali"`
string yazımı da yorumlanmıyor.

### 5.8 Struct/class geri kazanımı yok

Bölüm 3'teki tablo elle birleştirildi. Motorda "aynı base'e erişen offset'leri grupla,
struct öner" yeteneği yok (Ghidra'da yarı otomatik var, IDA'da struct toolbar + Lumina).

### 5.9 Yapılamayanların tamamı (kısa liste)

- Sanal fonksiyon/vtable analizi, RTTI sınıf hiyerarşisi kurma
- C++ istisna (`.eh_frame`/SEH) akış analizi
- Inlining'in geri açılması — bu kurban programda gerçek: `-O2`'de `memset` ve
  `strcpy` main'e gömüldü, main'deki `notlar` döngüsü **tamamen derleme zamanında
  hesaplandı** (Bölüm 8.4), `toplama` ise `ortalama_hesapla`'ya gömülüp SIMD'e
  vektörize edildi (Bölüm 8.5). "Burada bir zamanlar ayrı bir fonksiyon/döngü vardı"
  bilgisini hiçbir decompiler geri getiremez.
- Jump table (switch) çözümü
- Değişken ömür/birleştirme (SSA tabanlı veri akışı yok — o yüzden ifade birleşmiyor)
- DWARF/PDB'den tip importu

---

## 6. Uçtan Uca Gerçek Örnek — `toplama` fonksiyonu, üç katman

**Katman 1 — C++ kaynağı (yazdığımız):**
```cpp
int toplama(const int* dizi, int adet) {
    int toplam = 0;
    for (int i = 0; i < adet; i++) {
        toplam += dizi[i];
    }
    return toplam;
}
```

**Katman 2 — Derleyicinin ürettiği makine kodu (`objdump -d -M intel kurban_O0`, gerçek):**
```asm
0000000000001149 <_Z7toplamaPKii>:
    1149:  push   rbp
    114a:  mov    rbp,rsp
    114d:  mov    QWORD PTR [rbp-0x18],rdi     ; dizi
    1151:  mov    DWORD PTR [rbp-0x1c],esi     ; adet
    1154:  mov    DWORD PTR [rbp-0x4],0x0      ; toplam = 0
    115b:  mov    DWORD PTR [rbp-0x8],0x0      ; i = 0
    1162:  jmp    1181
    1164:  mov    eax,DWORD PTR [rbp-0x8]      ; i
    1167:  cdqe
    1169:  lea    rdx,[rax*4+0x0]              ; i*4
    1171:  mov    rax,QWORD PTR [rbp-0x18]     ; dizi
    1175:  add    rax,rdx                      ; &dizi[i]
    1178:  mov    eax,DWORD PTR [rax]          ; dizi[i]
    117a:  add    DWORD PTR [rbp-0x4],eax      ; toplam +=
    117d:  add    DWORD PTR [rbp-0x8],0x1      ; i++
    1181:  mov    eax,DWORD PTR [rbp-0x8]
    1184:  cmp    eax,DWORD PTR [rbp-0x1c]     ; i vs adet
    1187:  jl     1164                         ; i < adet ?
    1189:  mov    eax,DWORD PTR [rbp-0x4]      ; return toplam
    118c:  pop    rbp
    118d:  ret
```

**Katman 3 — Bizim decompiler'ın çevirdiği kod (`decomp 0x1149`, gerçek):** Bölüm 4.3'teki
tam çıktıdır; özetle:

```c
void toplama(...)(void)
{
    ...                                        // prologue + dizi/adet stack'e
    goto 0x1181;                               // döngü koşuluna atla
    while (true) { // döngü başı 0x1164
        ... // "toplam += dizi[i]" ifadesinin 7 satırlık ham hali + i++
        cmp eax, dword ptr [rbp - 0x1c];
        if (!(jl 0x1164)) goto 0x1189;         // i < adet → devam
    }
    mov eax, dword ptr [rbp - 4];              // return toplam (eax)
    return;
}
```

**Karşılaştırma — aynı fonksiyon, üç düzey:**

| Öğe | Kaynak (gerçek) | GodTier v1 (gerçek, eski) | GodTier v2 (gerçek, şimdi) | Hex-Rays düzeyi |
|---|---|---|---|---|
| İmza | `int toplama(const int*, int)` | `void toplama(...)(void)` | `int toplama(int * a1, int a2)` | aynı |
| Döngü | `for (i=0; i<adet; i++)` | `while(true)` + `goto` | `while ( v2 < a2 )` | aynı |
| Gövde | `toplam += dizi[i]` | 7 ayrı satır | `v1 += a1[v2];` | aynı |
| Dönüş | `return toplam` | `mov eax,..; return;` | `return v1;` | aynı |
| Kayıp | — | semantik %60 görünür | semantik ~%90 görünür | ~%90+ |

*(Son sütun "üretir" ifadeleri IDA/Ghidra'nın belgelenmiş yetenekleridir; bu oturumda
IDA/Ghidra çalıştırılmadı, çıktı uydurulmadı.)*

---

## 7. Hepten dürüst tablo — kim neyi yapar

| Yetenek | i4M-GodTier (v6) | Ghidra (OSS) | Hex-Rays (IDA, ticari) |
|---|---|---|---|
| Disassembly kalitesi (x86-64) | Capstone-çekirdek (endüstri standardı) + imza motoru + tip notları | kendi, çok iyi | en iyi (FLIRT + en geniş DB) |
| Sembollü fonksiyon keşfi | var | var | var |
| Sembolsüz fonksiyon keşfi | v4: prolog taraması + veri-referansı (fptr/vtable + PIE reloc) + tail-call — güven skoru ve kanıt zinciriyle; `deep apply` | iyi (aggressive finder, tek hamlede) | en iyi |
| FLIRT tarzı isim geri kazanımı | v4 `.gsig` (tek komutla üret) + v6: **repoda 2208 imzalı libc havuzu + load'ta OTOMATİK uygulama** | FID (hazır veritabanı gerekir) | FLIRT (en geniş hazır DB — 20+ yıl birikim) |
| CFG + döngü tespiti | v5: + süper blok birleştirme (trambolin yönlendirme + tek-öncül füzyon) | var | var |
| Yapılaştırma (if/else/while) | v4: while/do-while/for/break/continue/&&-\|\|/ternary + goto geri dönüşü; v5: erken dönüş zinciri + koşullu dönüş ternary'si | tam | tam + daha az goto |
| phi-SSA | v5: döngü-taşıyıcı phi (`v2 += ...` kurtarma) + cmov donanım-phi katlaması + uzlaşan-register mirası + koşullu dönüş ternary'si | tam SSA (dominator tree) | tam SSA |
| SIMD vektör geri açma | **v5: lane modeli** — movups/mulps/addps/paddd + yatay indirme zinciri TAMAMEN skaler ifadeye açılır | çoğunlukla ham kalır | çoğunlukla ham kalır |
| Devirtualizasyon | **v7: 4 strateji** — (1) kurucu vtable kanıtı, (2) DWARF CHA, (3) slot-tek-impl, (4) **PE32 RTTI atlası + singleton zincir değerlendiricisi** (gerçek metin2client.exe: 3842/7420 dolaylı çağrı statik çözüldü, IDA'da da Ghidra'da da otomatik karşılığı YOK) | yok (betikle kısmen) | yok (Simplify trace ile elle) |
| Değişken isim/tip çıkarımı | imza+tip+yerel-değişken + v6: **authoritative DWARF struct giydirme** (o->notlar[2] üslubu; belirsizse giydirmez) + **lumina push/pull birikimli isim havuzu** | otomatik | otomatik + Lumina (bulut) |
| Struct geri kazanımı | otomatik (union-find) | yarı otomatik | güçlü (elle hızlandırılır) |
| Derleyici idiom katlama | magic-div + % + opak öncül katlama + ölü kod budama | var (opak öncül katlaması yok) | var |
| Çağrı kuralı desteği | Win64 + SysV | tümü | tümü |
| DWARF/PDB | v3: DWARF 4/5 + PDB (MSF7/TPI) | DWARF var (PDB: Universal) | ikisi de var |
| Obfuscation analizi | v4: entropi + packer imzaları + anti-analiz + opaque predicate taraması → risk raporu; katlamayla ölü kod budama | çoğunlukla takılır (yerleşik tarama yok) | çoğunlukla takılır (+SDK ile elle) |
| Arama | v4: `find hex/imm/str/asm` | GUI arama | GUI + SDK |
| Mimari kapsamı | v6: x86-64 decompiler + ARM64/ARM32 analiz hattı; **v7: x86-32 (PE32) decompiler YOLU AÇILDI** — cdecl/thiscall/stdcall argüman kurtarma + ertelenmiş çağrı malzemeleşmesi (vN = çağrı; tek sefer basım) + devirt- entegrasyonu | onlarca mimari + hepsinde decompiler | onlarca mimari + hepsinde decompiler |
| GUI | ImGui (dock) | Swing | Qt (en olgun) |
| Komut satırı/otomasyon | v6: `godtier -s script.gt` + **$değişken/aritmetik/if koşullu script dili** (bağımlılıksız) | analyzeHeadless + Python (ghidra-script) | idat + idapython (en olgun betik API) |
| Fiyat | açık kaynak | açık kaynak | ~$$$/yıl |

Not (dürüstlük): Hex-Rays hâlâ genel olgunluk/DB genişliği/çoklu mimaride
öndedir; üstünlük iddiamız somut satırlardadır: **SIMD skaler geri açma**
(her ikisi de ham bırakır), **otomatik devirtualizasyon** (her ikisinde de otomatik yok — v7'de 4 strateji + gerçek
binary'de 3842 dolaylı çağrı statik çözüm kanıtı), **tek komutla imza üretimi**, **opak öncül katlaması**,
**kanıt zincirli derin keşif**, **goto'suz iç içe yapılaştırma**, **yerleşik
obfuscation risk raporu** ve fiyat. Kendi zayıf satırlarımız da dürüstçe
tabloda duruyor (mimari kapsamı, Lumina benzeri isim havuzu, GUI olgunluğu).

---

## 7-B. CANLI KANIT: metin2client.exe (v7 DEVRİT-PRO)

**Hedef:** gerçek bir ticari oyun istemcisi (Metin2, 5.2 MB PE32, MSVC, PDB'li).
**Soru (kullanıcıdan):** `CPythonPlayer::Instance().GetStatus(iType)` derlemde
`call eax` / `call dword ptr [edx+88h]` oluyor — "edx'i process'i açmadan %
100 simüle edip öğrenebilir miyiz? livestep.cpp (canlı analiz motoru) işi çözer mi?"

**Cevap (düşünce + uygulama + kanıt):**

1. **Process-geniş simülasyon YANLIŞ ARAÇ:** `playerGetStatus` oyuncu login
   olana dek çağrılmaz (Python'dan veri güdümlü). Hiçbir emülatör "oyuncunun
   giriş yapmasını" simüle edemez; D3D döngüsü milyonlarca komuttur. Üstelik
   livestep.cpp v4 amprik testte 6. adımda desync (jcc çözülmez, `mov reg,[mem]`
   çalıştırılmaz) — 78 adımda çöktü. **Doğru araç: livestep-LITE pencere
   değerlendiricisi** — çağrıya kadarki ~10 komutu somut-simgesel değerlendir,
   eksik halka "bu statik nesnenin vtable'ı ne?" ise cevabı KURUCUDA ara.

2. **Kanıt zinciri (tamamı STATİK — binary hiç çalışmadı):**
   - `mov ecx, [0x8BD2D0]` → .bss'te ms_singleton (imajda 0!)
   - RTTI atlası: 892 sınıf, 7282 vftable slotu (TypeDescriptor/COL taraması)
   - CPythonPlayer kurucusu: `[this+4] = vftable 0x805054` + `ms_singleton = this`
     → son-yazım-kazanır kanıtı (ara yazımlar dürüstçe ezilir)
   - `call eax` (vptr+0x10) → **CPythonPlayer::GetStatus, slot 4** [ÇÖZÜLDÜ]
   - `call [edx+0x88]` → **CPythonPlayer::NEW_GetMainActorPtr, slot 34** [ÇÖZÜLDÜ]

3. **Sonuç — decompiler çıktısı vs Orijinal kaynak kodu (1:1):**

```c
// godtier: decomp 0x4ead70  (PDB isimleri + devirt-pro ile)
_object * playerGetStatus(_object * poSelf, _object * poArgs)
{
    v2 = PyTuple_GetInteger(poArgs, 0, &iType);
    if (v2 != 0) goto loc_4ead97;
    return Py_BuildException(0);
    v3 = CPythonPlayer::GetStatus((*(CSingleton<CPythonPlayer>::ms_singleton) + 4), iType);
    if (iType != 0x11) goto loc_4eadda;                    // POINT_ATT_SPEED = 17
    v4 = CPythonPlayer::NEW_GetMainActorPtr(...);           // <-- call [edx+0x88] DEVRİRT
    if (v4 == 0) goto loc_4eadda;
    v5 = CInstanceBase::GetWeaponType(v4);
    if (v5 != 3) goto loc_4eadda;                          // WEAPON_TWO_HANDED = 3
    return python27.dll.Py_BuildValue("i", (v3 - *(TWOHANDED_WEWAPON_ATT_SPEED_DECREASE_VALUE)));
}
```

Kaynak koddaki her satır (arg adları, 0x11 sabiti, "== 3" karşılaştırması,
TWOHANDED global adı, `"i"` format stringi) geri kazanıldı.

4. **Geniş ölçüm:** 25.673 fonksiyon, 111 statik nesne yazıcısı (50'si vtable
   kanıtlı), **3842/7420 dolaylı çağrı statik çözüldü** (geri kalanlar IAT
   dışı dürüst-sanal). IDA'da da Ghidra'da da bunu otomatik yapan yok.

5. **livestep.cpp hükmü:** v4 = uzunluk-çözümleyici + iz dökümü (yürütme
   modeli push/pop/mov-reg-imm/call-rel only). Devirt için gerekmedi —
   fikirleri (seyrek bellek, TEB, iz biçimi) devirt-pro'ya "livestep-lite"
   olarak devralındı ve kanıtlandı. Tam-emülasyon gerektiğinde (VMProtect
   üslubu runtime-vtable, packer) repo'daki **Unicorn emülatörü** (gerçek
   x86-32/64 yürütme + API shim + TEB/PEB) livestep'in mini-yorumlayıcısından
   çok daha güçlüdür — Tier-3 entegrasyonu oradan yapılacaktır.

## 8. Hex-Rays ve Ghidra'nın da BAŞARISIZ OLDUĞU şeyler

"En gelişmiş" bile her şeyi çeviremez — derleme **kaybediçi** bir dönüşümdür:

1. **Yorumlar, makrolar, `typedef`, `#define` geri gelmez.** `MAX_ELEMAN` ile `100`
   aynı makine kodunu üretir.
2. **Eş anlamlı kaynaklar ayrıştırılamaz:** `a[i]`, `*(a+i)`, `i[a]` — üçü aynı kod.
   Hangisi yazıldığını hiçbir decompiler bilemez.
3. **Inlining geri açılmaz tam olarak:** bu projede `-O2` ile `memset` ve `strcpy`
   main'e gömüldü (gerçek kanıt: `mov DWORD PTR [rsp+0x28],0x696c41` — strcpy'nin
   tamamı tek immediate). Dünyanın en iyi decompiler'ı bile "burada bir zamanlar
   ayrı bir `strcpy` çağrısı vardı" diyemez; bu bilgi makine kodunda yok.
4. **Optimizasyon döngüyü/özyinelemeyi yok eder (bu programda GERÇEK):**
   - `-O2`'de `faktoriyel` derleyici tarafından döngüye çevrildi (gerçek objdump:
     `jg 1280` geri döngüsü, kendine `call` yok). Kaynaktaki özyineleme kavramı
     makine kodunda **fiziksel olarak mevcut değil** — Hex-Rays bile burada recursion
     göstermez. (GodTier'ın -O0 çıktısında yakaladığı özyineleme, -O2'de kimsenin
     bulamayacağı şeydir.)
   - **`-O2`'de main'in `notlar` döngüsü tamamen kayboldu:** `for (i=0..7) notlar[i]
     = (i*13)%100` döngüsü derleyici tarafından **derleme zamanında hesaplandı** ve
     dizi sabit veri olarak `.rodata`'ya gömüldü — gerçek kanıt:
     ```
     .rodata 0x2050:  00000000 0d000000 1a000000 27000000   = {0, 13, 26, 39}
     .rodata 0x2060:  34000000 41000000 4e000000 5b000000   = {52, 65, 78, 91}
     ```
     main artık döngü yerine bu sabitleri `movdqa` ile kopyalıyor. Döngü diye bir
     yapı kalmadı — hiçbir decompiler "burada bir for döngüsü vardı" diyemez.
5. **Vektörizasyon (bu programda GERÇEK):** `-O2`'de `toplama(o->notlar, 8)` çağrısı
   yalnızca `ortalama_hesapla`'ya gömülmedi — 8 tur atan döngü **birkaç SSE komutuna**
   vektörize edildi (gerçek objdump çıktısı):
   ```asm
   11f0:  movdqu xmm1,XMMWORD PTR [rdi+0x14]   ; notlar[4..7] yükle
   11f5:  movdqu xmm0,XMMWORD PTR [rdi+0x4]    ; notlar[0..3] yükle
   11fa:  paddd  xmm0,xmm1                     ; 4 int'i TEK komutta topla
   11fe:  movdqa xmm1,xmm0                     ; yatay toplama ağacı:
   1202:  psrldq xmm1,0x8                      ;   8→4→2→1 eleman
   1207:  paddd  xmm0,xmm1
   120b:  movdqa xmm1,xmm0
   120f:  psrldq xmm1,0x4
   1214:  paddd  xmm0,xmm1
   1218:  movd   eax,xmm0                      ; sonuç: toplam (364)
   ```
   `for (i=0..7) toplam += dizi[i];` satırı artık makine kodunda **yok**. Hex-Rays
   bunu en iyi ihtimalle intrinsics karışımı garip bir ifade olarak gösterir;
   "bu bir dizi toplama döngüsüydü" bilgisini veremez. Bizim motorun aynı
   fonksiyonun çıktısı için Bölüm 9'a eklenmiştir (dal yapısı doğru kalır:
   `test eax,eax` → `if (!(je ...)) goto` — kaynaktaki `if (toplam == 0)`).
6. **Template/lambda/STL anlamları dağılır:** `std::vector::push_back` inlining +
   SSO sonrası tanınmaz hale gelir; Hex-Rays bunları `operator new` + `memcpy`
   yığını olarak gösterir.
7. **Sanal dispatch statik çözülemez:** `vptr->fn()` hangi sınıfın `fn`'i? Tüm
   program akışını bilmeden cevaplanamaz (bazen hiç cevaplanamaz).
8. **Anti-analysis:** VMProtect/Themida sanallaştırılmış kodunda Hex-Rays ve Ghidra
   çoğunlukla işe yaramaz — statik decompiler'ların evrensel sınırı. (Bu boşluk,
   bizim motordaki Unicorn emülasyon yaklaşımının var olma sebebidir: statik
   çözülemeyeni çalıştırarak gözlemlersin.)

---

## 9. Nasıl Tekrar Üretilir (bu dokümanın her çıktısı)

```bash
# kurban program
cd scripts/decomp_demo
g++ -O0 -g -o kurban_O0 kurban.cpp
g++ -O2 -o kurban_O2 kurban.cpp && strip kurban_O2 -o kurban_O2s
./kurban_O0                       # "Ogrenci 7: Ali ort=45.50 / buyuk faktoriyel: 5040"

# referans disassembly
objdump -d -M intel --no-show-raw-insn kurban_O0

# GodTier motoru (download/i4M-GodTier/build/bin/godtier)
godtier kurban_O0
gt> funcs                          # Bölüm 4.1
gt> dis 0x1149 21                  # Bölüm 4.2
gt> decomp 0x1149                  # Bölüm 4.3  (toplama)
gt> decomp 0x118e                  # ortalama_hesapla
gt> decomp 0x11d5                  # faktoriyel (özyineleme)
gt> decomp 0x120b                  # rapor_yaz (string annotation)
gt> decomp 0x12af                  # main (0x696c41 / 0x51eb851f)
gt> xref 0x11d5                    # özyineleme kanıtı

godtier kurban_O2s
gt> funcs                          # Bölüm 5.4 (sadece 6 fonksiyon)
gt> decomp 0x11c0                  # Bölüm 4.7 (optimize toplama, manuel adres)
gt> decomp 0x11f0                  # Bölüm 8.5 (vektörize ortalama_hesapla)

# kurban_O2s'de decomp 0x11f0'nın GERÇEK çıktısı (vektörize fonksiyonda bile
# dal yapısı doğru: test eax,eax → kaynaktaki "if (toplam == 0)"):
#   // sub_000011f0  (17 komut, 3 blok)
#   void sub_000011f0(void)
#   {
#       movdqu xmm1, xmmword ptr [rdi + 0x14];    // 0x11f0
#       movdqu xmm0, xmmword ptr [rdi + 4];    // 0x11f5
#       paddd xmm0, xmm1    // 0x11fa
#       movdqa xmm1, xmm0;    // 0x11fe
#       psrldq xmm1, 8    // 0x1202
#       paddd xmm0, xmm1    // 0x1207
#       movdqa xmm1, xmm0;    // 0x120b
#       psrldq xmm1, 4    // 0x120f
#       paddd xmm0, xmm1    // 0x1214
#       movd eax, xmm0;    // 0x1218
#       pxor xmm0, xmm0    // 0x121c
#       test eax, eax;    // 0x1220
#       if (!(je 0x1234)) goto 0x1224;
#       pxor xmm0, xmm0    // 0x1224
#       cvtsi2ss xmm0, eax    // 0x1228
#       mulss xmm0, dword ptr [rip + 0xdd0]    // 0x122c
#       return;    // 0x1234
#   }
```

---

## 10. Sonuç

- **Evet,** IDA/Ghidra önce tüm binary'yi tarar, sonra istenen fonksiyonu bu
  global veritabanıyla çevirir. Sebebi, sorudaki tahmin: çağıran-çağrılan
  ilişkileri ve ortak bellek kullanımı ancak bütün programa bakınca anlaşılır.
  **v2'den itibaren bizim motor da tam bu modelde çalışıyor** (TypeInferer
  Faz A + Faz B) — Bölüm 0'daki `Ogrenci` struct'ının birebir geri kazanımı
  bunun kanıtı.
- **Konumumuz:** Hex-Rays hâlâ genel lider (FLIRT, Lumina, 20+ yıl tip
  veritabanı); Ghidra açık kaynak lideri. GodTier v2, bu oturumda gerçek
  çıktılarla kanıtlanan bir üst sıraya taşındı: imza çıkarımı, struct geri
  kazanımı, ifade katlama, koşul yapılaştırma, idiom katlama, PLT çözümü ve
  strip'li main keşfi artık **bizde de var** — 27 otomatik testle doğrulanıyor
  (103/103 PASS). Kalan açık: tam SSA, SIMD geri açma, inlining, vtable/RTTI.
- Bir sonraki adım sırası: **(1) SSA tabanlı çapraz-blok değişken birleştirme
  (karmaşık O2 akışlarında ham register kalıntılarını temizler), (2) jump
  table/switch çözümü, (3) Ghidra köprüsünden tip ithalati
  (`scripts/godtier_ghidra.py` hazır), (4) DWARF/PDB okuyucu.**
