# i4M GodTier Engine — MEGA GOD SSS TIER Binary Analiz Motoru

```
  ____        ______                    _____            _        _
 |_  /  ___  |_   _|_ __ _   _ ___    |_   _|_ __  ___| |_ __ _| |__ | | ___
  / /  / _ \   | |/ _| '_ \ / | '_ \____| || '_ \/ _ \ __/ _` | '_ \| |/ _ \
 / /__| (_) |  | | (_| | | | \ | | |_____| || | |\\  __/ || (_| | |_) | |  __/
/____|\___/   |_|\__,_| |_| |_|_|_|    |_||_| |_|\\___|\__\__,_|_.__/|_|\___|
        MEGA GOD SSS TIER Binary Analiz Motoru  |  Capstone + Keystone + Unicorn
```

i4M ekosisteminin yeni nesli: **i4MConsoleLoader**'ın tüm çekirdek yetenekleri
(PE parser, manual mapper, disassembler, patch, process araçları) alındı;
GitHub'daki en iyi açık kaynak projelerin ödüllü özellikleriyle birleştirildi
ve **cross-platform** (Windows + Linux) tek bir C++ motorunda birleştirildi.

> Araştırma ve puanlama: bu depoyla birlikte gelen
> `GitHub_Analiz_Puanlama_TierListesi.xlsx` (38 GitHub projesi + IDA Pro 9.5 +
> Binary Ninja + Ghidra 12.2 karşılaştırmalı, ağırlıklı 10 boyutlu puanlama).

---

## GOD TIER Özellikler

| Modül | Yetenek | İlham Kaynağı |
|---|---|---|
| **format** | PE32/PE32+ tam parser: section, import/export, reloc, TLS, delay-load, **rich header**, **PDB GUID tespiti**, COFF sembolleri (MinGW) | LIEF, pe-parse, PE-bear, pefile |
| **format** | ELF32/64 parser: segment, section, symtab/dynsym, dinamik | LIEF, angr/CLE |
| **disasm** | Capstone sarmalayıcı + recursive traversal + fonksiyon keşfi (sembol/entry/call hedefi) + xref DB (call/jmp/jcc/data) + ASCII & UTF-16 string tarama | Capstone, rizin, FLOSS |
| **asm** | **Keystone tabanlı gerçek assembler** — eski el yapımı assembler'ın yerine + round-trip doğrulama + sınırsız undo/redo patch defteri | Keystone, x64dbg |
| **mapper** | **Cross-platform Windows loader emülasyonu**: 7 adımlı akış, elle reloc (DIR64/HIGHLOW), **shadow IAT** (gerçek LoadLibrary YOK — Linux'ta da çalışır!), TLS raporu | libpeconv, i4M PEManualMapper, Qiling |
| **emulate** | **Unicorn ile kod gerçekten çalışır**: instruction trace, bellek erişim günlüğü, PEB/TEB-lite, stack/heap, **API shim** (MessageBoxA, ExitProcess, HeapAlloc, IsDebuggerPresent=false, ...) + apitrace | Unicorn, Speakeasy, Qiling |
| **decomp** | CFG kurulumu (basic block + kenarlar), **döngü tespiti** (while), C-benzeri pseudocode üretici (API çağrıları `dll.api(arg...)` olarak), RetDec/Ghidra headless köprüleri | Ghidra decompiler, angr, RetDec, IDA üslubu |
| **analysis** | **imphash (pefile ile birebir aynı — testle kanıtlı)**, bölüm entropisi, packer sezgileri (DIE tarzı 6 kural), **findcrypt** (AES/RC4/MD5/SHA/CRC32 sabitleri), capa-lite yetenek çıkarımı | Mandiant capa/FLOSS, YARA, PE-bear, findcrypt |
| **proc** | Process bellek erişimi: **Windows** ReadProcessMemory + **Linux** /proc/pid/mem + modül listesi | x64dbg, pwndbg, i4M InstanceManager |
| **ui** | Renkli komut kabuğu (rizin tarzı) + klasik i4M numaralı menü + batch script modu | rizin, i4M konsol |
| **gui** | ImGui (docking) + SDL2 arayüz: dockspace, disasm/pseudocode/hex/emülatör/analiz panelleri, konsol | Cutter, IDA, eski i4MGUILoader |

## Hızlı Başlangıç

### Linux (kutudan çıktığı gibi — third_party hazır)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/bin/godtier                    # interaktif kabuk
./build/bin/godtier fixture_api.exe    # dosyayla başla
./build/bin/godtier -s scripts/demo.gt # script modu
./build/bin/godtier_tests              # 76 test (hepsi geçmeli)
```

### Windows (Visual Studio 2019/2022)

1. `third_party/lib/` altına x64 kütüphaneleri koyun:
   `capstone.lib` (veya dll+kütüphane), `unicorn.lib`, `keystone.lib`
   (+ varsa `.dll` dosyaları — bin/ yanına otomatik kopyalanır).
   İndirme: [capstone releases](https://github.com/capstone-engine/capstone/releases),
   [unicorn releases](https://github.com/unicorn-engine/unicorn/releases),
   [keystone](https://github.com/keystone-engine/keystone/releases).
2. `cmake -B build -G "Visual Studio 17 2022" -A x64` + derleyin.
3. Alternatif: sistem kuruluysa `find_package` otomatik bulur.

### GUI (opsiyonel)

```bash
cmake -B build-gui -DGODTIER_GUI=ON    # SDL2 + ImGui docking otomatik çekilir
cmake --build build-gui -j
./build-gui/bin/godtier_gui
```

## Örnek Oturum

```
gt> load fixture_api.exe
[+] Yuklendi: fixture_api.exe
    PDB: D:\projeler\godtier\fixture.pdb  GUID: 000102...0001
gt> map                          # Windows loader emülasyonu (kod çalışmaz)
[1/7] DOS/NT header dogrulama ... [6/7] Import cozumu (shadow IAT)
[+] Map tamam: 0x140000000-0x140004000 | import: 3 shadow
gt> emu setup                    # Unicorn ile GERÇEKTEN çalıştır
[MessageBox] (caption: GodTier API emulasyon testi)
[+] Emulasyon normal bitti
gt> apitrace
  USER32.dll   MessageBoxA      -> 0x1  "GodTier API emulasyon testi"
  KERNEL32.dll IsDebuggerPresent -> 0x0  false (temiz)
  KERNEL32.dll ExitProcess      (0x2a)  process sonlandirildi (kod=42)
gt> types                         # global tip veritabani (imzalar + struct'lar)
gt> decomp loop_sum              # Hex-Rays uslubi pseudocode (v2)
void loop_sum(void) { ... while (true) { // döngü başı ...
```

Tam oturum: `docs/ORNEK_OTURUM.md` — Mimari: `docs/MIMARI.md`
Decompiler derin analizi (gerçek kaynak → disassembly → pseudocode zinciri,
IDA/Ghidra karşılaştırması): `docs/DECOMPILER_GERCEK_ANALIZ.md` —
yeniden üretme script'i: `scripts/decomp_demo/decomp_demo.gt`

## Decompiler v6 (askeri seviye)

Iki fazli global analiz — IDA/Ghidra modeli.

- **v8.1 vfN SÖZLÜĞÜ + MEKANİZMA KIRILIMI (metin2client.exe'de ÖLÇÜLMÜŞ):**
  PDB'siz çıktıda `vf4`/`vf34` adlarının NE olduğu artık kanıt koordinatlarıyla yazılıyor —
  çağrının yanında ve fonksiyon-sonu sözlüğünde: `// vf4 = CPythonPlayer
  vftable[0x805054] + 0x10 -> 0x4e2f60` (vfN = vtable slot N; x86-32 ofseti 4×N).
  Yeni `devirt stats` komutu "4444/9160 çözüldü" sayısının İÇ YAPISINI döker:
  kurucu-kanıt 245, atlas inversiyonu 236, tier-3 unicorn 256, IAT import 3222,
  vtable'sız somut 485; kalan 4716 = 4117 tier-3-pencere (tohum yok) + 471
  kanıt-yok (heap/param alıcı) + 128 dürüst çoklu-aday. Çözülemeyenlerin
  tamamı neden-etiketli; tekil spekülatif tahmin sıfır. Test: 319/319.
- **v8 DEVRİT TIER-3 + İNVERSİYON + INSTANCE() (metin2client.exe'de KANITLI —
  `docs/DEVRIT_V8_CANLI_KANIT.md`):**
  **TIER-3 Unicorn tohumlu pencere emülasyonu** (`src/decomp/devirtemu.cpp` —
  livestep.cpp vizyonunun doğru ölçekte gerçekleştirilmesi: dolaylı çağrının
  temel bloğu GERÇEK x86 semantiğiyle koşar, runtime vptr'ler kurucu-kanıt
  TOHUMLARIYLA verilir — process ÇALIŞMAZ; çoklu vtable adayında her aday AYRI
  pass'te koşar, hepsi aynı hedefe giderse KANITLANMIŞ çözüm), **atlas
  inversiyonu** (metot → sahip vftable'lar: sanal metod gövdesinde this'in
  dinamik tipi kanıtlanır — CHA), **RTTI-güdümlü fonksiyon keşfi** (vtable
  slotları: +3033 sanal metod), **Instance() katlaması** (`mov ecx,[ms_singleton];
  add ecx,4; mov eax,[ecx]...` → `CPythonPlayer::Instance().GetStatus(iType)`
  — kaynak kodla 1:1) ve **metot sözdizimi** (`v4->GetWeaponType()`).
  Gerçek binary: **4444/9160** dolaylı çağrı statik çözüldü (tier-3 unicorn:
  +256), `playerGetStatus` PDB'li VE PDB'siz kaynak kodla 1:1.
- **v7 DEVRİT-PRO + x86-32 DECOMPILER (metin2client.exe'de KANITLI):**
  **MSVC RTTI atlası** (`rtti` — sembolsüz PE32/PE64'te TypeDescriptor/COL/
  vftable taraması: sınıf evreni + slot tablosu + kalıtım), **DEVRİT-PRO**
  (`devirt [adres]` — pencere değerlendiricisi [livestep-lite]: `call
  [edx+0x88]` üslubu dolaylı çağrıları kurucu vtable-kanıtıyla STATİK çözer,
  IAT importlarını `dll.api` isimlendirir, çok-impl slot dürüstçe aday
  listesiyle sanal kalır), **x86-32 decompiler** (cdecl/thiscall arg kurtarma,
  ertelenmiş çağrı malzemeleşmesi — her çağrı TEK sefer basılır, kısa string
  sabitleri, PDB isim entegrasyonu). Gerçek binary: 892 sınıf, 3842/7420
  dolaylı çağrı statik çözüldü; `playerGetStatus` kaynak kodla 1:1
- **v6 ÇIKTI KALİTESİ:** işaretli pretty-print (`0xffffffff` → `-1`),
  **authoritative DWARF struct giydirme** (parametre tipi biliniyorsa sahte
  struct_N/FILE bağını devralır; belirsizse giydirmekten vazgeçer), -O2 ileri
  referanslı üye tiplerinin ertelenmiş çözümü, SIMD rodata-sabitli store'ların
  4 üye atamasına geri açılması, sahte-döngü koruması + çok-öncül phi mirası
- **v6 ÇOKLU MİMARİ:** x86-64/x86-32 decompiler + **ARM64/ARM32 analiz hattı**
  (BL keşfi, cbz/b.cond kenarları, adr string-xref — cross-compiler'sız
  elle kodlanmış fixture'larla testli)
- **v6 HAZIR İMZA HAVUZU:** `sigs/libc_x64.gsig` (2208 imza) — `load`
  komutunda OTOMATİK uygulanır; `sig export` ile TEK KOMUTLA üretilir/genişletilir
- **v6 LUMINA-LITE:** `lumina push/pull` — birikimli yerel isim havuzu (bulut YOK)
- **v6 SCRIPT API:** `$değişken`, `set` (tam öncelikli aritmetik), `eval`,
  `echo`, `if <kosul> : <komut>` (iç içe koşullar)
- **v5:** phi-SSA (döngü-taşıyıcı + cmov), SIMD lane skaler geri açma,
  CHA devirtualizasyon, süper blok birleştirme
- **v4:** derin fonksiyon keşfi, FLIRT-tarzı `.gsig`, opak öncül katlaması,
  goto'suz iç içe yapılaştırma

1. **Faz A (gövde):** arg canliligi (tanim-once-kullanim) -> arg sayisi;
   ret aninda eax/xmm0 kaniti -> donus tipi; pointer kokeni (provenance)
   izleme -> bellek erisimleri (offset/boyut/float/index-stride).
2. **Faz B (global):** cagri grafiginde tip yayilimi; union-find ile ayni
   nesneye bakan yerlerin kumesi; libc imza tablosu; >=2 offsetli kume ->
   **struct geri kazanimi**.
3. **Pseudocoder v2:** register dataflow ile ifade katlama (7 komut -> tek
   satir), while/do-while/if-else yapilastirma, magic-number bolme + `%`
   idiom katlama, SysV+Win64 cagri kurallari, ELF PLT/GOT isim cozumu,
   strip'li binary'de `__libc_start_main` kalibindan main kesfi.

Ornek (gercek cikti — tests/fixtures/kurban.elf, 27 otomatik dogrulama):

```c
int toplama(int * a1, int a2)
{
    int v1; int v2;
    v1 = 0; v2 = 0;
    while ( v2 < a2 ) { v1 += a1[v2]; ++v2; }
    return v1;
}
// ve otomatik geri kazanilan struct:
struct struct_1 { int field_0; int field_4[]; float field_24; char field_28[24]; };
```

## Komut Referansı (kısa)

```
load/info/sections/imports/exports/strings/pdb/save
funcs/dis/xref/decomp [adres|all]          types   # imza+struct veritabani
deep [apply]          # v4: derin kesfi
sig [export|import <f>|auto|stats]   # v4+v6: imza motoru + havuzlar
lumina [push|pull]    # v6: birikimli isim havuzu
obfus                 # v4: obfuscation risk raporu
find hex|imm|str|asm  # v4: arama
analysis [all|imphash|entropy|packer|crypto|capa]
asm <adres> "kod"   patch <adres> b:..|a:  hex [adres] [satir]   undo/redo
map  maplog  dump                            # loader emulasyonu
emu [setup [adres]|step|stop|mem]  regs  apitrace  trace [n]
proc list|attach|modules|read|write|detach   bridge retdec|ghidra
script <dosya.gt>    # v6: $degisken + set/eval/echo/if kosullu script dili
menu  help  quit
```

## Testler

```bash
$ ./build/bin/godtier_tests
[1] MD5 ... [2] Entropy ... [3] Keystone + Capstone round-trip
[4] ELF parser + analyzer + decompiler (gerçek gcc binary'si)
[5] PE parser (elle üretilmiş fixture, pefile ile ÇAPRAZ DOĞRULANMIŞ)
[6] Mapper (forceBase ile reloc testi) + Unicorn emülasyonu (rax=0x3c, loop=55)
[6b] API shim: MessageBoxA + IsDebuggerPresent + ExitProcess
[7] PatchBook (undo/redo)   [8] ProcessAccess (/proc)
[25] v7: RTTI atlası + devirt-pro + x86-32 (fixture_devirt.exe)
[26] v8: tier-3 unicorn + atlas inversiyonu + Instance() katlaması
     [26b] v8.1: vfN sozlugu + mekanizma kirilimi (tutarlilik: kategori
           toplamlari = evren; vf4/vf34/vf2 sozluk notlari; devirt stats)
== SONUC: 319 PASS, 0 FAIL ==   (189 tanesi decompiler v2..v8 dogrulamasi:
                                 DWARF/PDB import, jump table, vtable, switch,
                                 gercek param/uye adlari + derin fonksiyon kesfi,
                                 imza motoru (.gsig) + libc havuzu + lumina,
                                 opaque predicate katlamasi, goto'suz ic ice
                                 yapilastirma, phi-SSA (dongu-tasiyici + cmov),
                                 SIMD lane skaler geri acma + DWARF struct
                                 giydirme (o->notlar[k]), CHA devirtualizasyon,
                                 super blok birlestirme, ARM64/ARM32 analiz,
                                 tier-3 unicorn pencere emulasyonu (lineer
                                 degerlendiricinin COZEMEDIGI vaka) —
                                 hepsi GERCEK binary uzerinde)
```

imphash çapraz doğrulaması: GodTier'ın ürettiği özet, Python `pefile`
kütüphanesinin `get_imphash()` sonucuyla **birebir aynıdır** (testte sabit
referans değer olarak gömülüdür).

## Proje Yapısı

```
i4M-GodTier/
├── CMakeLists.txt
├── src/
│   ├── core/        types, renkli log, util (MD5/entropi/demangle-lite)
│   ├── format/      binary.h (soyut), pe, elf, image (MappedImage)
│   ├── disasm/      engine (Capstone), analyzer (fonksiyon/xref/string)
│   ├── asm/         assembler (Keystone) + PatchBook
│   ├── mapper/      cross-platform loader emülasyonu + shadow IAT
│   ├── emulate/     emulator (Unicorn) + apishim (Windows API sahtesi)
│   ├── decomp/      cfg + pseudocode v2 + types (TypeInferer) + köprüler
│   ├── analysis/    imphash, entropi, packer, findcrypt, capa-lite
│   ├── proc/        process erişimi (Win32 + /proc)
│   ├── ui/          shell (3 dosya: dosya/analiz/sistem komutları)
│   └── main.cpp
├── gui/             godtier_gui.cpp (ImGui docking + SDL2 renderer)
├── sigs/            libc_x64.gsig — 2208 imzalı hazır havuz (load'ta otomatik)
├── scripts/         godtier_ghidra.py (headless köprü), demo*.gt,
│                    decomp_demo/ (kurban.cpp + gerçek-çıktı demo script'i)
├── tests/           test_main.cpp + fixtures (kaynak + üreticiler)
├── docs/            MIMARI.md, ORNEK_OTURUM.md, DECOMPILER_GERCEK_ANALIZ.md
└── third_party/     include/ + lib/ (Linux .so hazır; Windows .lib koyulur)
```

## Lisans ve Krediler

- GodTier motoru: i4M ekosistemi (özgün kod).
- **Capstone** (BSD-3) — disassembly motoru
- **Unicorn** (GPLv2) — CPU emülasyonu (QEMU türevi)
- **Keystone** (GPLv2) — assembler motoru
- **ImGui** (MIT) + **SDL2** (zlib) — GUI
- Araştırma bazları: **IDA Pro 9.5**, **Ghidra 12.2**, **Binary Ninja**
  (karşılaştırma xlsx'inde).

> Not: Unicorn/Keystone GPLv2'dir; GodTier'ı kapalı kaynak ürüne gömerken
> bu bağımlılıkların lisans koşullarına uygun davranın (motor arayüzü
> soyutlanmıştır, alternatif motor takılabilir).

## i4MConsoleLoader'dan Farklar

| Eski (i4MConsoleLoader) | Yeni (i4M GodTier) |
|---|---|
| Sadece Windows (VirtualAlloc/LoadLibrary) | Windows + Linux (elle reloc, shadow IAT) |
| Yalnız PE | PE + ELF + ham shellcode |
| Capstone yalnız dosya görünümünde | Mapped görüntüde recursive traversal + xref + string |
| Elle yazılmış mini assembler (5-6 komut) | Keystone — tam x86/x64 |
| Kod çalıştırma yok | **Unicorn: gerçek emülasyon + API shim + trace** |
| Decompiler yok | CFG + pseudocode + RetDec/Ghidra köprüsü |
| imphash/entropi/findcrypt yok | Hepsi + capa-lite |
| GUI silinmiş durumda | ImGui docking GUI (opsiyonel hedef) |
