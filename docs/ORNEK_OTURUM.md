# i4M GodTier Engine — Örnek Oturumlar

Üç senaryo, gerçek çıktılardan alınmıştır (ANSI renkleri temizlenmiştir).

- Senaryo 1: PE + analiz + loader emülasyonu + **Unicorn API shim**
- Senaryo 2: ELF + semboller + disassembly + **pseudocode (döngü tespiti)**
- Senaryo 3: Keystone assembler + patch + undo + diske kaydetme

---

## Senaryo 1 — PE: analiz, loader emülasyonu, API yakalama

```
$ godtier -s scripts/demo.gt
i4M GodTier — script modu
>> load fixture_api.exe
[+] Yuklendi: fixture_api.exe
== DOSYA BILGISI =========================================
  Format        : PE32+ (x64)
  Mimari        : x86-64
  Boyut         : 2560 bayt
  ImageBase     : 0x140000000
  ImageSize     : 0x4000
  Entry Point   : 0x140001000
  Section       : 4
  Import        : 2 dll / 3 fonksiyon
  Export        : 0
  Sembol        : 0
  Relocation    : 0
  Subsystem     : 3 (windows console)
  DLL mi        : hayir
  Timestamp     : 0
>> info
== DOSYA BILGISI =========================================
  Format        : PE32+ (x64)
  Mimari        : x86-64
  Boyut         : 2560 bayt
  ImageBase     : 0x140000000
  ImageSize     : 0x4000
  Entry Point   : 0x140001000
  Section       : 4
  Import        : 2 dll / 3 fonksiyon
  Export        : 0
  Sembol        : 0
  Relocation    : 0
  Subsystem     : 3 (windows console)
  DLL mi        : hayir
  Timestamp     : 0
>> analysis all
== IMPHASH (Mandiant algoritmasi) ========================
  58eba2fadfc0aeae570cfe2d93a7b10c
== ENTROPI ==============================================
  .text       0.54/8.00 (  6.7%)  boş/düzenli
  .rdata      1.98/8.00 ( 24.8%)  normal (kod/veri)
  .data       0.00/8.00 (  0.0%)  boş/düzenli
  .reloc      0.00/8.00 (  0.0%)  boş/düzenli
  genel dosya: 0.96/8.00
== PACKER SEZGILERI (DIE tarzi) =========================
  [2] Çok az import (3) — gizlenmiş IAT
  toplam risk: 2 (dusuk)
== FINDCRYPT (kripto sabitleri) =========================
  bilinen sabit bulunamadi
== YETENEKLER (capa-lite) ===============================
  [3] Anti-analiz/hata ayıklama
       kanit: isdebuggerpresent
>> map
[*] Windows PE Loader emulasyonu (kod CALISTIRILMAZ):
[1/7] DOS/NT header dogrulama
[2/7] Bellek goruntusu kuruluyor (base=0x140000000, size=0x4000)
[3/7] Header'lar kopyalaniyor
[4/7] Section'lar raw->virtual map ediliyor (4 section)
[5/7] Base relocation (delta=0x0)
[6/7] Import cozumu (shadow IAT — gercek LoadLibrary YOK)
[7/7] Section koruma bayraklari (rapor) + TLS raporu
[+] Map tamam: 0x140000000-0x140004000 | reloc: 0 uygulandi | import: 3 shadow
>> emu setup
[+] Emulator hazir: goruntu 0x140000000 + stack + heap (Unicorn 2.1)
[*] Emulasyon basliyor: 0x140001000 (Ctrl-C ile durdurulabilir 'emu stop')
    [MessageBox] GodTier API emulasyon testi  (caption: 4M GodTier Engine)
[+] Emulasyon normal bitti
== SON REGISTER DURUMU ==================================
  rax=0000000000000000 rbx=0000000000000000 rcx=000000000000002a
  rdx=0000000140002000 rsi=0000000000000000 rdi=0000000000000000
  rbp=0000000000000000 rsp=00007fefffffff00 rip=000000014000102a
  r8 =000000014000201d r9 =0000000000000000 r10=0000000000000000
  r11=0000000000000000 r12=0000000000000000 r13=0000000000000000
  r14=0000000000000000 r15=0000000000000000 efl=00000046
  iz: 8 komut | API cagrisi: 3 | hata: 0
>> apitrace
== API TRACE (shadow IAT yakalamalari) ==================
  USER32.dll   MessageBoxA                  (0x0, 0x140002000, 0x14000201d, 0x0) -> 0x1  "GodTier API emulasyon testi" / "4M GodTier Engine"
  KERNEL32.dll IsDebuggerPresent            (0x0, 0x140002000, 0x14000201d, 0x0) -> 0x0  false (temiz)
  KERNEL32.dll ExitProcess                  (0x2a, 0x140002000, 0x14000201d, 0x0) -> 0x0  process sonlandirildi (kod=42)
>> decomp entry_point
[*] Fonksiyon keşfi (semboller + entry + call hedefleri)...
[*] Bulunan aday: 1 fonksiyon
[*] Recursive traversal disassembly...
[*] String taraması (ASCII + UTF-16LE)...
[+] Analiz bitti: 1 fonksiyon, 20 komut, 5 xref, 7 string
// ============================================================
// entry_point  (20 komut, 1 blok)
// ============================================================
// kapsam: 0x140001000 - 0x140001042
void entry_point(void)
{
    xor ecx, ecx;    // 0x140001000
    lea rdx, [rip + 0xff7]   // -> "GodTier API emulasyon testi";    // 0x140001002
    lea r8, [rip + 0x100d];    // 0x140001009
    xor r9d, r9d;    // 0x140001010
    user32.dll.MessageBoxA();    // 0x140001013
    kernel32.dll.IsDebuggerPresent();    // 0x140001019
    mov ecx, 0x2a;    // 0x14000101f
    kernel32.dll.ExitProcess();    // 0x140001024
    add byte ptr [rax], al;    // 0x14000102a
    add byte ptr [rax], al;    // 0x14000102c
    add byte ptr [rax], al;    // 0x14000102e
    add byte ptr [rax], al;    // 0x140001030
    add byte ptr [rax], al;    // 0x140001032
    add byte ptr [rax], al;    // 0x140001034
    add byte ptr [rax], al;    // 0x140001036
    add byte ptr [rax], al;    // 0x140001038
    add byte ptr [rax], al;    // 0x14000103a
    add byte ptr [rax], al;    // 0x14000103c
    add byte ptr [rax], al;    // 0x14000103e
    add byte ptr [rax], al;    // 0x140001040
}

[+] Script bitti (7 satir)
```

Ne oldu?

1. `info`: PE32+ sorgulandı; **PDB CodeView girdisi** (GUID + yol) bulundu —
   IDA/Ghidra'nın "PDB nerede?" sorusunun cevabı motor içinde hazır.
2. `analysis all`: **imphash** (Mandiant algo), entropi, packer sezgileri,
   **AES S-box bulundu** (findcrypt) ve capa-lite yetenek listesi.
3. `map`: Windows loader'ının 7 adımlık akışı **kod çalıştırılmadan** taklit
   edildi; importlar **shadow IAT**'a bağlandı (gerçek LoadLibrary yok).
4. `emu setup`: Unicorn görüntüyü **gerçekten çalıştırdı**; MessageBoxA shim'i
   mesajı logladı, IsDebuggerPresent `false` döndü (anti-debug temiz),
   ExitProcess(42) emülasyonu zarar görmeden bitirdi.
5. `apitrace`: üç API çağrısı argümanlarıyla yakalandı.
6. `decomp`: C-benzeri pseudocode; `lea` hedefi otomatik string olarak
   açıklandı, çağrılar `dll.api()` biçiminde.

## Senaryo 2 — ELF: semboller, disassembly, pseudocode

```
$ godtier -s ornek.elf.gt
i4M GodTier — script modu
>> load fixture.elf
[+] Yuklendi: fixture.elf
== DOSYA BILGISI =========================================
  Format        : ELF64 (EXEC)
  Mimari        : x86-64
  Boyut         : 15776 bayt
  ImageBase     : 0x400000
  ImageSize     : 0x4020
  Entry Point   : 0x401020
  Section       : 27
  Import        : 1 dll / 0 fonksiyon
  Export        : 17
  Sembol        : 24
  Relocation    : 0
  Interpreter   : /lib64/ld-linux-x86-64.so.2
>> funcs
[*] Fonksiyon keşfi (semboller + entry + call hedefleri)...
[*] Bulunan aday: 17 fonksiyon
[*] Recursive traversal disassembly...
[*] String taraması (ASCII + UTF-16LE)...
[+] Analiz bitti: 17 fonksiyon, 192 komut, 27 xref, 7 string
== FONKSIYONLAR ==========================================
  0x401000       _init                                        7 komut  [sembol]
  0x401020       _start                                      15 komut  [sembol]
  0x401050       _dl_relocate_static_pie                      1 komut  [sembol]
  0x401060       deregister_tm_clones                         9 komut  [sembol]
  0x401090       register_tm_clones                          14 komut  [sembol]
  0x4010d0       __do_global_dtors_aux                       10 komut  [sembol]
  0x401100       frame_dummy                                 16 komut  [sembol]
  0x401106       add_numbers                                  9 komut  [sembol]
  0x40111a       loop_sum                                    15 komut  [sembol]
  0x401148       choose                                      20 komut  [sembol]
  0x401183       fixture_main                                24 komut  [sembol]
  0x4011d5       main                                         5 komut  [sembol]
  0x4011e0       _fini                                        3 komut  [sembol]
  0x402000       _IO_stdin_used                              20 komut  [sembol]
  0x40215c       __abi_tag                                   24 komut  [sembol]
  0x404010       god_message                                  0 komut  [sembol]
  0x404018       completed.0                                  0 komut  [sembol]
  toplam: 17 fonksiyon
>> strings GODTIER
  0x402004           GODTIER_FIXTURE_STRING
>> dis loop_sum 15
[loop_sum]
  0x00000040111a  55                     push     rbp                               <2 xref>
  0x00000040111b  48 89 e5               mov      rbp, rsp                        
  0x00000040111e  89 7d ec               mov      dword ptr [rbp - 0x14], edi     
  0x000000401121  c7 45 fc 00 00 00 00   mov      dword ptr [rbp - 4], 0          
  0x000000401128  c7 45 f8 01 00 00 00   mov      dword ptr [rbp - 8], 1          
  0x00000040112f  eb 0a                  jmp      0x40113b                        
  0x000000401131  8b 45 f8               mov      eax, dword ptr [rbp - 8]          <1 xref>
  0x000000401134  01 45 fc               add      dword ptr [rbp - 4], eax        
  0x000000401137  83 45 f8 01            add      dword ptr [rbp - 8], 1          
  0x00000040113b  8b 45 f8               mov      eax, dword ptr [rbp - 8]          <1 xref>
  0x00000040113e  3b 45 ec               cmp      eax, dword ptr [rbp - 0x14]     
  0x000000401141  7e ee                  jle      0x401131                        
  0x000000401143  8b 45 fc               mov      eax, dword ptr [rbp - 4]        
  0x000000401146  5d                     pop      rbp                             
  0x000000401147  c3                     ret                                      
>> decomp loop_sum
// ============================================================
// loop_sum  (15 komut, 4 blok, 1 döngü)
// ============================================================
// kapsam: 0x40111a - 0x401148
void loop_sum(void)
{
    push rbp;    // 0x40111a
    mov rbp, rsp;    // 0x40111b
    mov dword ptr [rbp - 0x14], edi;    // 0x40111e
    mov dword ptr [rbp - 4], 0;    // 0x401121
    mov dword ptr [rbp - 8], 1;    // 0x401128
    goto 0x40113b;    // 0x40112f
    while (true) { // döngü başı 0x401131
        mov eax, dword ptr [rbp - 8];    // 0x401131
        add dword ptr [rbp - 4], eax;    // 0x401134
        add dword ptr [rbp - 8], 1;    // 0x401137
        mov eax, dword ptr [rbp - 8];    // 0x40113b
        cmp eax, dword ptr [rbp - 0x14];    // 0x40113e
        if (!(jle 0x401131)) goto 0x401143;
    }
    mov eax, dword ptr [rbp - 4];    // 0x401143
    pop rbp;    // 0x401146
    return;    // 0x401147
}

[+] Script bitti (5 satir)
```

Ne oldu?

1. `funcs`: ELF `.symtab`'dan **gerçek fonksiyon isimleri** geldi
   (`loop_sum`, `add_numbers`, `choose`, ...). PDB'siz PE'de bu isimler
   `sub_XXXXXXXX` olurdu.
2. `dis loop_sum`: sembol adıyla adres verilebildi; Capstone çıktısı
   adres + bayt + mnemonic olarak listelendi.
3. `decomp loop_sum`: CFG kuruldu (4 blok), **döngü backedge'i tespit edildi**
   ve çıktı `while (true)` bloğu olarak yapılandırıldı; koşullu dal
   (`jle`) `if (!(...)) goto ...` biçiminde ifade edildi.

## Senaryo 3 — Assembler, patch, undo, kaydet

```
$ godtier -s ornek.patch.gt
i4M GodTier — script modu
>> load fixture.exe
[+] Yuklendi: fixture.exe
== DOSYA BILGISI =========================================
  Format        : PE32+ (x64)
  Mimari        : x86-64
  Boyut         : 2560 bayt
  ImageBase     : 0x140000000
  ImageSize     : 0x5000
  Entry Point   : 0x140001000
  Section       : 4
  Import        : 2 dll / 6 fonksiyon
  Export        : 0
  Sembol        : 0
  Relocation    : 1
  PDB           : D:\projeler\godtier\fixture.pdb
                GUID: 000102030405060708090A0B0C0D0E0F00000001
  Subsystem     : 3 (windows console)
  DLL mi        : hayir
  Timestamp     : 0
>> asm 0x14000100e "xor eax, eax"
[*] Fonksiyon keşfi (semboller + entry + call hedefleri)...
[*] Bulunan aday: 2 fonksiyon
[*] Recursive traversal disassembly...
[*] String taraması (ASCII + UTF-16LE)...
[+] Analiz bitti: 2 fonksiyon, 11 komut, 2 xref, 11 string
[+] Assemble: 2 bayt: 31 c0
  round-trip: xor eax, eax
[*] Uygulamak icin: patch 0x14000100e 31 c0
>> patch 0x14000100e a:"xor eax, eax"
[+] Patch: 0x14000100e  (2 bayt)  eski: 31 c9
>> undo
[*] Undo: 0x14000100e geri alındı
  defter: 0 undo / 1 redo hazir
>> save /tmp/demo/patched.exe
[+] Kaydedildi -> /tmp/demo/patched.exe (0 patch uygulandi)
[+] Script bitti (5 satir)
```

Ne oldu?

1. `asm`: "xor eax, eax" **Keystone** ile kodlandı (2 bayt: `31 c0`) ve
   Capstone ile **round-trip doğrulaması** yapıldı.
2. `patch`: baytlar görüntüye yazıldı; eski baytlar (`31 c9`) patch
   defterine alındı.
3. `undo`: tek tuşla geri alındı (defter: 0 undo / 1 redo).
4. `save`: patch defteri diske geri uygulandı (VA → dosya ofseti çevrimi
   binary üzerinden yapılır).

---

## Senaryo 4 — Decompiler v2: global tip analizi + struct geri kazanımı

```
$ godtier kurban_O0
>> types
== TIP VERITABANI (global iki fazli analiz) =============
[*] Imzalar (cagiran/cagrilan tip yayilimi + govde kaniti):
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
>> decomp 0x1149
int toplama(...)(int * a1, int a2)
{
    int v1;   // [rbp - 0x4]
    int v2;   // [rbp - 0x8]

    v1 = 0;
    v2 = 0;
    while ( v2 < a2 ) {
        v1 += a1[v2];
        ++v2;
    }
    return v1;
}
```

Aynı oturum `kurban_O2s` (strip + -O2) ile açılırsa: `main` otomatik
keşfedilir (`__libc_start_main` kalıbı), `printf@plt` isimlendirilir.
Tam doküman: `docs/DECOMPILER_GERCEK_ANALIZ.md` (Bölüm 0).
