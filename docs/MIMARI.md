# i4M GodTier Engine — Mimari Doküman

Bu doküman, GodTier motorunun katman yapısını, veri akışını ve her modülün
hangi araştırma bulgusuna dayandığını anlatır. Puanlama detayları için
`GitHub_Analiz_Puanlama_TierListesi.xlsx` dosyasına bakın.

## 1. Katmanlı Mimari

```
┌─────────────────────────────────────────────────────────────────┐
│  SUNUM KATMANI                                                  │
│  ui/shell (CLI kabuk + menü)     gui/godtier_gui (ImGui+SDL2)   │
├─────────────────────────────────────────────────────────────────┤
│  ANALİZ KATMANI                                                  │
│  disasm/analyzer   decomp/cfg+ pseudocode   analysis/features   │
│  (fonksiyon/xref/  (basic block, döngü,     (imphash/entropi/   │
│   string keşfi)     C-benzeri çıktı)         packer/findcrypt)  │
├─────────────────────────────────────────────────────────────────┤
│  YÜRÜTME KATMANI                                                 │
│  mapper (loader emülasyonu)      emulate/emulator (Unicorn)     │
│  reloc + shadow IAT              + apishim (Windows API sahtesi) │
├─────────────────────────────────────────────────────────────────┤
│  FORMAT KATMANI                                                  │
│  format/binary.h (soyut arayüz)  format/pe   format/elf          │
│  format/image (MappedImage: sanal bellek görüntüsü)              │
├─────────────────────────────────────────────────────────────────┤
│  ÇEKİRDEK                                                        │
│  core/types  core/log  core/util (MD5, entropi, demangle-lite)   │
├─────────────────────────────────────────────────────────────────┤
│  MOTORLAR (third_party)                                          │
│  Capstone (disasm)   Keystone (asm)   Unicorn (emülasyon)        │
└─────────────────────────────────────────────────────────────────┘
```

Tasarım ilkesi: **üst katmanlar format bilmez**. `Binary` soyutlaması
(binary.h) PE ve ELF'i tek arayüzde birleştirir (LIEF dersi); Analyzer,
Pseudocoder, Emulator yalnız `MappedImage` + `Binary` üzerinden çalışır.

## 2. Veri Akışı (ana senaryolar)

### 2.1 Statik analiz

```
dosya → Binary::Open (MZ/ELF koklama)
      → PE/ELF parser (header/section/import/export/reloc/sembol)
      → MappedImage (raw → sanal görüntü)
      → Analyzer::RunFull
           ├─ DiscoverFunctions   (semboller + entry + call hedefi taraması)
           ├─ DisassembleFunction (recursive traversal; kuyruk tabanlı)
           ├─ xref kayıtları      (call/jmp/jcc/data; IAT yuvaları çözülür)
           └─ ExtractStrings      (ASCII + UTF-16LE; bölüm sonu flush)
      → Pseudocoder::DecompileFunction
           ├─ CFG::Build          (liderler → basic block'lar → kenarlar)
           ├─ DetectLoops         (backedge → while/do-while)
           └─ kalıp kütüphanesi   (mov rcx,imm+call → API(arg...))
```

### 2.2 Loader emülasyonu (Windows'un dosya→bellek akışı)

```
MapPE (mapper/mapper.cpp) — 7 adım, i4M PEManualMapper'ın cross-platform hali:
 [1/7] DOS/NT doğrulama
 [2/7] Görüntü kurulumu        (VirtualAlloc YOK — MappedImage vektörü)
 [3/7] Header kopyalama
 [4/7] Section raw→virtual map
 [5/7] Base relocation         (ELLE: DIR64=tip10, HIGHLOW=tip3;
                                hedef = reloc_va + delta  ← yeni taban)
 [6/7] Shadow IAT              (her import → 0x77000000 bölgesinde sahte adres;
                                LoadLibrary YOK — Qiling/Speakeasy yaklaşımı)
 [7/7] Koruma bayrağı raporu + TLS callback listesi (ÇALIŞTIRILMAZ)
```

`forceBase` ile farklı taban verildiğinde delta uygulanır ve reloc'lar
gerçekten test edilir (bkz. test [6]: 0x140003000 → 0x150003000).

### 2.3 Dinamik analiz (Unicorn + API shim)

```
Emulator::Setup
  ├─ görüntüyü emülatör belleğine map et (sayfa hizalı)
  ├─ shadow IAT bölgesi: her stub 1 bayt 0xC3 (ret)
  ├─ stack (1 MB) + magic dönüş sayfası (ana akış ret'i buraya düşer)
  ├─ heap (bump allocator — HeapAlloc shim'i bunu kullanır)
  ├─ TEB/PEB-lite + GS base (fs:[0]/gs:[0] erişimleri çökmez)
  └─ hook'lar: UC_HOOK_CODE (trace + shim), MEM_INVALID (hata raporu),
               MEM_READ/WRITE (bellek günlüğü)

Emulator::Run
  └─ HookCode: shadow adrese düşülünce ApiShim::Handle
        ├─ argümanlar (rcx/rdx/r8/r9) okunur
        ├─ shim davranışı (MessageBoxA: log+IDOK, ExitProcess: dur,
        │   IsDebuggerPresent: false, HeapAlloc: heap'den ayır, ...)
        ├─ RAX = dönüş, RIP = [RSP] (ret taklidi), RSP += 8
        └─ stop gerekiyorsa uc_emu_stop
```

## 3. Modül Detayları ve Araştırma Kökleri

| Modül | Dosya(lar) | Kök proje | Neden bu yaklaşım |
|---|---|---|---|
| PE parser | format/pe | pefile, pe-parse, PE-bear | pefile davranışı referans (imphash birebir); PE-bear'ın rich header/PDB görünümü |
| ELF parser | format/elf | LIEF, angr/CLE | çoklu format tek API; sembol tabloları analizin tohumu |
| MappedImage | format/image | i4M MemImage | orijinal sınıfın platform-bağımsızlaştırılmış hali |
| Analyzer | disasm/analyzer | rizin, FLOSS | call-hedefi taraması + recursive traversal (angr/rizin standardı) |
| Assembler | asm/assembler | Keystone | elle opcode üretimi bakım kabusu; Keystone Capstone'un kardeşi |
| Mapper | mapper | libpeconv, Qiling | libpeconv = i4M ile aynı soydan; shadow IAT fikri Qiling/Speakeasy |
| Emulator | emulate | Unicorn, Speakeasy | Unicorn = emülasyon standardı (Frida/Qiling/angr altında o da var) |
| API shim | emulate/apishim | Speakeasy, capa gözlemi | argümanlı çağrı günlüğü + gerçekçi dönüş değerleri |
| CFG | decomp/cfg | Ghidra decompiler | lider/blok/kenar modeli Ghidra'nın "structuring" ön adımı |
| Pseudocode | decomp/pseudocode | IDA Hex-Rays üslubu | hedef "okunabilir taslak"; dürüst sınırlar |
| Features | analysis/features | capa, FLOSS, YARA, findcrypt, DIE | imphash=Mandiant algo (pefile eşleşmeli); packer kuralları DIE tarzı |
| Process | proc/process | x64dbg, pwndbg | Win32 RPM + Linux /proc ikiz arayüz |
| Shell | ui/shell* | rizin komut dili | kestirme komut adları (dis/pd, hex/px, xref/xt) |
| GUI | gui | ImGui docking + SDL2 | SDL_Renderer: OpenGL başlığı gerektirmez → her yerde derlenir |

## 4. Önemli Tasarım Kararları

1. **Shadow IAT (0x77000000)**: Import çözümünde gerçek DLL yüklenmez.
   Her import, emülatör belleğindeki sabit bir sahte adrese bağlanır.
   Kod bu adrese `call` edince HookCode shim'i tetikler. Sonuç: Windows
   PE'si **Linux'ta bile** emüle edilebilir; ayrıca hiçbir gerçek kod
   (LoadLibrary/GetProcAddress) çalışmaz — tam izole analiz.

2. **Relocation elle uygulanır**: Windows loader'ının
   LdrRelocateImageWithBias adımı birebir taklit edilir (DIR64/HIGHLOW);
   işletim sisteminden medet umulmaz. forceBase ile test edilir.

3. **Magic dönüş sayfası**: Ana akışın `ret`'i, stack'e yazılan sihirli
   adrese düşer; HookCode bunu görür ve emülasyonu "normal bitti" olarak
   kapatır. ExitProcess shim'i de aynı şekilde durur.

4. **Anti-analiz temizliği**: `IsDebuggerPresent → false`, `PEB.BeingDebugged
   = 0`. Analiz edilen kodun anti-debug kontrolleri yanıltılır (Speakeasy
   davranışı).

5. **Dürüst pseudocode**: Bu bir Hex-Rays değil; CFG + döngü/if iskeleti +
   API çağrı açıklamaları üretir. Derin veri-tipi kurtarma için RetDec/Ghidra
   köprüleri vardır (`bridge retdec|ghidra`).

6. **imphash çapraz doğrulaması**: MD5 implementasyonumuz RFC 1321'e
   göredir; imphash algoritması pefile kaynak kodundan birebir taşınmıştır
   (uzantı soyumu, sıralama yok) ve üretilen özet pefile çıktısıyla aynıdır.

## 5. Genişletme Noktaları

- **Yeni mimari**: `DisasmEngine::Init`/`Emulator::Setup` içindeki
  CS/UC arch seçimine ARM/ARM64 eklemek yeterli başlangıçtır (Capstone ve
  Unicorn çok mimarilidir).
- **Yeni API shim'i**: `ApiShim::Handle` içine yeni `lname == "..."`
  dalı ekleyin.
- **Yeni format**: `Binary` türet (ör. Mach-O) — üst katmanlar hiç
  değişmeden çalışır.
- **PDB sembolleri**: `PE::GetDebugInfo` PDB GUID+path'i verir;
  `llvm-pdbutil` köprüsü eklenebilir (shell'de `pdb` komutu yol gösterir).
- **GUI**: `GuiApp::UiXxx` panelleri Shell komutlarını sürer; yeni panel
  = yeni komut.
