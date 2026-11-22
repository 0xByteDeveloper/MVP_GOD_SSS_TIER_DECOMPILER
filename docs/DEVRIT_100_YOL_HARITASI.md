# DEVRİT %100 YOL HARİTASI — v8 Sonrası: Eksikler, Dünya Araştırması ve v9+ Planı

> **REVİZYON NOTU (2026-11-22, 4-AI sentezi sonrası):** Bu dokümandaki "%100 statik imkansız"
> çerçevesi, sabit bir binary + kapalı sınıf evreni için fazla güçlü bulundu ve
> `DEVRIT_V9_KARAR_PLANI.md` içinde revize edildi (kullanıcının ağ-value/vptr-kurucu kanıtı
> üzerine). Ayrıca bu turda gözden kaçan 5 doğruluk (soundness) hatası — RestoreDirty 64B,
> MemLog 65536, x64 `rip` yazım atlaması, `off==0` kısıtı, tail-call evren eksikliği — sonraki
> analizlerde tespit edildi ve karar planının Faz 0'ını oluşturdu. Öncelik sıralaması için
> yeni doküman esas alınmalıdır; buradaki kök-neden haritası (§3) ve dünya turu (§4) geçerliliğini korur.

> Kapsam: `i4M-GodTier` v8 (`bb40b88`) sonrası "%100 devirtualizasyon" hedefinin dürüst analizi.
> Kaynak: GitHub deposunun (0xByteDeveloper/MVP_GOD_SSS_TIER_DECOMPILER) tam kaynak kod analizi
> + GitHub/internetteki araç taraması + akademik sınır.
> Tarih: 2026-11-22

---

## 0. TL;DR — Net Cevaplar

**Soru: "GitHub'da ve internette %100 devirt edebilen program var mı?"**
**Cevap: HAYIR.** Hiçbir ticari, açık kaynak veya akademik araç statik olarak %100 devirt yapamıyor ve
bu teorik olarak da imkansız (bkz. §4.1). Kanıt özeti:

| Kanıt | Sonuç |
|---|---|
| Ghidra 12.2 (PDB'siz, kendi canlı testimiz) | `playerGetStatus` içindeki 2 sanal çağrıyı da HAM bırak (`(**(code **)(...))(...)`) |
| IDA / Hex-Rays | Topluluk açıkça şikayet ediyor: "polymorphism için organize destek yok"; eklenti ekosistemi (ClassInformer, Virtuailor, devirtualize, CodeXplorer...) tam da bu yüzden var |
| Trail of Bits'ın Binary Ninja eklentisi (2017) | Temel blok sınırlı, çağrıda yazmaçları silen — bizim Tier-1 ile AYNI sınıf, aynı sınır |
| OOAnalyzer (Pharos/CMU-SEI, CCS'18) | Sınıfları/vtable'ları kurtarır; çağrı çözümünde %100 iddiası yok |
| Akademik SOTA (DeClassifier, KallGraph, iResolveX, SoK) | En iyiler bile kısmi kapsama raporluyor; SoK makalesi "tasarım-uygulama boşluğu → eksik sonuçlar" diyor |
| Dinamik araçlar (devi/Frida) | Yalnızca ÇALIŞTIRILAN çağrıları %100 çözer — koşulmayan soğuk yollar dışarıda kalır |

**Önemli çerçeve: iki farklı "%100" var.**
1. **%100 statik** (binary'yi hiç çalıştırmadan tüm dolaylı çağrılar) → **imkansız**. Hedef değer
   program girdisinin fonksiyonu olabilecek bir adres olabilir (dosyadan/ağdan/şifreli tablodan
   okunan işaretçi) — bu, durdurma problemine (halting problem) indirgenir.
2. **%100 kanıtlı sanal-çağrı kapsaması + %100 gerçekleşen-çağrı kapsaması** → **ulaşılabilir**.
   Pragmatik zirve: vtable'lı sanal çağrıların ~%95-99'u KANITLA çözülür; kalan veri-bağımlılar
   dürüst aday listesi olarak etiketlenir; ayrıca binary bir kez koşturularak (dinamik iz)
   gerçekleşen çağrıların tamamı ground-truth olarak eklenir.

**Bizim eksikimiz tek cümlede:** v8'in çözemediği ~4716 çağrının ezici çoğunluğu,
**interprocedural nesne-akış katmanının olmamasından** kaynaklanıyor — heap allokasyonu (`new`),
fonksiyon dönüş değerleri, parametre alıcıları, STL konteyner elemanları, COM/D3D arayüzleri ve
fonksiyon-işaretçisi veri tabloları. Bunların hepsi mühendislikle eklenebilir (§6).
Ayrıca **3 bedava kazanç** var: kaynakta hazır ama hiç okunmayan/boş geçilen kod (§5).

**İlk hamle:** `devirt stats` — çözülemeyen her çağrıya gerekçe kodu basan döküm komutu (§6.1).
Kova büyüklükleri ölçülmeden yapılan her öncelik sıralaması tahmin kalır; bu dokümandaki tüm
kazanç tahminleri de buna göre etiketlidir.

---

## 1. Metodoloji ve Dürüstlük Notu

Bu doküman üç kaynaktan sentezlendi:

1. **Tam kaynak kod analizi** — GitHub'daki v8 ağacı (`bb40b88`) satır satır incelendi:
   `devirtpro.cpp` (1101 satır, Tier-1), `devirtemu.cpp` (462 satır, Tier-3), `msvcrtti.cpp`
   (RTTI atlası), `pseudocode.cpp` (Decompile32 + callRender), `emulator.cpp` (Unicorn sarmalayıcı),
   test paketi (26 bölüm, 308 CHECK) ve `docs/` altındaki 4 doküman. Aşağıdaki tüm `dosya:satır`
   referansları gerçek kodda teyitlidir.
2. **Araç taraması** — GitHub + web: Ghidra/Pharos/OOAnalyzer, IDA eklenti ekosistemi,
   Binary Ninja, dinamik araçlar (devi), emülasyon çerçeveleri (Qiling, Speakeasy), VM-koruma
   devirt araçları (NoVmp, Triton), akademik literatür (§4, §9).
3. **Canlı kanıt verisi** — v8'in metin2client.exe üzerindeki ölçümleri (docs/DEVRIT_V8_CANLI_KANIT.md).

**Dürüstlük notu:** Bu oturumda hedef binary + PDB sandbox'ta mevcut değildi (çalışma ortamı
yenilendi). Bu yüzden "4716 çözülemeyen çağrının kova kova sayısı" bu dokümanda **tahmin**
olarak etiketlendi; kesin sayılar için §6.1'deki `devirt stats` komutunun eklenmesi ve
binary ile bir kez koşturulması yeterli. Kaynak kod analizi tahminleri güçlü şekilde
bilgilendiriyor çünkü her kök nedenin kodda tam karşılığı var.

---

## 2. Bugünkü Konum (v8 Özeti)

| Mod | Çözülen / Evren | Oran | Not |
|---|---|---|---|
| v8 PDB'li | 4444 / 9160 | %48.5 | Tier-1: 4188 + Tier-3: 256 |
| v8 PDB'siz | 3358 / 7855 | %42.7 | RTTI kanıtıyla: `CPythonPlayer::Instance().vf4(v1)` |
| v7 (önceki) | 3842 / 7420 | %51.8 | Evren küçüktü: +3033 gizli sanal metod henüz keşfedilmemişti |

Metin2client.exe: 5.2 MB, ~28.706 fonksiyon, 892 RTTI sınıfı, 7282 vftable slotu (PDB'siz);
PDB: 176.018 tip, 23.479 fonksiyon yeniden adlandırması. PDB'li tam boru hattı 8.5 sn;
Ghidra 12.2 aynı işi ~4 dakikada yapıp sanal çağrıları çözümeden bırakıyor.

**Mimari hatırlatma ( çağrı noktasının akışı ):**

```
dolaylı çağrı adresi
 └─ DevirtPro::Resolve(callAddr)                          [devirtpro.cpp:1008]
     ├─ Tier-1: EvalFunction(başlangıç→çağrı)            [devirtpro.cpp:436]
     │    • kurucu vtable-yazım kanıtları (statics_ tablosu)
     │    • atlas inversiyonu (this ← sahip vftable'lar)
     │    • IAT import adlandırma, .rdata somut slot okuma
     │    • çoklu-aday tek-hedefe çökerse → KANITLI çözüm
     └─ Tier-3: EmuResolve (Unicorn tohumlu pencere)      [devirtpro.cpp:892]
          • temel blok içinde ≤64 komut geriye pencere
          • statik/this kanıtlarıyla tohumlama, gerçek x86 koşumu
          • çoklu geçiş: tüm adaylar aynı hedefe giderse → KANITLI çözüm
          • çelişki/uzaklaşma → dürüst aday listesi ("SANAL KALDI")
```

Dürüstlük disiplini (yanlış tekil tahmin asla yapılmaz; aday listesi basılır) v7'den beri
kodun DNA'sında — bu, dünyadaki birçok araçtan İLERİDE bir özellik ve korunmalı.

---

## 3. Çözülemeyen ~4716 Çağrının Anatomisi — 12 Kök Neden

Kaynak kodda her nedenin kesin karşılığı var. Etki sütunundaki değerler **tahmin** (§1 notu).

### K1. Heap alıcıları — `operator new` hiç modellenmiyor (EN BÜYÜK KOVA, tahmin ~%30-40)

`new CMonster(...); obj->Attack()` deseni: alıcı, bir **çağrının dönüş değeri**. İki katman da
bunu göremez:

- **Tier-1:** her `call` anında caller-saved yazmaçlar silinir, dönüş değeri modellenmez
  (`devirtpro.cpp:684-693` — "çağrı: kayıp yazmaçları temizle"). `call operator new` sonrası
  `eax` = Unknown → `mov ecx,eax; mov edx,[ecx]` → zincir kopar.
- **Tier-3:** pencere temel blokla sınırlı (64 komut, `devirtemu.cpp:155`), `new` genelde başka
  bloktadır; üstelik tier-3'ün `mapRep_`'i **boş** (`devirtemu.h:96` — "shadow bölgesi boş"),
  yani pencere içi herhangi bir import çağrısı eşlenmemiş adrese zıplar → hata → deneme başarısız.

### K2. Interprocedural veri akışı (IPA) yok — hiçbir özet yok (tahmin ~%20-30)

Kod tabanında "interprocedural/IPA" grep'i **sıfır** sonuç veriyor (teyit edildi). Tek çapraz-
fonksiyon yapı, statik nesne kanıt tablosu `statics_`. Şunlar yok:

- "F fonksiyonu S statik nesnesini döndürür" (dönüş özeti),
- "F'in 2. parametresi hep CMonster* türünden geçer" (parametre özeti),
- "F, H allokasyon noktasından nesne döndürür" (allokasyon özeti).

Sonuç: `GetItem(i)->Use()` gibi ≥1 çağrı derinliğindeki tüm alıcı zincirleri çözülemez.
(İronik not: `TypeInferer`'da sınırlı bir interprocedural provenance grafiği VAR —
`CallEdge::Prov`, `types.h:155-163` — ama yalnız struct/arg-tipi çıkarımında kullanılıyor;
devirt alıcı yazmasına hiç beslenmiyor.)

### K3. Parametre alıcıları — yalnızca "erken [ebp+8]" sezgisi var

`void f(CUnknown* a2) { a2->Virtual(); }` durumu: fonksiyon girişinde yalnızca `this` tohumlanır
(ecx/rcx/rdi). cdecl kurucular için ilk ~12 komutta `[ebp+8]` okuması `this`'e map edilir
(`devirtpro.cpp:467, 760-765` — `earlyArgGuard = 12`). **`[ebp+0xC]` ve sonrası hiç
modellenmez.** En kritik nokta: **PDB'deki parametre TİPLERİ (176.018 tip!) DevirtPro'ya hiç
beslenmiyor** — PDB yalnızca isimlendirme/imza süslemede kullanılıyor. `f(CMonster* a2)`
imzası elimizdeyken `a2`'nin aday seti boş geziyor.

### K4. STL konteyner elemanları — modelleme yok

`std::map`/`vector` içine konan nesne işaretçileri (`mov eax,[vec._M_start]; mov ecx,[eax+4]; call [ecx]`)
hiçbir katman tarafından izlenmiyor. Metin2'de karakter/eşya haritaları bolca bu desende — tahmin
~%5-10.

### K5. COM / DirectX arayüzleri — sözlük yok

`IDirect3DDevice9::Release()` tarzı çağrılar: alıcı import'tan gelir (K1+K2) VE COM arayüzlerinin
MSVC RTTI'si yoktur → atlas'ta hiç görünmezler (`IsVftable()==false`). Metin2 istemcisi D3D9
ağırlıklı; `d3d9->...` çağrıları kalıcı olarak çözümsüz. Oysa D3D9 arayüz vtable düzenleri kamu
bilgisidir (SDK başlıklarında) — sentetik atlas sınıfı olarak şırınga edilebilir (§6.3).

### K6. Vtable-dışı fonksiyon işaretçileri — veri tabloları

- Statik tablo + somut adresli `call [taban+K]`: Tier-1 zaten çözüyor (image okuma).
- Kalanlar: taban **parametreden/heap'ten** gelen işaretçiler, `PyMethodDef` tarayıcısının
  olmaması (metin2'de her Python modül kaydı `{"isim", fonk, bayrak, doc}` dizisidir — saf veri,
  RTTI yok, aday üretilemiyor). Deepscan veri-referanslı fptr'leri fonksiyon KEŞFİ için buluyor
  ama çağrı noktasına bağlamıyor.

### K7. Gerçek CHA muğlaklığı — tasarım gereği "sanal kalır"

Aynı slotu dolduran birden fazla somut sınıf varsa ve tüm adaylar aynı hedefe çökmüyorsa
dürüst aday listesi basılıyor (`pseudocode.cpp:4146-4161`). Bu bir bug değil, doğruluk politikası;
ancak §6.6'daki açık-etiketli tahmin moduyla kapsamaya çevrilebilir.

### K8. Tier-3 yapısal limitler

| Limit | Yer | Etki |
|---|---|---|
| 180 sn toplu bütçe | `devirtpro.cpp:265-274` | sonrası siteler Tier-1'e kalır (metin2'de tetiklenmedi: 2.1 sn) |
| 60.000 us / 20.000 komut | `devirtemu.cpp:320` | uzun pencereler zaman aşımı |
| ≤64 komut, temel blok | `devirtemu.cpp:155-163` | blok-ötesi zincirler (döngü/dal) görünmez |
| ≤4 this-tohum varyantı | `devirtpro.cpp:917-918` | >4 sahip metotlarda denenmez |
| ≤6 aday açılımı | `devirtpro.cpp:961` | geniş muğlaklık kesilir |
| ~1024 tohumlanabilir statik | `devirtemu.cpp:29-30, 95-99` | 1 MB sentetik bölge, 0x400/statik |
| Boş shadow-IAT | `devirtemu.h:96` | pencere içi import çağrısı = fault (K1'in tetikleyicisi) |

### K9. RTTI'siz / vftable'sız sınıflar + kanıtsız statikler

Metin2'de 111 statik yazıcı tarandı, yalnızca 50'si vtable-kanıtlı. RTTI'siz derlenen sınıflar
atlasta yok; vftable slot taraması ilk kod-dışı işaretçide veya 512 slotta durur
(`msvcrtti.cpp:220-229`). İşaretçi üzerinden/yazılım kopyasıyla yazılan `.bss` statikleri
`statics_`'e hiç girmez.

### K10. `memFacts_` — toplanıyor ama HİÇ OKUNMUYOR (ölü kod, teyitli)

Fonksiyon içi mutlak-adres yazımları toplanıyor (`devirtpro.cpp:713, 731`) ama `ReadMemory`
(368-395) bu tabloya hiç bakmıyor (grep: yalnızca yazım + clear). Yani aynı fonksiyon içinde
"vtable'ı .data'ya yaz, sonra geri oku" desenini Tier-1 kaçıyor — fixture'taki `F_EMUCASE`
tam da bu yüzden yalnız Tier-3'te çözülüyor. **Ucuz kazanç (§5).**

### K11. `vptrAll` — toplanıyor ama HİÇ OKUNMUYOR (ölü kod, teyitli)

Yazıcı taraması her ofsete YAZILMIŞ TÜM vtable'ları da topluyor (`devirtpro.cpp:738`) ama
birleştirme yalnız son-yazım birliğini kullanıyor (`243-244` — "ara yazımlar dürüstçe ezilir").
Taban→türetilmiş kurucu sırası için doğru; iki farklı nesnenin aynı yazıcıyı paylaşması
durumunda kanıt kaybı. **Ucuz kazanç (§5).**

### K12. Değerlendirici boşlukları (ufak ama gerçek)

- Bilinmeyen indeksli adresleme: `mov eax,[esi+ecx*4]`, ecx Unknown → Unknown
  (`devirtpro.cpp:495-504`).
- `.bss`/yerleştirilmemiş slot okuması `Conc 0` döndürür → exec değil → adaysız çözümsüz.
- `earlyArgGuard` 12 komutta biter → geç okunan ilk arg `this` bağını kaybeder (`885`).
- x86-32 dışında Tier-3 yok (`devirtemu.cpp:110-111`) — metin2 için sorun değil.

---

## 4. Dünya Turu: Kim Ne Kadar Devirt Edebiliyor?

### 4.1 "%100 statik" neden teorik olarak imkansız

Dolaylı çağrının hedefi, programın girdisine bağlı herhangi bir değer olabilir (yapılandırma
dosyasından okunan işaretçi, ağ paketiyle seçilen işleyici, şifresi çalışma anında çözülen tablo).
"Tüm girdiler için hedef nedir?" sorusu, programın tüm girdilerde davranışını çözmeyi gerektirir
— bu, durdurma probleminin kararıdır ve genel algoritması yoktur (undecidability). Bu yüzden
statik analizlerin gold standardı olan Value-Set Analysis / points-to aileleri (Balakrishnan &
Reps'in VSA'sından 2025-26'daki KallGraph/iResolveX'e kadar) daima **konservatif üst sınır**
üretir: "hedef şunlardan biri olabilir" kümesi. Pratikte: %100 statik iddiası yapan hiçbir saygın
araç yok; olanlar ya "koşulanı %100" (dinamik) ya da "kanıtlıyı %X" (statik, X < 100) der.

### 4.2 Araç karşılaştırma tablosu

| Araç | Tür | Yaklaşım | Sınırı — %100 mü? |
|---|---|---|---|
| **Ghidra 12.2** (NSA) | statik | RTTI taraması + demangler + decompiler tip yayılımı | Hayır — canlı kanıtımızda sanal çağrılar ham çift-deref kaldı |
| **OOAnalyzer / Pharos** (CMU-SEI, CCS'18) | statik | XSB Prolog mantık programlama; sınıf/metot/vtable kurtarma; Ghidra eklentisi | Hayır — sınıf kurtarma odaklı; çağrı çözümü iddiası yok; Ghidra temsili "work in progress" |
| **IDA ClassInformer** | statik | MSVC RTTI taraması, vftable adlandırma/etiketleme | Hayır — isimlendirir, çağrıyı çözmez |
| **Virtuailor** (Hex-Rays eklenti) | dinamik yardımlı | breakpoint'te kayıtlardan vtable geri kurar | Hayır — yalnız çalıştırılan/kesilen noktalar |
| **ALSchwalm/devirtualize** (IDA) | statik | vtable ayrıştırır, tipleri uygular, sanal çağrıları direkte çevirir | Hayır — kullanıcı kök vtable'ı verir; blok/işlev içi |
| **HexRaysCodeXplorer** | statik | C++ RE otomasyonu, sanal çağrı gezinme | Hayır — asistan, çözücü değil |
| **ida_medigate** (Hex-Rays) | statik | decompiler tip paylaşımı + xref takibi | Hayır — "yalnızca decompile edilmiş çağrılar" diye kendi belirtiyor |
| **Binary Ninja 3.4+** | statik | HLIL SSA + "propagate data variable references" ile vtable referans yayılımı | Hayır — tip verildiyse iyi; heap/IPA akışı tam değil |
| **Trail of Bits vtable-navigator** (BN, 2017) | statik | LLIL'de kurucu vtable deseni + yazmaç takibi | Hayır — temel blok sınırlı; çağrıda yazmaçları siler (bizim Tier-1'in aynısı) |
| **devi** (murx-, Frida) | dinamik | çalışma anında sanal çağrı izi → JSON → IDA/BN/Ghidra eklentisi | "**koşulanın** %100'ü" — koşulmayan yollar dışarıda |
| **Qiling** (6.2k yıldız) | emülasyon | Unicorn üstünde işletim sistemi farkındalığı: PE yükleyici, syscall/IO, çapraz platform | Çerçeve — çözücü değil; kanıt üretmek için üstüne araç yazılır |
| **Speakeasy** (Mandiant) | emülasyon | Windows kullanıcı+çekirdek modu modellenmiş çalışma zamanı | Aynı — çerçeve |
| **NoVmp / Triton / Syntia** | statik+sembolik | VM-koruma (VMProtect) devirtualizasyonu, VTIL | **Farklı problem** — bizimki C++ sanal dispatch, onlarkı opcode sanallaştırma |
| **DeClassifier** (ACM TOPS'19) | akademik | sınıf-kalıtım çıkarımı | O0'da %94.5, O2'de %71.4 — ve bu KENARLAR için; çağrı çözümü değil |
| **KallGraph** (IEEE S&P'25), **iResolveX** (2026), **SoK** | akademik | dolaylı çağrı points-to / katmanlı çözümleme | En güncel SOTA bile kısmi; SoK: "tasarım-uygulama boşluğu → eksik sonuçlar" |

### 4.3 Bizim konumumuz

- Tier-1'in (doğrusal pencere + kurucu kanıtı + atlas inversiyonu) sınıf olarak karşılığı
  Trail of Bits/BN yaklaşımı — ama bizde ekstra: RTTI atlası, çoklu-aday tek-hedef kanıt
  katlaması, IAT adlandırma, Instance() katlaması ve **kanıt zinciri çıktısı** var.
- Tier-3 (tohumlu gerçek-x86 pencere emülasyonu) kamu araçlarında eklenti düzeyinde yaygın
  DEĞİL — bu bizim farklılaştırıcımız.
- Ghidra'yı canlı binary'de geçtik (aynı fonksiyonda 2/2 vs 0/2, 8.5 sn vs ~4 dk).
- Bize olmayan, SOTA'nın da tam yapamadığı ama **literatürün yapmayı bildiği** şey: özet
  tabanlı IPA (K2/K3), allokasyon-noktası heap modeli (K1), çalışma-zamani kanıt hasadı
  (Qiling/Speakeasy'nin kendi motorumuzdaki hali). Yani fark "imkansız" değil "sıralı
  mühendislik".

---

## 5. Hazır ama Ölü: 3 Bedava Kazanç (v9.0'ın çekirdeği)

1. **`memFacts_` okuma yolu** — `ReadMemory`'ye (devirtpro.cpp:368-395) `memFacts_` sorgusu
   ekle: fonksiyon içi yaz→oku yönlendirmesi. `F_EMUCASE` desenini Tier-1 bile çözmeye başlar;
   Tier-3'e binen yük azalır. (~30 satır)
2. **Tier-3'e gerçek `mapRep_` ver** — Shell'de mapper'ın dolu raporu zaten duruyor
   (`shell.h:51`, `shell_analyze.cpp:236`), DevirtEmu'ya boş kopya geçiliyor
   (`devirtemu.h:96`). Dolusunu geçir: pencere içi import çağrıları (operator new, memcpy...)
   artık shadow-IAT saplamalarına düşer, fault etmez → K1'in emülasyon tarafı açılır.
   (Pseudocoder→DevirtPro→DevirtEmu kurucu zincirine bir parametre; ~20 satır)
3. **`vptrAll` birleştir** — statik birleştirmede (devirtpro.cpp:243-244) son-yazım birliğine
   ek olarak tam yazım kümesini aday olarak kat: iki-nesne-tek-yazıcı durumu kanıt kazanır;
   çoklu-aday katlaması zaten var. (~10 satır)

Bu üçü hiçbir yeni mimari gerektirmez; hepsi mevcut dürüstlük kuralları içinde.

---

## 6. Yol Haritası: v9 → v12

### 6.1 v9.0 — Ölç + bedava kazançlar (günler)

1. **`devirt stats` komutu**: her çözülemeyen çağrı için gerekçe kodu topla ve kova kova dök.
   Önerilen kod tablosu (çıkışa + `stats` alt komutuna):

   | Kod | Anlam | Kök neden |
   |---|---|---|
   | `R_HEAP` | alıcı çağrı dönüşü (new/fabrika) | K1/K2 |
   | `R_PARAM` | alıcı parametre/arg | K3 |
   | `R_CONTAINER` | alıcı konteyner içi | K4 |
   | `R_COM` | alıcı import-kökenli arayüz | K5 |
   | `R_FPTR_DATA` | vtable-dışı işaretçi, taban izlenemedi | K6 |
   | `R_AMBIG` | çoklu aday, çakışmadı | K7 |
   | `R_WINDOW` | tier-3 pencere/bütçe sınırı | K8 |
   | `R_NORTTI` | sınıf atlasta yok | K9 |
   | `R_ZERO` | okunan slot 0 / eşlenmemiş | K12 |

   Bu döküm, bu dokümandaki tüm tahminleri gerçeğe çevirir ve v9.5+ sıralamasını veriler belirler.
2. §5'teki üç bedava kazanç.
3. Tier-3 limit parametrize: `--tier3-budget`, `--tier3-window`, sentetik bölge 16 MB
   (~16K statik), this-tohum 4→8, aday 6→16.

### 6.2 v9.5 — IPA katmanı: özet tabanlı nesne akışı (haftalar) — EN BÜYÜK LEVER

Klasik, iyi anlaşılmış teknik: **tabulation/summary-based analysis** (fonksiyon başına özet,
alt-üsten çağraf geçişi). Üç özet türü:

1. **Dönüş özetleri** — her F için: "S statığını döndürür" / "H allokasyonu döndürür" /
   "k. parametreyi döndürür" / belirsiz. Üretim: EvalFunction'ı `ret` anında eax'ı okuyacak
   şekilde çalıştır (altyapı zaten değerlendirici içinde). Tüketim: çağrı noktalarında
   `eax`'ı silmek yerine özete bağla → `GetInstance()` tarzı zincirler katlanır
   (Instance() katlamasının genelleşmiş hali).
2. **Allokasyon-noktası heap modeli** — `call [IAT: operator new]` → taze sembolik heap
   anahtarı `H_site`; ardından kurucu çağrısında WriterScan zaten vtable yazımlarını
   topluyor: `ObjFacts`'i heap anahtarlarıyla da sürdür → `H_site`'tan gelen alıcının aday
   vtable seti kurucu kanıtıyla sınırlanır. Tek kurucu → tek aday → KANIT. Birden kurucu
   (fabrika) → aday listesi (dürüst). Tier-3'e de `H_site` tohumu: `new`'in çağrıldığı
   pencerede dönüş yazmacını sentetik nesneye bağla.
3. **PDB parametre tohumlama** — PDB imzalarındaki parametre tipi sınıf ise
   (`CMonster*`), EvalFunction girişinde `[ebp+8/0xC/0x10]`'u o sınıfın CHA alt ağacıyla
   tohumla. PDB'li yolda muhtemelen **tek başına en yüksek ROI**: 176.018 tip elimizde,
   hiç kullanılmıyor. Tek impl → çözüm; çoklu → zengin aday listesi.

Ek: `this`-tohumlamayı kurucu olmayan metotlara genişlet (atlas inversiyonu zaten var);
`earlyArgGuard`'ı 12'den "ilk temel blok sonu"na taşı; `[ebp+0xC]`'yi de kapsayacak şekilde.

### 6.3 v10 — Tier-4: emülasyonla kanıt hasadı + COM sözlüğü (haftalar-aylar)

1. **Pencereyi blok-ötesine genişlet**: temel blok yerine fonksiyon girişinden path-sensitif
   kısıtlı koşum (20K komut limiti korunur; memoization ile patlamayı önle).
2. **Kurucu tam-emülasyon geçişi**: atlastaki her sınıfın kurucusunu girişten `ret`'e koştur,
   gerçek vptr tablolarını hasatla → `statics_`/kurucu şablonları zenginleşir. (Şu an
   tohumlama statik yazım taramasına dayalı; tam koşum eksik yazımları da yakalar.)
3. **Program-init emülasyonu ("kendi motorumuzda Qiling")**: CRT init + DLL statik
   kurucuları + `WinMain` önüsünü, VAR OLAN altyapıyla koştur — 7 adımlı loader emülasyonu,
   shadow-IAT @0x77000000, TEB/PEB, API saplamaları hepsi `mapper/` + `emulate/` içinde hazır.
   MemLog'daki her `[adres]=vftable` yazımını global kanıt veritabanına yaz, `statics_`'e
   geri besle. Bu, "process'i hiç çalıştırmadan runtime kanıtı" üretir — K1/K5'in
   büyük bölümünü tek seferde ısıtır.
4. **COM/D3D arayüz sözlüğü**: d3d9/dsound/dinput8/d3dx arayüz vtable düzenleri kamu bilgisi
   (SDK/MinGW başlıkları). Sentetik atlas sınıfları üret ("synthetic" etiketiyle, RTTI'siz),
   `Direct3DCreate9`/`QueryInterface` importlarını bu sınıflara bağla → `d3d9->Release()`
   ailesi çözülür. Metin2 istemcisinde gözle görülür kazanç.
5. K8 limit kaldırma zaten 6.1'de; ayrıca tier-3'ü ARM'a taşıma (öncelik düşük).

### 6.4 v11 — Veri tablosu ve functor desenleri

1. **PyMethodDef tarayıcı** (metin2'ye özel büyük kazanç): `.rdata`'da
   `{char* isim; PyCFunction fonk; int bayrak; char* doc}` dizi desenini tara →
   (a) yüzlerce isimsiz fonksiyona GERÇEK isim ver (PDB'siz yolda bile),
   (b) Python dispatch çağrılarını bu tabloyla eşleştir.
2. **Callback tablo xref çözümümü**: `R_FPTR_DATA` kovaları için — adresi alınmış
   (address-taken) fonksiyonları imzayla kümele; taban K'da yürüyüşle tabloyu kur;
   `call [taban+K]`'yı tabloyla eşleştir. Kanıt değil ama PDB tip bilgisiyle
   "tek uyumlu aday" sık sık çıkacaktır (KAPSAM modu, §6.6).
3. **std::function / boost::signals desenleri**: MSVC düzeni bilinir; `_Func_impl`
   vtable'ları RTTI'sizdir ama desen tanınır — sentetik sınıf şablonu uygula.

### 6.5 v12 — Dinamik gerçek-gerçek (opsiyonel, "koşulanın %100'ü")

`devirt trace dosya.json` komutu: devi-formatındaki (Frida) izi içe aktar, her
`çağrı_adresi → hedef` çiftini **"runtime kanıtı"** etiketiyle çözüm tablosuna yaz
(`why="DINAMIK KANIT (iz)"` — kanıt zinciri kültürüne uyar). `scripts/` altına hazır
Frida izleme scripti koy (tüm `call reg`/`call [mem]`'i kancala, modül+offset bas).
Oyun bir kez koşturulursa sıcak yolların tamamı ground-truth olur. Soğuk yollar
(menü derinlikleri, hata yolları) için fuzz/kısa senaryo turları ekle. Not: oyun
GPU/D3D istiyor; Linux tarafında Wine üstünde ya da gerçek Windows kutusunda
koşturmak gerekir — emülasyonda tam oyun döngüsü gerçekçi hedef değil (init yolu yeter,
o da 6.3'te).

### 6.6 KAPSAM modu — açık etiketli spekülatif katman ( "%100 kapsam" isteniyorsa )

v7'de ELF yolunda zaten öncü var: "slot N binary capinda tek impl (spekulatif devirt)"
(`types.cpp:1667`). Öneri: kanıt/spekülasyon ayrımını DOSYA ÇIKTISINDA görünür kılan
açık-kapalı mod:

- `KANIT modu` (varsayılan, bugünkü): yalnız kanıtlı çözüm + aday listesi.
- `KAPSAM modu` (`--coverage`): PDB tipi + CHA'da tek impl / tek uyumlu imza →
  çözüm ama satır sonunda `// TAHMIN(guven:0.9)` etiketiyle. Aday listeleri de
  olasılık sıralı ilk adayı işaretler (işaretler, ASLA gizlice yazmaz).

Böylece "%100'e kadar her satır ya çözülür ya TAHMIN işaretlidir ya da aday listesidir" —
dünyada kimsenin dürüstçe vermediği bir çıktı sözü.

---

## 7. Hedef Matrisi (TÜMÜ TAHMİDİR — `devirt stats` gerçekçileştirecek)

| Aşama | Eklenen | Tahmini çözülen (PDB'li) | Tahmini oran |
|---|---|---|---|
| v8 (bugün) | — | 4444 / 9160 | %48.5 |
| v9.0 | ölçüm + 3 bedava kazanç + limitler | ~4700-5100 | %51-56 |
| v9.5 | IPA: dönüş özetleri + heap modeli + **PDB parametre tohumlama** | ~5600-6600 | %61-72 |
| v10 | Tier-4 kanıt hasadı + COM/D3D sözlüğü | ~6800-8000 | %74-87 |
| v11 | PyMethodDef + callback + functor | ~7100-8500 | %78-93 |
| v12 | dinamik iz (koşulanların tamamı) | ~8300-9000 | %91-98 |
| Dürüst zemin | veri-bağımlı işaretçi + hiç koşulmayan yol | ~100-600 site ADAY LİSTESİ kalır | — |

İki dürüst uyarı: (1) evren büyümeye devam edebilir — v8'de RTTI-güdümlü keşif evreni
7420'den 9160'a büyüttü; IPA da yeni fonksiyonlar bulunca oran payı oynar. (2) Tahmin
aralıkları kova büyüklükleri ölçülmeden yönlendirme içindir; `devirt stats` çıkınca bu
tablo veriyle yeniden yazılmalı.

---

## 8. Önerilen İlk 3 Hamle

1. **`devirt stats`** (yarım gün) → R_* kova sayıları. Bu dokümanın §7 tablosunu gerçeğe çevirir.
2. **3 bedava kazanç** (1-2 gün) → memFacts_ okuma yolu, Tier-3'e dolu mapRep_, vptrAll
   birleştirme. Fixture'a yeni vakalar + test.
3. **PDB parametre tohumlama** (2-4 gün) → PDB'li yolda muhtemelen en yüksek tekil kazanç;
   K3 kovasını büyük ölçüde kapatır ve v9.5 IPA'sının giriş kapısıdır.

Bundan sonra: IPA dönüş özetleri → allokasyon modeli → Tier-4 init-emülasyonu → COM sözlüğü →
PyMethodDef → dinamik iz. Her adımda fixture + test + kanıt zinciri kültürü korunarak.

---

## 9. Kaynaklar

**Proje ve kanıt**
- Repo: https://github.com/0xByteDeveloper/MVP_GOD_SSS_TIER_DECOMPILER (v8 = `bb40b88`)
- v8 canlı kanıt dokümanı (repo içi): `docs/DEVRIT_V8_CANLI_KANIT.md`

**Statik sınıf/vtable kurtarma**
- OOAnalyzer (Pharos, CMU-SEI): https://github.com/cmu-sei/pharos —
  https://www.sei.cmu.edu/blog/using-ooanalyzer-to-reverse-engineer-object-oriented-code-with-ghidra
- OOAnalyzer makalesi (CCS'18, Schwartz ve diğ.): "Using Logic Programming to Recover C++
  Classes and Methods from Compiled Executables"
- DeClassifier (ACM TOPS'19): https://arxiv.org/abs/1901.10073 — kalıtım kenarları O0 %94.5 / O2 %71.4
- IDA ClassInformer: https://github.com/kweatherman/IDA_ClassInformer_PlugIn
- ALSchwalm/devirtualize: https://github.com/ALSchwalm/devirtualize
- HexRaysCodeXplorer: https://github.com/rehints/hexrayscodexplorer
- Virtuailor: https://plugins.hex-rays.com/0xgalz/virtuailor

**Binary Ninja**
- Trail of Bits, "Devirtualizing C++ with Binary Ninja" (2017):
  https://blog.trailofbits.com/2017/02/13/devirtualizing-c-with-binary-ninja/
- BN C++ tipleri/vtable dokümantasyonu: https://docs.binary.ninja/guide/types/cpp.html
- Sean Seaton, vtable RE (2024):
  https://www.seandeaton.com/gotta-re-em-all-reversing-c-virtual-function-tables-with-binary-ninja

**Dinamik / emülasyon**
- devi (Frida tabanlı sanal çağrı izi): https://github.com/murx-/devi —
  https://insinuator.net/2020/11/reversing-c-without-getting-a-heart-attack-devirtualize-virtual-calls-with-devi/
- Qiling: https://github.com/qilingframework/qiling — https://qiling.io/comparison
- Speakeasy (Mandiant): https://github.com/mandiant/speakeasy

**VM-koruma devirt'i (farklı problem, referans)**
- NoVmp: https://github.com/can1357/NoVmp
- Triton: https://github.com/jonathansalwan/triton
- Salwan, VMProtect-devirtualization: https://github.com/JonathanSalwan/VMProtect-devirtualization

**Akademik sınır**
- Balakrishnan & Reps — VSA / x86 points-to (REWARDS çizgisi)
- KallGraph (IEEE S&P'25): https://www.cs.ucr.edu/~zhiyunq/pub/oakland25_indirect_call.pdf
- iResolveX (2026): https://arxiv.org/html/2601.17888v1
- SoK: Multi-Layer Indirect Call Analysis in the Real World (Du ve diğ.)
- Durdurma problemi / undecidability: https://en.wikipedia.org/wiki/Halting_problem

---

*Bu doküman v8 kaynak kodundaki dosya:satır referanslarıyla ve §4'teki kamuya açık kaynaklarla
desteklenmiştir. Tahmin olarak işaretlenen hiçbir sayı kanıt olarak sunulmamıştır.*
