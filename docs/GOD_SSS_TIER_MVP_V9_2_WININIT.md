# GOD SSS TIER MVP — v9.2 WINİTİT RAPORU
## Windows Süreç-Başlangıcı Benzetimi (Tier-5a), Hex-Rays/Ghidra Kıyaslaması ve Yeniden-Derlenebilirlik Cevabı

> Tarih: 2026-11-22 · Repo: `MVP_GOD_SSS_TIER_DECOMPILER` · Sürüm v9.2 (v9.1 dokümanlarının
> üstüne, kod değişiklikleriyle). Önceki: v8.1 (319 test), v9.1 (doküman: yapay yığın/kanıt
> mimarisi + 4-AI sentez karar planı).
> Ortam: Linux g++ 14.2, Unicorn 2.1, Capstone 5, Ghidra 12.2 PUBLIC (JDK 25, PyGhidra).
> Testler: **342/342 PASS** (v9.1: 319 → +23 yeni WinInit testi, 0 regresyon).

---

## 0. Yönetici Özeti (TL;DR)

1. **WinInit (Tier-5a) inşa edildi ve KANITLANDI** — kullanıcının "Windows exe açılınca ne
   yapıyorsa aynısını simüle edelim" öngörüsünün mühendisliği: kernel→yığın→import→TLS(EP'den
   önce!)→CRT-init→duvar sırasıyla, deterministik ortamda. Kontrollü fixture'ta
   **4/4 dolaylı çağrı çözümü** (WinInit'siz 2/4, Ghidra 12.2: 2/4 — aynı 2'si yalnız IAT).
2. **6 adet ÖNCEDEN VAR OLAN motor hatası bulundu ve düzeltildi** — WinInit'in fixture'ı
   bir hata-avlama enstrümanına dönüştü (x86-32 shim argümanları hiç okunmuyordu, API dönüş
   değeri EAX'a hiç yazılmıyordu, TLS dizini VA'ları iki katına çıkıyordu...).
3. **SIFIR REGRESYON kanıtlandı** — metin2client.exe PDB'li 4444/9160 ve PDB'siz 3358/7855
   kırılımları bit-bitiye v9.1 taban çizgisiyle aynı; WinInit yalnız açıkça çağrılırsa
   devreye girer (`wininit off` ile her an kapatılır).
4. **Ghidra 12.2 kıyaslaması tazelendi** — aynı binary, aynı fonksiyon, otomatik post-script,
   hiçbir el düzenlemesi yok. Ghidra her iki sanal çağrıyı da çözemeden bırakıyor (v8
   bulgusunun yeniden doğrulanması); yeni: kontrollü fixture kıyası ve analiz-süresi ölçümü.
   IDA Pro/Hex-Rays lisanslı yazılımdır — sandbox'ta koşulamaz; davranışı v8 dokümanındaki
   kayıtlı gözlemle ve Hex-Rays'in bilinen devirt modeliyle (kullanıcı betiği ister) not edildi.
5. **Yeniden-derlenebilirlik sorusuna ölçülebilir cevap** — "decompile edip derleyip aynı
   projeyi çalıştırabilir miyiz?" için R0→R3 merdiveni + **diferansiyel test orakcı**:
   bir fonksiyon, orijinal binary'si Unicorn'da N girdiyle koşulup decompile edilmiş haliyle
   AYNI çıktıyı veriyorsa "R1 sertifikalı"dır. %100 sloganı böylece ölçülebilir hale gelir.
6. **WinInit'in metin2 cephesi**: CRT-init'e 7.904 komut derinleşti (ilk hali 351), 135 API
   çağrısı, 80 init-kanıtı üretildi; 45 devirt zinciri artık bayat dosya baytı yerine GERÇEK
   runtime değeri taşıyor. Sınır dürüstçe raporlandı: `__vcrt` per-thread dispatch'te
   `int 0x29 __fastfail` — sonraki shim turunun kesin hedefi.

---

## 1. Kullanıcının Sorularına Cevaplar (özet — ayrıntı §2-§5)

### 1.1 "Windows exe açılınca ne yapıyor? Stack runtimeden mi başlar, EP'den mi, TLS'den mi?"

Windows'un gerçek sırası (Windows Internals + PE spesifikasyonu):

| # | Aşama | Kim yapar | Bizim karşılığı (v9.2) |
|---|---|---|---|
| 1 | Süreç nesnesi + adres alanı + **PEB** | kernel | `Mapper::MapPE` (görüntü kur) + PEB |
| 2 | **İlk thread + 1 MB ayrılmış yığın** (kernel, kullanıcı kodundan ÖNCE) | kernel | `Emulator` stack (0x7FEF0000-0x7FF00000, 1 MB — v8.1 notundaki gibi) |
| 3 | Statik import çözümü (BFS bağımlılık sırası) | ntdll Ldr | shadow-IAT (mapper) |
| 4 | **TLS: `__tls_index`=0 yazımı + TLS callback'ler (Reason=PROCESS_ATTACH) — EP'den ÖNCE** | ntdll Ldr | `WinInit::RunTlsCallbacks` — koşulur, kanıt üretilir |
| 5 | EP: `WinMainCRTStartup` → security-cookie → `_initterm` (CRT$XI/XCA/XCU: **global kurucular**) → WinMain | CRT (exe'nin içinde; metin2client STATİK CRT — doğrulandı: 19 dll importu arasında msvcrt yok) | `WinInit::RunEntryPoint` (Unicorn, gerçek yürütme) |
| 6 | WinMain → pencere/ağ/mesaj döngüsü | oyun | **DUVAR** — dürüst duruş + anlık görüntü |

Yani: **yığın "runtime'dan" başlamaz** — kernel ilk thread'i yaratırken ayırır; TLS
callback'ler EP'den önce koşar; thread'ler (CreateThread) kullanıcı modunda sonra yaratılır.
WinInit bu sırayı birebir izler.

### 1.2 "Stack aynı anda birden fazla yerden mi geçer (multithread)?"

**Her thread'in KENDİ yığını ve TEB'i vardır.** İlk thread = 1 yığın. `CreateThread` →
yeni yığın + yeni TEB; gerçek paralellik (çok çekirdek) veya zaman dilimleme. WinInit'te
**bilinçli tek-thread determinizm** vardır: `CreateThread` çağrıları KAYDEDİLİR ama
koşturulmaz (raporda görünür), senkron API'leri anında geçer, zaman/PID/TID/QPC/tick SABİT
tohumludur. Çok-thread'li init'in simülasyonu (deterministik zamanlayıcıyla thread
proceduralarının sırayla koşturulması) yol haritasında — ama init kanıtı için tek thread
yeterlidir: C++ global kurucular ana thread'de koşar.

### 1.3 "Runtime'dan WinMain'e olasılıklar zinciri — her daldan doğru stacklarla geçmek"

Kullanıcının sezgisi doğru yönde, ölçek yanlış: **tüm dalları gezme 2^dal üsteldir**
(yol patlaması — sembolik yürütmenin bilinen problemi). Doğru araç kombinasyonu:
- WinMain'e KADAR: tek deterministik yol yeter (init kodu girdi-bağımsızdır: ağ yok,
  kullanıcı yok — WinInit'in tam kapsadığı kısım).
- WinMain'den SONRA: her dalın tüm yığınını simüle etmek yerine, **ilgili dolaylı çağrının
  temel bloğunu** gerçek x86 semantiğiyle koştur (Tier-3 pencere emülasyonu — v8'den beri
  var) ve eksik değerleri statik kurucu kanıtı + init-anlık görüntüsüyle tohumla (v9.2).
  "Her yerden geçmek" yerine "her ÇAĞRI NOKTASI için kanıt-chain'i kurmak" — bu %100
  sözleşmesinin ölçülebilir hali (DEVRIT_V9_KARAR_PLANI §6).

### 1.4 "Windows'u %100 simüle edersek decompile seviyemiz çok artar mı?"

**Yığını gerçekleştirmek darboğaz DEĞİLDİ** (v8'in cevabı geçerli) — ama kullanıcı bu
sefer darboğazı DOĞRU yakaladı: **global-durum (globals-state) sadakati** darboğazıdır.
WinInit bunu çözer: CRT-init'in kurduğu tüm statikler + heap'e yazılan vptr'ler gerçek
değerleriyle kanıt tablosuna girer. Artmayan kısım dürüstçe söylenir: kullanıcı girdisi ve
sunucu paketi bekleyen kod yolları (login sonrası) init'te YOKTUR — onlar Tier-5b paket
simülasyonunun (V9 planı Faz 4) işidir. WinInit = Tier-5a; birlikte kapatırlar.

### 1.5 "Decompile edilmiş kodu derleyip aynı projeyi ÇALIŞTIRABİLİR MİYİZ?" (§5'te tam cevap)

Kısa cevap: **otomatik ve bugün için hayır; ölçülebilir merdivenle kısmen evet, hedefe
kilitli evet.** R0 (derlenebilir pseudocode) mühendislikle yakın; R1 (diferansiyel-test
sertifikalı fonksiyonlar) bizim mimarinin doğal ürünü; R2 (menüye kadar açılan klon)
PDB+init-anlık görüntüsü+paket simülasyonuyla yıllar yerine aylar; R3 (tam davranışsal
eşdeğerlik) veri-bütünlüğü ve kütüphane-parite sorunlarıyla araştırma sınırlıdır. Ayrıntı ve
gerekçe §5.

---

## 2. WİNİTİT (Tier-5a) — Mimari ve Kanıt

### 2.1 Neden "ek araç" olarak doğru

v7, "EP'den %100 yürütmek"ni çürüttü (playerGetStatus login'e dek çağrılmaz). v9.2'nin
WinInit'i FARKLI bir hedefe koşar: **oyun mantığını yürütmek değil, init durumunu
maddelleştirmek.** Duruş koşulları ("duvar") oyun mantığına girmeden yakalanır:

- mesaj döngüsü: `GetMessage*/PeekMessage*/WaitMessage*`
- ağ: `connect/WSAStartup/socket/select/send/recv/...`
- pencere: `CreateWindowEx*/DialogBox*/MessageBox*`
- süreç: `CreateProcess*/ShellExecute*/WinExec`
- bekleme: `Sleep*/WaitForSingleObject*/WaitForMultipleObjects*/WaitForOnAddress*`
- `ExitProcess` ailesi → doğal son (duvar DEĞİL — ayrı sınıflandırılır)
- bütçe: komut sayısı / süre dolarsa → BUTCE (raporlanır, sessiz değil)
- eşlenmemiş bellek erişimi / CPU istisnası (`int 0x29` __fastfail dahil) → HATA + rip

### 2.2 Kanıt üretimi (initFacts overlay)

```
WinInit::Run
  ├─ [1] kendi MappedImage kopyası (Shell görüntüsüne DOKUNMAZ — sıfır yan etki)
  ├─ [2] TEB/PEB gerçek NT düzeni (x86: Self+0x18, PEB+0x30, TLS dizi+0x2C ...)
  ├─ [3] TLS dizini: __tls_index=0 + callback'ler (EP'den ÖNCE, stdcall)
  ├─ [4] EP yürütme (Unicorn, gerçek CRT kodu — metin2client STATİK CRT doğrulandı)
  ├─ [5] duvar/bütçe/hata → temiz duruş + son-40-API ve son-400-komut teşhisi
  └─ [6] ANLIK GÖRÜNTÜ: yazılabilir bölümlerde değişen her slot + heap'te
         vftable-benzeri her değer → overlay (VA → değer, IAT/shadow/0 filtreli)
```

**Overlay'in devirt'e bağlanma kuralı (kontrollülük):** öncelik `IAT > statik yazıcı >
init-overlay > imaj baytı`. Statik kanıt (kurucu/atlas) her zaman kazanır; overlay yalnız
statik kanıtın sussa kaldığı yerde konuşur. Kullanıldıysa kanıt etiketi dürüstçe
`WinInit init-anlık-görüntüsü (Tier-5a)` olur (`proofKind="init"`, kırılımda ayrı satır).
`wininit off` → overlay anında düşer, motor v8.1 saf statik davranışa döner.

Heap düzeni DevirtEmu ile örtüşür (x86-32: 0x52000000 taban; tier-3 yığını 4→16 MB
yapıldı — yalnız kapasite, davranış değişmedi). Böylece overlay'deki heap adresleri
Tier-3'ün kendi emülatöründe de geçerlidir: `[g_singleton] = 0x5200xxxx` ve
`[0x5200xxxx] = vftable` zinciri tier-3 penceresinde GERÇEK bellekle okunur.

### 2.3 Kontrollü kanıt: `fixture_wininit.exe` (yeni fixture, elle inşa)

Metin2 deseninin minyatürü: TLS callback (statik tarayıcı FONKSİYON olarak bile görmez —
kodda çağrısı yoktur, yalnız TLS dizininde referansı vardır), heap'e kurucu yazımı
(statik değerlendiricide `call` sonrası eax boşalır — kanıtlanamaz), duvar API'li EP.

| Soru | Cevap |
|---|---|
| TLS callback EP'den önce koştu mu? | **Evet — 1/1** |
| Duvarda temiz duruş | **Evet — USER32.GetMessageA** |
| Statik slot değişimi | 2/2 (g_vptr_slot + g_heapobj) |
| Heap vptr | 1/1 |
| Overlay | 3 giriş (2 statik + 1 heap vptr) |

**Devirt sonuçları (aynı fixture, üç senaryo):**

| Senaryo | Evren | Çözülen | Kırılım |
|---|---|---|---|
| GodTier v9.1 (WinInit'siz) | 4 | 2 | IAT 2 — kalan 2 dürüstçe sanal |
| **GodTier v9.2 + WinInit** | 4 | **4** | IAT 2 + **init 2** (TLS-only + heap-only zincirler) |
| **Ghidra 12.2** (headless, tam analiz) | 4 | **2** | yalnız IAT — `call ecx` ve `call [ecx+4]` çözülmeden |

Yani: WinInit'in getirdiği 2 çözümün **tam aynı ikilisi Ghidra'da da karanlıkta** —
kanıt zincirinin yalnız Windows-init benzetimiyle aydınlanabileceği yer.

---

## 3. WinInit'in Enstrüman Olduğu Yer: 6 Gerçek Hata Avı

Fixture ve metin2 koşuları, motorun EMÜLASYON katmanında önceden var olan 6 hatayı
ortaya çıkardı — hepsi düzeltildi, hepsi raporlu (dosya:satırları commit'te):

| # | Hata | Etki (v8.1'de) | Düzeltme |
|---|---|---|---|
| 1 | `HookCode` x86-32 args döngüsünde `u64 esp;` **başlatılmamış** — unicorn ESP'nin yalnız 4 baytını yazar, üst 4 bayt çöp kalır | x86-32 IAT-shim **argümanları hiç okunamıyordu** (hep 0) | `u64 esp = 0;` |
| 2 | `ApiShim::Handle` dönüş adresini her genişlikte **8 bayt** okur | x86-32'de arg1, retAddr'e taşıp EIP'ı zehirliyordu (yalnız truncation şansla kurtarıyordu) | mimariye göre 4/8 bayt oku |
| 3 | x86-32'de `uc_reg_write(UC_X86_REG_RAX,...)` **sessizce işe yaramaz** (32-bit modda 32-bit reg kimliği gerekir) | **API dönüş değeri EAX'a hiç yazılmıyordu** — HeapAlloc hep 0 döner sanılıyordu | `UC_X86_REG_EAX` + u32 |
| 4 | PE TLS dizini alanları **absolute VA** iken kod ImageBase **ekliyordu** | TLS callback adresleri iki katına çıkıyordu (0x402014→0x802014) | spesifikasyon doğru uygulandı (PE32: +12, PE32+: +24 ofset genişlik-farkında) |
| 5 | `HookMemInvalid` `UC_MEM_*_UNMAPPED` tiplerini YAZMA yerine OKUMA basıyordu | hata raporları yanıltıcı | UNMAPPED varyantları doğru sınıfla |
| 6 | `LoadLibraryExW` bilinmeyen API olup 0 döndürüyordu; `GetProcAddress` **çağrılabilir** adres döndürmüyordu | statik UCRT CRT-init'i erken çıkıyordu / sahte adrese çağrıp çöküyordu | sahte modul handle + **dinamik API stub bölgesi** (0x76000000): GetProcAddress'ın döndürdüğü stub gerçekten ÇAĞRILABİLİR, shim yakalar; `InitializeCriticalSectionEx` (12B stdcall) tabloya eklendi |

Bu tablo V9 karar planının Faz 0 ruhunu (doğruluk önce) somutluyor: yeni kapasite eklerken
bulunan her hata, mevcut kullanıcıları da düzeltti. Hiçbiri varsayılan davranışı
değiştirmiyor (özellikle #1-#3 yalnız API-shim yoluyla koşan emülasyonları etkiler; test
suitesi ve metin2 kırılımları bit-bitiye aynı — bkz. §6).

---

## 4. TÜM DOSYALARDA ÇALIŞMA (genellik denetimi)

- WinInit **tamamen jenerik** PE32/PE32+ (x86/x64) üzerindedir: metin2 sabiti YOK;
  duvar listesi genel Win32; stdcall tablosu ~200 genel API; çevre değerleri (PID/TID/saat/
  QPC/komut satırı) deterministik-generic. Test [29] x64 yolunu (fixture.exe, PE32+)
  koşar — EP kendi ret'iyle biter, düzgün sınıflanır.
- Motorun metin2'ye özgü hiçbir sabiti çekirdekte değil: 0x4EAD70 vb. yalnız `scripts/*.gt`
  analiz betiklerinde.
- ELF: analiz/devirt/tier-3 yolları zaten ELF fixture'larıyla test ediliyor (kurban*.elf,
  342 testin içinde); WinInit'in ELF karşılığı (ld.so + `__libc_csu_init` benzetimi) yol
  haritasında — PE evreni öncelikli (kullanıcının binary'si + tüm Windows oyunları).
- Sınır dürüstçe: WinInit yalnız PE'de çalışır; ELF'te açık uyarı basar.

---

## 5. "Derleyip Aynı Projeyi Çalıştırabilir miyiz?" — Yeniden-Derlenebilirlik Merdiveni

Soruyu ciddiye alıp mühendislik hedeflerine böldük. "Çalıştırılabilir"in tanımı önemli:
**davranışsal eşdeğerlik** hedef (bit-bitiye aynı binary imkânsız — derleyici sürümü,
optimizasyon, layout değişir; /BASE:0x400000 + /FIXED ile mutlak-adres uyumu korunabilir).

### R0 — Derlenebilir pseudocode (her fonksiyon → geçerli C++)
Statik tipler + PDB tipleri + devirt kanıtlarıyla üretilen kodun `cl /c` geçmesi.
**Durum:** pseudocode motoru zaten C-benzeri üretiyor; PDB'siz binary'lerde tip tahmini
hataları R0'ın önündeki ana engel. PDB'li metin2 için R0 gerçekçi bir hedeftir (176.018 tip
/ 23.479 fonksiyon imzası hazır). R0'ın yan ürünü dev: **derleyici tip-denetçisi, tip
çıkarımımızın dış denetçisi olur** (yanlış struct düzeni = derlenmez).

### R1 — Diferansiyel-test sertifikalı fonksiyonlar (birim düzeyde "aynı")
**Bizim özgün kaldıracımız.** Bir fonksiyon için: (a) orijinal binary'den Unicorn'da N
girdi vektörüyle koştur (init-anlık görüntüsü + Tier-3 altyapısı ZATEN elimizde), (b)
decompile edilmiş + derlenmiş halini aynı girdilerle koştur, (c) çıktı/exit-state
bit-bitiye eşitse **R1 sertifikalı**. Bu, "%100 decompile" sloganını **fonksiyon-başına
ölçülebilir söze** çevirir: R1 oranı = nesnel kalite metriği. Hiçbir ticari araç bunu
dışarıdan sunmaz; bizim mimaride parçaları hazır.

### R2 — Çalışan klon (çift-tık → oyun açılır)
Gereksinimler: (1) %100 fonksiyon kapsamı + doğru imzalar, (2) tüm .data/.rdata
rekonstrüksiyonu — tablolar, stringler, vtable+RTTI dizileri (PDB 4.434 globalin tipini
verir; WinInit anlık görüntüsü ÇALIŞMA ZAMANI değerlerini verir — ikisi birleşince veri
sadakati tarihsel olarak zor olan parça kapanır), (3) statik-bağlı CRT/STL kodu ya
yeniden derlenir ya birebire taşınır, (4) UB bağımlılıklarının ayıklanması (init-edilmemiş
okuma, heap-layout varsayımı), (5) anti-tamper (varsa self-checksum — yeniden derlenen
kod BY TANIM farklı baytlar üretir; kaldırılması gerekir). re3 (GTA III) ve SM64-decomp
gibi projeler bunu İNSAN-YILLARIYLA yaptı; otomatik yapan araç YOK. Bizim avantajımız:
PDB + kanıt-devirt + init-anlık görüntüsü + Tier-5b paket simülasyonu — bunlar R2'nin en
pahalı üç kalemini (tipler, dispatch, init-durumu) otomatikleştirir.

### R3 — Tam davranışsal eşdeğerlik (aynı sunucuda aynı oyun)
R2 + ağ protokol katmanının bit-exact davranışı + zamanlama-toleranslı determinizm.
Araştırma sınırlıdır; dürüst hedef değil, yön işaretidir.

**Sonuç:** "Her şeyi simüle edip öyle decompile edersek derleyip çalıştırır mıyız?"
— WinInit + Tier-5b + diferansiyel test ile **R1 otomatik**, **R2 insan denetimli
pipeline** hedeflenebilir; **R3 bugün için değil.** Önemli nüans: R2'ye giden yolda her
R1 sertifikası, motorun doğruluğunu da BÜYÜK ölçekte kanıtlar — R1 hem amaç hem araç.

---

## 6. Kıyaslama: GodTier v9.2 vs Ghidra 12.2 (taze koşu, bugün)

Metodoloji: Ghidra 12.2 PUBLIC (resmi release, JDK 25 + PyGhidra), `pyghidra` headless
tam otomatik analiz + `scripts/gh_bench.py` post-script (fonksiyon sayısı, dolaylı çağrı
evreni, somut-hedef bağlantısı, izlenen çağrıların çözümü, fonksiyon-keşif probları).
Hiçbir el düzenlemesi yok. GodTier aynı binary'leri kendi komutlarıyla.

### 6.1 Kontrollü fixture (fixture_wininit.exe — gerçek hedefler kaynakta sabit)

| Ölçüm | **GodTier v9.2** | Ghidra 12.2 |
|---|---|---|
| Fonksiyon | 6 (EP+ctor+2 victim+2 hedef ailesi) | 5 |
| Dolaylı çağrı evreni | 4 | 4 |
| Çözülen | **4/4** (IAT 2 + **WinInit 2**) | **2/4** (yalnız IAT) |
| `call ecx` @0x401028 (TLS-only) | **çözüldü — 0x401040, kanıt: init** | çözülmedi |
| `call [ecx+4]` @0x401037 (heap-only) | **çözüldü — 0x401050, kanıt: init** | çözülmedi |
| TLS callback'i fonksiyon olarak buldu | hayır (statik olarak görülemez — WinInit KOŞUTUR) | evet (TLS dizininden yarattı) — ama değerini kullanamaz |

### 6.2 metin2client.exe (5,2 MB, 25.673 PDB fonksiyonu, PE32, statik CRT)

**Ghidra 12.2 koşusu (bugün, tamamlanan):** 29 dk CPU — 36.152 fonksiyon (agresif
kesif), 10.826 dolaylı çağrı evreni, **3.828 somut bağlı (%35,4)** — izlenen iki
sanal çağrı da (`0x4EADA9`, `0x4EADBE`) **ÇÖZÜLMEDİ**.

| Ölçüm | **GodTier v9.2** (PDB'li) | GodTier (PDB'siz) | **Ghidra 12.2** (PDB'siz, 29 dk) |
|---|---|---|---|
| playerGetStatus @0x4EAD70 | **tam kaynak-stili** (`CPythonPlayer::Instance().GetStatus(iType)`) | vfN sözlüğüyle (`Instance().vf4`) | `**(code**)(*(int*)(DAT_008bd2d0+4)+0x10)` — ham çift-deref |
| Sanal çağrı 0x4EADA9 (slot 4) | **ÇÖZÜLDÜ → CPythonPlayer::GetStatus (0x4E2F60), kanıt zinciriyle** | çözüldü (vf4→0x4e2f60) | **çözülmedi** (taze koşu JSON'u: resolved=false) |
| Sanal çağrı 0x4EADBE (slot 34) | **ÇÖZÜLDÜ → NEW_GetMainActorPtr (0x4E26F0)** | çözüldü (vf34→0x4e26f0) | **çözülmedi** |
| Toplam devirt (evren) | **4444/9160 = %48,5** | 3358/7855 = %42,7 | 3828/10826 = **%35,4** (daha geniş evren: tail-jmp dahil) |
| Çözüm başına kanıt | **her çözümde kanıt zinciri + sınıf adı + slot** (PDB'sizde de RTTI'dan) | aynı | bağlantı var, kanıt zinciri yok |
| Analiz süresi | **16,5 sn** (PDB+RTTI+WinInit+devirt+decomp) | 7,2 sn | **~29 dk** (tek süreç, tam analiz + post-script) |

(Not: Ghidra'nın PDB yüklemesi headless-Linux'ta Windows PDB evrensel ayrıştırıcısıyla
sınırlıdır; kıyas PDB'siz tarafta dürüst kurgulandı — PDB üstünlüğü bizim elimizde
ayrı bir katmandır: 176.018 tip + 23.479 isim. Ghidra evreni daha geniştir — tail-jmp
sanalları ve daha agresif fonksiyon kesfi (36.152 vs 25.673 PDB fonksiyonu) sayar;
oran kıyası (%48,5 vs %35,4) buna rağmen bizde. Ham JSON: `scripts/` klasöründe
`gh_bench.py` ile yeniden üretilebilir.)

**IDA Pro/Hex-Rays:** lisanslı ürün — bu sandbox'ta koşturulamaz; sahte "koşuttum"
iddiası GOD TIER'da yeri olmaz. Kayıtlı gözlem (v8 dokümanı §7): Hex-Rays de bu tarz
sanal çağrıları varsayılan olarak çözmez (devirt kullanıcı betiği/FLIRT benzeri katman
ister); GodTier'in getirdiği, bunun KANIT ZİNCİRİYLE ve PDB'siz RTTI sınıf adıyla
otomatik yapılmasıdır. Kullanıcının erişiminde gerçek bir IDA Pro + SDK varsa
`scripts/godtier_ghidra.py` benzeri bir IDA köprüsü eklemek 1 günlük iştir — davet ederiz.)

### 6.3 "Güçlendirme düşürür mü?" — regresyon denetimi (kontrollülük kanıtı)

Aynı binary, aynı betikler, v9.2 motoru, WinInit KAPALI:

| Kırılım | v9.1 taban çizgisi | v9.2 (bugün, WinInit'siz) | Fark |
|---|---|---|---|
| PDB'li çözülen | 4444/9160 | 4444/9160 | **0** |
| kurucu/atlas/unicorn/IAT/somut | 245/236/256/3222/485 | 245/236/256/3222/485 | **0** |
| PDB'siz çözülen | 3358/7855 | 3358/7855 | **0** |
| Testler | 319 PASS | **342 PASS** | +23, 0 FAIL |

WinInit AÇIKken: toplam 4444 (aynı) ama **45 zincirin kanıt kaynağı bayat dosya baytından
GERÇEK runtime değerine** yükseldi (vtablesiz-somut 485→440, init +45) — yanlış-çözüm
EKLİLMEDİ, doğru-kaynağa GEÇİLDİ. Yeni-net-çözüm 0 olması dürüstçe raporlanır: metin2'nin
global kurucularına WinInit henüz ulaşamadı (aşağıda).

### 6.4 WinInit'in metin2 cephesi ve sınır (teşhis altın değerinde)

İlk koşu 351 komutta "EP döndü" idi → teşhis kuyruğu `LoadLibraryExW→0` gösterdi → shim
düzeltildi → `GetProcAddress("InitializeCriticalSectionEx")` çağrılabilir stub'a bağlandı →
**7.904 komut, 135 API çağrısı** (ICSEx×16, FLS ailesi, GetStartupInfoW, HeapAlloc(868)×2
= gerçek __acrt per-thread veri). Şu anki sınır:

```
0x6e7202  xor esi, [0x86640c]        ; __security_cookie (0xBB40E64E default)
0x6e720b  ror esi, cl                ; encode/decode
0x6e7210  test esi, esi
0x6e7212  jne 0x6e71d1               ; çözülen ptr != 0 → çağır
0x6e7214  call __fastfail            ; == 0 → int 0x29  ← burada duruyoruz
```

`__vcrt` per-thread dispatch tablosunun 6+ girdisi ( dinamik api-set yürüyüşünün
0x8bc1b0 tablosu) hâlâ "encoded-NULL" — bir sonraki shim turunun kesin hedefi.
**Döngü kuruldu:** koş → apiTail/traceTail teşhisi → shim → daha derin. WinInit'in kendi
raporu bu döngünün enstrümanıdır (son-40 API + son-400 komut + duruş sınıfı).

---

## 7. %100 Yol Haritasına Bağlantı (V9 karar planı güncellemesi)

- **Faz 0 (doğruluk):** #1-#5 hataları bu raporda kapatıldı (emülasyon katmanı). Kalan:
  RestoreDirty 64B sınırı, MemLog doyması, bütçe bayrakları, Cand-join — sıradaki sprint.
- **Faz 1 (ölçüm):** `devirt stats` kırılımı WinInit satırıyla zenginleşti (`byInit`).
- **Faz 2 (ucuz kazanım):** WinInit overlay'i `memFacts_` okuma yoluyla birleşebilir
  (fonksiyon-içi yaz→oku); global store merge ile çarpıcı sinerji (init yazdığını
  başkan fonksiyonlar görsün).
- **Faz 3 (nesne akışı):** WinInit'in heap-alloc kayıtları (caller VA'lı ApiCall) =
  **allocation-site kanıtının hazır hammaddesi** — `HeapAlloc(0x52002370)@caller` kayıtları
  zaten toplanıyor.
- **Faz 4-5:** Tier-5b paket simülasyonu WinInit'in duvar-farkını doldurur; dinamik iz
  (DynamoRIO/QBDI) init-anlık görüntüsünü doğrular (M3 ölçütü).
- **Yeni (bu rapordan):** R1 diferansiyel-test sertifikası — %100 sözleşmesinin nesnel
  ölçüsü olarak plana eklenmelidir.

---

## 8. Değişiklik Envanteri (commit içeriği)

**Yeni:** `src/emulate/wininit.h/.cpp` (Tier-5a), `tests/fixtures/make_fixture_wininit.py`
(+üretilen fixture), `scripts/gh_bench.py` (Ghidra 12.2/PyGhidra kıyaslama ölçeği),
`scripts/metin2_wininit.gt`, bu doküman.
**Değişen:** `apishim.h/.cpp` (duvar kipi, Win32 stdcall tablosu ~200 API, deterministik
çevre, dinamik stub üretimi, yapı-dolduran API'ler), `emulator.h/.cpp` (RunWithArgs,
Teb/Peb getter, dinamik stub bölgesi, EAX düzeltmesi, args/retAddr düzeltmeleri),
`pe.h/.cpp` (TlsDirInfo + VA düzeltmesi), `devirtpro.h/.cpp` (overlay + init kanıt etiketi
+ byInit), `devirtemu.h/.cpp` (overlay uygulama + heap 16MB), `pseudocode.h/.cpp`
(SetInitOverlay), `shell.h/shell_analyze.cpp/shell_system.cpp` (`wininit` komutu:
`wininit [bütçe] [verbose] | off | info`), `CMakeLists.txt`, `tests/test_main.cpp`
([27][28][29]), derleme yardımcısı `scripts/build_godtier.sh` (cmime'sız ortamlar için).

**Testler:** 342/342 PASS (yeni: [27] WinInit kanıtı 21 check, [28] WinInit'siz negatif
kontrol 4 check, [29] x64 duman).

---

## 9. Katkı Zinciri (v9.2)

- **Kullanıcı:** "Windows ne yaparsa aynısını simüle edelim" direktifi + stack/multithread/
  WinMain-olasılık-zinciri soruları + "tüm dosyalarda çalışsın" + "güçlenmeliyiz, düşmemeliyiz"
  kontrolü + yeniden-derlenebilirlik sorusu — bu sürümün tamamı bu direktiflerin mühendisliği.
- **Motor (bu oturum):** WinInit Tier-5a tasarım/uygulama, 6 hata avı, kıyaslama altyapısı,
  regresyon kanıtı, R0-R3 merdiveni + diferansiyel-test orakcı.
- **4-AI sentezi (v9.1 dokümanları):** teori çerçevesi (Rice düzeltmesi), beşli sınıflandırma,
  hata avı listesi — WinInit, planın Faz 3/4/5'lerine hammadde akıtır.

> **SINIR YOK — EN İYİSİ OLANA KADAR DURMAYACAĞIZ.**
> Sonraki durak: `__fastfail` engelini aşan shim turu → metin2 global kurucularına ulaşan
> init-anlık görüntüsü → `byInit`'in ilk NET-ARTIŞI + R1 diferansiyel test iskeleti.
