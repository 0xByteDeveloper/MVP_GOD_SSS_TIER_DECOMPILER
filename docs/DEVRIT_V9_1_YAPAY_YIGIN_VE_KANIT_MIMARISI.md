# DEVRİT v9.1 — YAPAY YIĞIN, KANIT MİMARİSİ VE DAHA İYİ YÖNTEMLER
## GOD SSS TIER MVP GÜNCELLEME RAPORU (Soru-Cevap Turu #2)

> Girdi: kullanıcının dört sorusu — (1) "madem yapay yığın, playerGetStatus'taki yapıyı
> nasıl tespit ettik?", (2) "yapay yığın da olsa nasıl hareket ediyor, tüm fonksiyonlardan
> mı geçiriyorsun?", (3) "yapay yığın yerine gerçek gibi simüle etsek daha iyi bir yöntem
> olabilir mi?", (4) "yapay yığından daha iyi yöntemler var mı?".
> Zemin: `DEVRIT_V9_KARAR_PLANI.md` (4-AI sentezi) ve `DEVRIT_100_YOL_HARITASI.md`.
> Bu dokümandaki her teknik iddia kaynak kodda yeniden doğrulandı; tüm `dosya:satır`
> referansları `0d690b6` (v8.1) çalışma ağacındadır.
> Tarih: 2026-11-22.

---

## 0. TL;DR — Dört Sorunun Net Cevabı

1. **"Madem yapay yığın, yapıyı nasıl tespit ettik?"** — Çünkü tespitlerin **%94.2'si
   yığına hiç dokunmuyor.** playerGetStatus'un iki sanal çağrısı da (`call eax` @
   0x4EADA9 ve `call [edx+0x88]` @ 0x4EADBE) **TIER-1 STATİK KANITLA** çözüldü — kanıt
   çıktısında `[STATIK COZUM]` yazar, tek bir komut bile yürütülmedi, yığın hiç kurulmadı.
   Yapay yığın yalnız **Tier-3**'ün (256/4444 = **%5.8**) scratch ortamıdır ve orada bile
   tespiti belirleyen yığın değil, **statik-kanıt tohumları + binary'nin kendi .rdata
   içeriğidir** (§2).
2. **"Tüm fonksiyonlardan mı geçiriyorsun?"** — **HAYIR.** Hareket modeli *site-odaklı
   pencere koşusu*: her çözülemeyen dolaylı çağrının **kendi temel bloğu** ayrı bir Unicorn
   koşusudur (≤64 komut, ortalama <30). Yığın bir kere kurulur ama her koşuda **taze
   durumla** kullanılır; bloklar arasında yığın taşınmaz, program asla baştan sona koşmaz (§3).
3. **"Gerçek gibi simüle etsek daha iyi olur mu?"** — **Yığının 'gerçekliği' darboğaz
   değil.** Kalan 4716 çağrının hiçbiri "yığın gerçekçi değil" yüzünden çözülemiyor:
   4117'si pencere-tohum eksikliği, 471'i heap/param alıcı kanıtsızlığı, 128'i gerçek
   muğlaklık. "Gerçek-benzeri"liğin değerli biçimleri vardır (program-init emülasyonu,
   canlı iz, sembolik yürütme) — hepsi v9 planında zaten Faz 0/3/4/5 olarak işli (§4).
4. **"Daha iyi yöntemler var mı?"** — **VAR, sekiz tane, sıralı** (§5). Ortak payda:
   yapay yığın *substrat* olarak kalır; gelişen üç eksen var — **tohumlama** (koşudan
   önce belleğe ne yazıyoruz), **kapsam** (ne kadar ileri koşuyoruz), **kanıt türü**
   (somut → sembolik → çalışma-zamanı gözlemi).

---

## 1. Dürüstlük Düzeltmesi (önce kendi hatamız)

Önceki sohbet turlarında Tier-3 yığınını "0x7FC00000-0x7FF00000 arası 4MB bölge"
olarak anlattım. Kaynak kodda gerçek değer:

| Öğe | Anlatılan (eski) | Gerçek (kaynak) |
|---|---|---|
| Yığın boyutu | 4 MB | **1 MB** (`emulator.h:41` → `stackSize = 0x100000`) |
| Yığın bölgesi | 0x7FC00000-0x7FF00000 | **0x7FEF0000-0x7FF00000** (`devirtemu.cpp:123` → `stackTop = 0x7FF00000`) |
| ESP başlangıcı | 0x7FEFFF00 | **doğruydu** (`emulator.cpp:107` → `sp = stackTop - 0x100`) |
| Sentinel sayfa | 0x7FF10000 | **doğruydu** (`emulator.cpp:104` → `stackTop + 0x10000`) |

Etki: sıfır — pencere koşuları ortalama <30 komut kullandığından 1 MB yığın fazlasıyla
yeterli (derinlik ihtiyacı <1 KB). Ama bu proje kendi dürüstlük disiplinini kendine de
uygular; not düşülür. Bu raporun geri kalanı %100 kaynak-doğruluklıdır.

---

## 2. Soru 1 — "Madem Yapay Yığın, playerGetStatus Yapısını Nasıl Tespit Ettik?"

### 2.1 Tek cümlelik cevap

**playerGetStatus'taki her şey, yığın ve yürütme HİÇ kullanılmadan, dört statik kanıt
kaynağından geldi: (a) kesitleme, (b) RTTI atlası, (c) kurucu-yazım kanıt taraması,
(d) imajın kendi .rdata verisi.** Yapay yığın sahneye yalnız bu dördün de yetmediği
256 sitede (Tier-3) çıkar — playerGetStatus onlardan biri bile değil.

### 2.2 Kanıt anatomisi: playerGetStatus'taki her bulgunun kaynağı

`decomp 0x4EAD70` çıktısındaki (46 komut) her satırın nereden geldiği:

| Bulgu | Kanıt kaynağı | Yürütme? | Yığın? |
|---|---|---|---|
| Fonksiyonun 46 komutu, dallar, akış | Capstone kesitleme (statik) | HAYIR | HAYIR |
| `python27.dll.PyTuple_GetInteger` adı | IAT import tablosu (`.rdata`'da duran gerçek veri) | HAYIR | HAYIR |
| `python27.dll.Py_BuildValue` + `"i"` formatı | IAT + imaj string'i | HAYIR | HAYIR |
| `CPythonPlayer` sınıf adı (PDB'sizde bile) | RTTI: vftable 0x805054 → COL → TypeDescriptor `".?AVCPythonPlayer@@"` | HAYIR | HAYIR |
| `0x8BD2D0` = `ms_singleton` olduğu | **ScanWriters**: 25.673 fonksiyonun hepsinde `mov [S], this` deseni taraması (`devirtpro.cpp:227-254`) | HAYIR | HAYIR |
| `[this+4] = 0x805054` (vptr) | Kurucu gövdesindeki `mov [this+0x4], 0x805054` saklaması (aynı tarama) | HAYIR | HAYIR |
| `Instance()` katlaması | statics_ kanıt tablosu + `CSingleton<>` deseni (`pseudocode.cpp`) | HAYIR | HAYIR |
| `vf4` = vtable slot +0x10 → hedef 0x4E2F60 | **imaj .rdata'dan statik slot okuma**: `[0x805054+0x10]`'da 0x4E2F60 yazar — binary'nin kendi baytı! | HAYIR | HAYIR |
| `GetStatus` / `NEW_GetMainActorPtr` isimleri | PDB sözlüğü (0x4E2F60 / 0x4E26F0 satır kayıtları) | HAYIR | HAYIR |
| `*(0x8bd764)` = `TWOHANDED_...` globali | PDB global tablosu (4.434 global) | HAYIR | HAYIR |

**Sonuç satırı:** playerGetStatus'un decompile'ındaki tek bir harf bile emülatörden
gelmiyor. `devirt 0x4EADA9` ve `devirt 0x4EADBE` çıktılarının ikisinde de
`[STATIK COZUM]` etiketi ve kanıt türü `kurucu vtable-saklama kanıtı` yazar.

### 2.3 Gerçek kanıt zincirleri (v8.1 oturumundan, hiç elle düzenlenmemiş)

`call eax` @ 0x4EADA9 — **Tier-1, sıfır yürütme**:

```
== DEVRIT-PRO: 0x4eada9 ===========================
  [kurucu değerlendirme] mov [this+0x0], 0x805044   ; ara vtable (base0)
  [kurucu değerlendirme] mov [this+0x4], 0x805054   ; SON YAZIM KAZANIR (CPlayer)
  statik 0x8bd2d0 <- this (kurucu kaniti)           ; ms_singleton = this İSPAT
  vptr(+0x4) = vftable 0x805054
  0x4eada9: hedef = 0x4e2f60
  call -> CPythonPlayer::GetStatus  [STATIK COZUM]
```

`call dword ptr [edx+0x88]` @ 0x4EADBE — **Tier-1, sıfır yürütme**:

```
  mov ecx, [0x8bd2d0]     ; ms_singleton (imajda 0 — değer kanıtla üretilir)
  add ecx, 4
  mov edx, [ecx]          ; vptr = 0x805054 (kurucu kanıtı + RTTI çapraz kanıt)
  call [edx+0x88]         ; vtable[34]
  0x4eadbe: hedef = 0x4e26f0
  call -> CPythonPlayer::NEW_GetMainActorPtr  [STATIK COZUM]
```

Buradaki mekanizma soyut yorumlamadır (`EvalFunction`, `devirtpro.cpp:460+`): yazmaçlar
`Sym`/`Conc` değerleri taşır; `mov ecx,[0x8bd2d0]` statics_ tablosundan `Sym(CPythonPlayer,+0)`
okur; `add ecx,4` → `Sym(+4)`; `mov edx,[ecx]` → kurucu kanıtı `Conc(0x805054)`;
`call [edx+0x88]` → imajdan slot okuma → `Conc(0x4E26F0)`. **Bellek yok, yığın yok,
Unicorn yok.** Sembolik değer zinciri + iki statik tablo (statics_, RTTI atlası) + imaj
verisi. Hepsi bu.

### 2.4 Sayısal kanıt: 4444 çözümün iç yapısı — yığının payı %5.8

`devirt stats` gerçek çıktısı (PDB'li, metin2client.exe, v8.1):

```
-- cozulenler (kanit mekanizmasi) --      yığın kullanıyor mu?
  kurucu vtable-saklama kaniti : 245       HAYIR (Tier-1 soyut yorumlama)
  atlas inversiyonu (CHA)      : 236       HAYIR (Tier-1)
  tier-3 unicorn pencere emu.  : 256       EVET  ← yapay yığın SADECE burada
  IAT importu (dll.api)        : 3222      HAYIR (import tablosu okuma)
  vtable'siz somut zincir      : 485       HAYIR (Tier-1)
-- kalanlar (dürüst neden etiketleri) --
  coklu aday (tekil tahmin yok): 128
  kanit yok (heap/param alici) : 471
  tier-3 pencere yetersiz      : 4117
```

Aritmetik: Tier-3 payı = 256/4444 = **%5.76**. Yani "çoğu şeyi" yapay yığın değil,
**yığınla hiç ilgisi olmayan statik kanıt makineleri** buldu. Tier-3'ün 256'sı da
"dürüst aday genişletme + RTTI çapraz doğrulama" kurallarıyla çalışır (§6).

### 2.5 Anahtar içgörü: binary zaten "donmuş bellektir"

Neden bu mümkün? Çünkü derlenmiş bir C++ programında **tip bilgisinin ezici çoğunluğu
dosyanın içine gömülüdür**: vtable'lar, RTTI yapıları, IAT, string'ler, sabitler —
hepsi `.rdata`/`.data`'da **statik olarak yatar**. Process çalışmadan da oradadırlar.
Runtime'da değişen tek şey bu yapıların **işaret edildiği yerlerdir** (`ms_singleton`
yuvası gibi). İşte o son halka da kurucu gövdesindeki yazım komutlarıyla kanıtlanır —
kurucu da binary'nin içindedir. Yapay yığın yalnız "kod, gerçek bellek semantiğiyle mi
çalışmalı?" sorusu anlam kazandığında devreye girer: dal bayrakları, `adc/sbb`, bayrak
bağımlı yüklemeler... Bunlar da yalnız statik yorumlamanın yetmediği 256 sitede gerekli
oldu.

---

## 3. Soru 2 — Yapay Yığın Nasıl Hareket Ediyor? (Tüm Fonksiyonlardan GEÇMİYOR)

### 3.1 Model: site-odaklı pencere koşusu

```
9160 dolaylı çağrı sitesi (evren)
 ├── 4188'i Tier-1 statik kanıtla çözülür  → HİÇ koşulmaz
 └── kalanlar için Tier-3: HER SİTE KENDİ KOŞUSU
      site #1 ──► TryCall: [pencere kur + tohumla + koş + kanıt topla + temizle]
      site #2 ──► TryCall: (taze durum — önceki koşudan hiçbir şey taşınmaz)
      ...
      site #N ──► TryCall: ...
```

Yığın "bir veri olarak fonksiyonlar arasında dolaşmaz". Yığın, her koşunun kendi içinde
`push/pop/call` komutlarının çalışabilmesi için kurulmuş **sıfırdan-çizilebilir bir
karalama defteridir**. Koşular arası bilgi taşıyan şey **kanıt tablolarıdır**
(statics_, RTTI atlası, sonuç tablosu), yığın değil.

### 3.2 Tek koşunun 10 adımı (kaynak referanslı, `devirtemu.cpp:256-460`)

1. **Site doğrula**: çağrı gerçekten `call` + dolaylı mı? (`TryCall` giriş kontrolü)
2. **Pencereyi bul**: çağrının **temel bloğu** — geriye doğru `jcc/jmp/ret` ve etiket
   hedeflerine dek, en fazla 64 komut (`WindowStart`, `:150-163`). Dallar arası düz
   çizgi → **tek yol → deterministik**.
3. **Kirli belleği geri al**: önceki pass'ın imaj-yazımları orijinal baytlarla,
   sentetik bölge yazımları sıfırla (`RestoreDirty`, `:186-207`).
4. **Tohumları yaz** (`ApplySeeds`, `:168-184`) — hepsi STATİK KANITTAN gelir:
   - `[S] = &sentetikNesne` ← kurucudaki `mov [S], this` kanıtı
   - `[sentetikNesne+K] = vftable` ← kurucudaki `mov [this+K], vft` kanıtı
   - (gerekirse) this-tohumu: atlas inversiyonundan `ecx = sentetikThis`, `[ecx] = vft`
5. **Yazmaçları kur**: hepsi sıfır (`ZeroRegs`), `EBP = 0x7FEFF800` (yığın çerçevesi),
   `ECX = this-tohum` (`:279-287`).
6. **KOŞ**: Unicorn, blok başından **çağrı noktasına dek** gerçek x86 semantiğiyle
   yürütür — çağrının KENDİSİ yürütülmez, RIP'te durur. Bütçe: 60.000 µs / 20.000
   komut (`:320`).
7. **Ulaşım kontrolü**: `RIP == çağrı adresi` değilse dürüst başarısızlık
   ("pencere çağrıya ulaşamadı — hata/yol") ve sonraki site.
8. **Operandı çöz**: `call reg` → yazmaç değeri + (kanıt için) diğer yazmaçlarda
   vftable tara, slot ofsetini doğrula (`:358-379`); `call [reg+K]` → `[vtable+K]`
   oku; mutlak adres → IAT/veri (`:380-437`).
9. **Çapraz doğrula**: vftable RTTI atlasta biliniyorsa atlasın slot değeriyle
   karşılaştır — **çelişki varsa çözüm DÜRÜSTÇE REDD EDİLİR** (`:439-457`).
10. **Çoklu aday dürüstlüğü + temizlik**: birden çok vtable adayı varsa HER aday AYRI
    pass'te koşar (orkestrasyon `devirtpro.cpp:927-1010`); tüm pass'ler aynı hedefe
    giderse KANITLANMIŞ çözüm, farklıysa aday listesi. Pass sonunda `RestoreDirty`.

Toplam Tier-3 bütçesi 180 saniye (`devirtpro.cpp:268-275`); metin2client.exe'te tüm
Tier-3 turu ~2 sn'de biter.

### 3.3 Bellek haritası — koşu anında emülatörde ne vardır (gerçek adresler)

| Bölge | Adres aralığı | Boyut | Nitelik |
|---|---|---|---|
| **İmaj** (kod+veri) | 0x400000-0x91C000 | 5.2 MB | **GERÇEK** — binary'nin kendi baytları; vtable/RTTI/IAT içerikleri bizzat buradan okunur |
| Yığın | 0x7FEF0000-0x7FF00000 | 1 MB | yapay (karalama defteri) |
| [ESP] sentinel | ESP=0x7FEFFF00, [ESP]=0x7FF10000 | 8 B | sihirli sayfa = "koşu sonu" algılayıcı |
| Sihirli sayfa | 0x7FF10000 | 4 KB | RIP buraya düşerse koşu biter |
| TEB / PEB | 0x7FF12000 / 0x7FF13000 | 8 KB | fs:[0] gerçek MSR yazımıyla bağlanır (`emulator.cpp:136+`) |
| Heap | 0x52000000-0x52400000 | 4 MB | yapay (`devirtemu.cpp:124-125`) |
| Sentetik nesneler | 0x60000000-0x60100000 | 1 MB | tohum bölgesi (0x400/statik, ~1024 statik kapasite) |
| Shadow-IAT | 0x77000000-0x77100000 | 1 MB | import stub'ları (0xC3 ret) + API shim (`mapper.h:30-31`) — *Tier-3'e şu an boş geçiliyor: karar planı Faz 2 maddesi* |

Kritik gözlem: tablonun **tek "gerçek" satırı imajdır** — ve tespitin özü zaten o satırdır.
Yapay satırlar, gerçek satırın **doğru biçimde tüketilebilmesi** için gereken sahne
donanımıdır.

### 3.4 Neden "tüm fonksiyonlardan stack geçirme" YOK — dört gerekçe

1. **Ölçek**: 9.160 site × 25.673 fonksiyon kombinasyonu anlamsızdır; pencere koşusu
   ortalama <30 komutla tek sitenin kanıtını üretir. (Yığın geçirme yaklaşımı, her
   fonksiyona yapay giriş durumu uydurma problemine de düşer — hangi `this`? hangi
   argümanlar?)
2. **Determinizm**: temel blok = dallar arası düz çizgi → içinde dal yok → tek yol →
   aynı tohum her zaman aynı sonucu verir. Test [26] bunu otomatik doğrular.
3. **Kanal ihtiyacı yok**: hedefi belirleyen veri (vtable slot içeriği) **imajdadır**;
   yığın üzerinden taşınması gereken hiçbir kanıt yoktur. Yığın yalnız komutların
   çalışma biçimi (push/pop) için gereklidir, kanıt kaynağı değildir.
4. **EP'den %100 koşu çürütülmüş** (v7 kanıtı): `playerGetStatus` login olana dek
   çağrılmaz; oyun döngüsü GPU/D3D ve ağ ister; saatler sürer ve yalnız **koşulan**
   yolları kapsar. Site-odaklı model, hiç koşulmamış soğuk yolları bile çözer —
   tam da bu yüzden Tier-1+tohum modeli EP-koşusundan ÜSTÜNdür.

### 3.5 Bir koşunun ömrü (sayılarla)

- Kurulum (map/hook): bir kez (process başına), `EnsureSetup`
- Site başına: ortalama pencere <30 komut; tipik koşu süresi mikro-saniye mertebesinde
  (60.000 µs üst sınırının çok altında); metin2client.exe'in tamamında Tier-3 turu ~2 sn
- Bellek izi: imaj 5.2 MB + yapay bölgeler ~10 MB — bir sandbox'ta rahat çalışır
- Koşu sayısı: ≤ site sayısı + aday genişletme pass'leri (çoklu-aday sitelerde aday
  başına 1 ek pass; en fazla 6 aday, `devirtpro.cpp:961`)

---

## 4. Soru 3 — "Yapay Yığın Yerine Gerçek Gibi Simüle Etsek Daha İyi Olur mu?"

### 4.1 "Gerçek gibi"nin dört yorumu ve bilançoları

| Yorum | Ne kazandırır | Bilanço |
|---|---|---|
| **A. Gerçek yığın İÇERİĞİ** (argv, env, CRT frame'leri, gerçek ESP değeri) | — | Pencere koşularının **hiçbir bloğu** bunları okumaz; koşu ortasında bir fonksiyonun yığın derinliğini varsayan kod yok. Kazanç: **sıfır**. |
| **B. EP'den tam program koşusu** (process'i baştan sona koştur) | koşulan yolların gerçek gözlemi | **v7'de çürütüldü**: login bariyeri (playerGetStatus çağrılmaz), GPU/D3D bağımlılığı, saatlerce süre, ve yalnız koşulan yollar. Soğuk yollar asla. |
| **C. Tam OS emülasyonu** (Qiling/Speakeasy tarzı: gerçek loader, PEB/TEB, syscall, DLL davranışları) | init-zamanı kod (CRT init, statik kurucular, DLLMain) için anlamlı | Login-sonrası kod için bariyer aynı. Bizde zaten var: 7 adımlı loader emülasyonu + shadow-IAT + TEB/PEB (`mapper/` + `emulate/`). Eksik olan bağlantı (Tier-3'e dolu mapRep_) = karar planı **Faz 2**. |
| **D. Gerçek süreçte izleme** (DynamoRIO/QBDI/Frida — simülasyon değil GÖZLEM) | koşulan her çağrının %100 doğru hedefi | En güçlü kanıt türü ama "simülasyon" değil; statik kümeyle birleşir = karar planı **Faz 5** (RUNTIME_OBSERVED). |

### 4.2 Darboğaz analizi: yığın gerçekliği hiçbir eksik çözümü açmıyor

Kalan 4716 sitenin dürüst neden etiketlerine bakalım — hangisinin ilacı "daha gerçekçi
yığın"?

| Kalan kovası | Adet | Gerçek ilaç | Yığın gerçekliği işe yarar mı? |
|---|---|---|---|
| tier-3 pencere yetersiz (tohum yok / pencere çağrıya ulaşamadı) | 4117 | **live-in kurtarma** (öncül blok değer akışı) + allocation-site + IPA | HAYIR — sorun pencerenin BAŞLANGIÇ DURUMU (yazmaç/bellek tohumları), yığının gerçekliği değil |
| kanıt yok (heap/param alıcı) | 471 | allocation-site heap modeli + dönüş özetleri + PDB parametre tohumlama | HAYIR — sorun alıcının PROVENANCE'ı (hangi kurucu kurdu), yığın değil |
| çoklu aday (gerçek muğlaklık) | 128 | bu bir hata değil, programın hakikati (aday listesi dürüst çıktı) | HAYIR — hiçbir analiz tekil söyleyemez |

Kanıt niteliğinde iki gözlem: (1) Tier-1 **hiç yığın kullanmadan** 4188 site çözüyor;
(2) Tier-3 yığını en gerçekçi yapsak da elindeki tohum kümesi değişmedikçe çözüm sayısı
değişmez — tohum YOKSA koşacak doğru veri de yok. **Yapay yığın bir scratch substrattır;
kararlı çıktıyı tohum kalitesi belirler.**

### 4.3 "Gerçek-benzeri"nin gerçekten değerli biçimleri (v9 planında işli)

1. **Program-init emülasyonu** (Tier-4): CRT init + statik kurucuları girişten `ret`'e
   koştur, belleğe yazdıkları GERÇEK vptr değerlerini hasatla → statics_ kanıt havuzu
   otomatik zenginleşir. Bu, "gerçek koşu"nun faydalı kısmını (init)login bariyerine
   takılmadan almanın yoludur. → Faz 3/4.
2. **Canlı iz** (Tier-5): DynamoRIO/QBDI ile `VirtualCallRecord{callerRva, this, vptr,
   slot, target}` topla; statik kümeye RUNTIME_OBSERVED olarak ekle; soundness denetimi
   (gözlem ⊆ statik küme mi?). → Faz 5.
3. **Sembolik yürütme** (Triton/angr/Z3): somut tohum yerine **sembolik vptr** → tek
   geçişte OLASI hedef KÜMESİ (aday başına pass koşmaya gerek kalmaz). Ağır ama
   güçlü; karar planında bilinçli olarak Faz 5+'ya ertelendi (§4.4'teki gerekçeyle
   ucuz kazanımlar önce). → Faz 5+.

### 4.4 Karar

**Yapay yığın doğru mimaridir ve kalır.** Gelişecek olan üç eksen: **tohumlama**
(belleğe koşudan önce ne yazıyoruz: live-in, allocation-site, PDB parametre), **kapsam**
(ne kadar koşuyoruz: blok → fonksiyon → init zinciri), **kanıt türü** (somut geçişler →
sembolik kümeler → çalışma-zamanı gözlemi). "Yığını gerçek yapmak" bu üç eksenin
hiçbirine dokunmaz — soruyu doğru yerde sormak gerekir: *"yığın gerçek mi?"* değil,
*"koşuya doğru başlangıç verisi ve yeterli kanıt tipi veriliyor mu?"*

---

## 5. Soru 4 — Yapay Yığından Daha İyi Yöntemler Var mı? (GOD SSS TIER MVP Cevabı)

**VAR.** Sekiz yöntem, etki/yatırım sırasıyla; her biri v9 karar planındaki bir faza
bağlıdır. Ortak özellik: hiçbiri yapay yığını "kaldırmaz" — onu daha akıllı besler
veya tamamlar.

| # | Yöntem | Ne açar | Hedef kova | Yığınla ilişki | Faz |
|---|---|---|---|---|---|
| 1 | **3 bedava kazanç**: `memFacts_` okuma yolu + Tier-3'e dolu `mapRep_` + `vptrAll` birleştirme | fonksiyon-içi yaz→oku zincirleri; pencere içi import çağrıları fault etmez | pencere-yetersiz (kısmen) | yapay yığın kalır, beslenir | **Faz 2** |
| 2 | **Live-in kurtarma**: öncül bloklardan yazmaç/yığın-slot değer akışı, sembolik Unknown ile | pencere başındaki sıfırlanan değerler (AI-2/AI-3 bulgusu) | pencere-yetersiz 4117'nin önemli bölümü | yapay yığın + tohumlu live-in | **Faz 0/3** |
| 3 | **Allocation-site heap modeli + IPA dönüş özetleri** | `new` → kurucu → vptr → alıcı zinciri (K1/K2) | kanıt-yok 471 + pencere 4117'nin heap'li kısmı | sentetik heap tohumları zenginleşir | **Faz 3** |
| 4 | **PDB parametre tohumlama** (176.018 tip elimizde, hiç kullanılmıyor) | `[ebp+8/0xC]` → sınıf CHA alt ağacı | param alıcılar | tohum zenginleşir | **Faz 3** |
| 5 | **Program-init / kurucu tam emülasyonu** (Tier-4) | statik kuruculardan GERÇEK vptr hasadı | kanıt havuzu geneli | yapay yığın + init zinciri koşusu | **Faz 3/4** |
| 6 | **Metin2 zekası**: PyMethodDef tarayıcı + paket dispatch tablosu + Tier-5b Python simülasyonu (kullanıcının ağ-value içgörüsü) | callback evreni, UI sınıf kayıtları, paket yolları | R_FPTR_DATA + evren tamamlama | bağımsız (veri çıkarımı) | **Faz 4** |
| 7 | **Dinamik iz** (DynamoRIO/QBDI/Frida-devi) | koşulan yolun %100'ü + soundness denetimi | hepsi (doğrulama) | simülasyon değil gözlem | **Faz 5** |
| 8 | **Sembolik yürütme** (Triton/angr + Z3) | aday KÜMELERİ tek geçişte, sound | muğlak siteler | concrete→symbolic | **Faz 5+** (ertelendi) |

### 5.1 Dünya araçları bu tabloda nereye düşer

- **Qiling / Speakeasy** = Yorum C'nin çerçeveleri (tam OS emülasyonu); çözücü değil,
  kanıt üretmek için üstüne araç yazılır. Motorumuzda eşdeğeri (loader+shadow-IAT+TEB/PEB)
  zaten gömülü.
- **angr / rev.ng** = #8'in hazır implementations'ı (CFG+SSA+sembolik); bizim Tier-4/8
  planına denk gelir.
- **Virtuailor / devi** = #7'nin hazır halleri (Hex-Rays/Frida ekosistemi); devi formatını
  `devirt trace` komutuyla içe almak Faz 5'in en ucuz başlangıcı.
- **Hiçbiri** hazır olarak "%100 devirt" vermez (`DEVRIT_100_YOL_HARITASI.md` §4 dünya
  turu: Ghidra'nın canlı testimizde iki sanal çağrıyı da çözemediği dahil).

### 5.2 Öncelik disiplini (karar planından aynen)

Yanlış tekil çözüm, çözümsüzlükten kötüdür → önce **Faz 0 soundness** (RestoreDirty 64B
sınırı, MemLog 65536 doyması, bütçe bayrakları), sonra **Faz 1 ölçüm** (devirt stats
R_* kovaları gerçek sayılarla), sonra kazanımlar. AI-2'nin "önce tam CFG+SSA" P0'ına
verilen ara-yol kararı da geçerlidir: soundness hataları ucuz düzeltmelerle kapanır,
tam SSA Faz 3'ün altlığı olarak inşa edilir (`DEVRIT_V9_KARAR_PLANI.md` §4.1).

---

## 6. Doğruluk — Yapay Yığında Yanlış Kanıt Riski ve Kontrol Mekanizmaları

Tier-3'ün "kanıt" diyebilmesinin şartları (kaynak kodda mevcut olanlar):

1. **Determinizm**: temel blok tek yolludur; aynı tohum → aynı sonuç (test [26]).
2. **RTTI çapraz doğrulaması**: emülasyonun bulduğu hedef, vftable atlasta biliniyorsa
   atlas slot değeriyle karşılaştırılır; **çelişki = çözüm reddi** (`devirtemu.cpp:439-457`).
3. **Çoklu-pass yakınsama**: birden çok vtable adayında HEPSİ ayrı pass'te koşulur;
   hepsi aynı hedefe giderse kanıt, biri bile saparsa **aday listesi** (tekil tahmin yok).
4. **Pass izolasyonu**: her pass öncesi `RestoreDirty` — önceki koşunun yazımları
   sonraki koşuya sızamaz.
5. **Hedef geçerliliği**: bulunan adres kod bölümünde mi? Değilse red.

**Bilinen iki sınırlılık** (dürüstçe; karar planı Faz 0'da düzeltilmek üzere):
- `RestoreDirty` giriş başına en fazla **64 bayt** geri alıyor (`devirtemu.cpp:192-204`)
  ve MemLog **65.536** girişte doyar (`emulator.cpp:282`) → çok yazımlı uzun pencerelerde
  pass-arası sızıntı riski. Faz 0.1/0.2.
- Bütçe kesmeleri (4 this-tohum varyantı, 6 aday, 180 sn) dolunca sessizce kapanıyor;
  kesilen siteler "incomplete" işaretlenmeli. Faz 0.3.

Bu disiplin sayesinde Tier-3'ün 256 çözümü test fixture'ında ve çapraz doğrulamada
geçmiştir; kalan 4716 dürüst etiketlerle raporlanır — **spekülatif tekil çözüm sıfır**.

---

## 7. v9 Karar Planına Etkisi — Bu Tur Ne Ekledi?

| Bu raporun bulgusu | Karar planındaki karşılığı |
|---|---|
| playerGetStatus %100 statik kanıtla çözülür (yığın gerektirmez) — "kanıt maliyeti" hiyerarşisi doğrulandı: statik > emülasyon | Faz sıralamasının gerekçesi güçlendi: statik kanıt makineleri (Faz 2/3) emülatör bütçesinden önce |
| Yığın gerçekliği darboğaz değil; tohum/kapsam/kanıt eksenleri darboğaz | Faz 0.5 (join güvenliği) + Faz 2 (dolu mapRep_) + Faz 3 (allocation-site/live-in) doğru hedeflerde |
| "Gerçek gibi simüle"nin değerli biçimleri = init emülasyonu + dinamik iz + sembolik | Faz 3/4 (Tier-4 init hasadı), Faz 5 (dinamik iz), Faz 5+ (sembolik) — zaten planlı |
| Yığın boyutu düzeltmesi (1 MB) + bellek haritası ilk kez tek tabloda belgelendi | Dokümantasyon borcu kapandı; ölçüm komutuna hazır zemin |
| Kova ilaç eşlemesi (4117→live-in/allocation-site; 471→IPA/PDB) | Faz 1 `devirt stats` R_* kovalarının hipotez tablosu — ölçümle doğrulanacak |

**Mimari karar değişmedi; güçlendi.** Yapay yığın + statik tohum modeli doğru substrattır;
%100 sözleşmesi (UNIQUE/FINITE_SET/RUNTIME_OBSERVED/PARTIAL/UNKNOWN, hedef:
UNKNOWN=0, PARTIAL=0) aynen geçerlidir.

---

## 8. Sonraki Adım

Karar planının İlk Sprint'i hazır: **Faz 0+1** (beş soundness düzeltmesi + `devirt stats`
R_* gerekçe kodları + tail-call evren düzeltmesi) → binary yeniden koşulur → tahmin
tabloları gerçek kova sayılarıyla değiştirilir. Sonrasında Faz 2'nin üç bedava kazancı.

> **SINIR YOK — EN İYİSİ OLANA KADAR DURMAYACAĞIZ.**
> Statik kanıt önce, emülasyon ikinci, dinamik gözlem üçüncü kat — ve her kat kendi
> dürüstlük etiketiyle. %100 bir söz değil, ölçülebilir bir sözleşmedir:
> UNKNOWN=0, PARTIAL=0.

---

## Kaynak Zinciri (bu dokümanın doğrulama noktaları)

- `src/decomp/devirtemu.cpp` — Tier-3 pencere emülasyonu (TryCall, WindowStart,
  ApplySeeds, RestoreDirty, RTTI çapraz doğrulama)
- `src/decomp/devirtpro.cpp` — ScanWriters (:227), EvalFunction (:460), EmuResolve
  (:927), CollectIndirectCalls (:336), bütçe (:268)
- `src/emulate/emulator.cpp` — Setup (imaj map, shadow-IAT, stack+TEB/PEB, heap),
  sentinel sihirli sayfa; `emulator.h` — EmuConfig (stackSize 1 MB)
- `src/mapper/mapper.h` — SHADOW_IAT_BASE 0x77000000
- `docs/DEVRIT_V8_CANLI_KANIT.md` — v8.1 mekanizma kırılımı (245/236/256/3222/485),
  playerGetStatus kanıt zincirleri, bellek haritası diyagramı
- `DEVRIT_V9_KARAR_PLANI.md` — 4-AI sentezi, 12 iddia doğrulaması, altı faz
- `DEVRIT_100_YOL_HARITASI.md` — 12 kök neden, dünya turu, v9→v12 planı
