# DEVRİT v9 KARAR PLANI — Dört Analizin Sentezi, Doğrulaması ve Nihai Yol

> Girdi: 4 ayrı derin analiz — (1) benim v8 kaynak analizi + dünya turu, (2) AI-1'in iki turlu
> görüşü ("%100 yapılamaz" → kullanıcının itirazı üzerine teori düzeltmesi), (3) AI-2'nin mimari
> denetimi, (4) AI-3'ün hata avı. Bu doküman hepsini kaynak kodda **tek tek doğrular**,
> çelişkileri karara bağlar ve uygulanacak planı seçer.
> Doğrulama ortamı: repo `bb40b88` (v8) yerel klon, tüm `dosya:satır` referansları teyitlidir.
> Tarih: 2026-11-22. Bu doküman `DEVRIT_100_YOL_HARITASI.md`'nin öncelik bölümünün yerini alır.

---

## 0. Yönetici Kararı (TL;DR)

1. **"%100 yapılamaz" iddiası BU BINARY İÇİN yanlıştı; kullanıcı haklı.** Rice/durdurma
   teoremi yalnızca "*keyfi* programlar için *evrensel* tek çözücü algoritması"nı yasaklar.
   Sabit bir binary + kapalı sınıf evreni + paket içinde gelen (shipped) script/veri tabloları
   için her çağrı noktasının **tam ve kesin hedef kümesi hesaplanabilir**. Engel hesaplanabilirlik
   değil, analiz hassasiyeti — yani mühendislik (§1).
2. **%100'ün sözleşmesi:** her dolaylı çağrı noktası beşli sınıflandırmada doğru yere oturur ve
   `UNKNOWN = 0`, `PARTIAL_CANDIDATES = 0` olur. Gerçekten çok-hedefli siteler (paket dispatch,
   CPython interpreter) `FINITE_SET_PROVEN` olarak kalır — bu başarısızlık değil, programın
   hakikatı (§6).
3. **12 somut teknik iddiadan 12'si kaynak kodda doğrulandı** — üçünde (AI-1, AI-2, AI-3)
   benim ilk turumda gözden kaçırdığım gerçek **doğruluk (soundness) hataları** var. Bunlar
   her şeyden önce düzeltilir (§2, Faz 0).
4. **Seçilen büyük kaldıraç sırası:** doğruluk düzeltmeleri → ölçüm (`devirt stats`) → ucuz
   kazanım paketi → **nesne akışı (allocation-site + IPA + PDB füzyonu)** → **Metin2'ye özel
   zeka (PyMethodDef + paket tablosu + Tier-5b Python simülasyonu)** → dinamik kanıt (§5).

---

## 1. Teori Kararı: %100 Ne Zaman Mümkün?

### 1.1 İki önerme birbirine karıştırılmamalı

- **Önerme A (doğru):** "Herhangi bir binary, herhangi bir girdi için, tüm olası çalışma
  zamanı hedeflerini kesin bulmayı garanti eden **evrensel** bir program yazılamaz." Bu,
  Turing-tam programların davranış kararının genel olarak verilemeyeceğinin (Rice/durdurma)
  doğrudan sonucudur.
- **Önerme B (yanlış türetme):** "Bu yüzden **bu** binary tam çözülemez." Önerme A'dan B
  çıkmaz. Analiz bir kez sabit binary'e bağlandığında problem artık "keyfi program" değil,
  "sonlu, kapalı bir artefaktın tam çözümü"dür.

### 1.2 Kullanıcının kanıtı neden geçerli (Metin2 mimarisi)

Kullanıcının itirazı: *"Ağdan sadece value gelir — token, id, HP, konum. Bunlar heap'teki
nesnenin ALANLARINA yazılır; vptr'yi ise kurucu belirler ve kurucu çağrısı binary'nin
içindedir, statik olarak görünür."* Bu argüman yapısal olarak doğru ve AI-1'in kaynak
doğrulamasıyla desteklendi: Metin2 istemcisinde `CInstanceBase` **tek somut sınıftır**;
oyuncu/canavar/NPC ayrımı subclass hiyerarşisi değil, `SCreateData::m_bType` **veri
alanıdır** (ADI97IDA/Client, `UserInterface/InstanceBase.h` — AI-1 doğrulaması; bağımsız
teyidim sayfa dönüştürme hatası nedeniyle başarısız oldu, Faz 1'de RTTI atlası üzerinden
binary'de çapraz doğrulanacak).

Metin2'de tipi belirleyen her şey **sonlu ve paket içinde**:

| Kaynak | Sonluluk | Kanıt yöntemi |
|---|---|---|
| Singleton/tek-sınıf aktörler | belirsizlik yok | v8 zaten çözüyor |
| Paket header dispatch (~200 header) | sonlu enum | tablo statik çıkarılır |
| Python UI/effect sınıfları | shipped `root/*.py`, `locale/*.py` | parse/simülasyon (Tier-5b) |
| item/skill/effect veri tabloları | shipped `.mse` vb. | statik parse → tipID→sınıf |
| CPython interpreter dispatch | sonlu ama büyük (tüm Py tipleri) | küme olarak verilir |

Kullanıcı eylemi **hangi sitenin çalışacağını** (coverage) etkiler; **hangi hedeflerin mümkün
olduğunu** (tip evreni) etkilemez. Hiç koşulmamış bir site için bile tam küme, paket
çıkarımıyla verilebilir.

### 1.3 Dürüst kalan tek nüans

- Kapalı-dünya varsayımı doğrulanmalı: pack dosyaları çıkarılabilir olmalı (Metin2 pack
  formatı bilinir; Faz 4'te doğrulanır).
- Interpreter katmanı siteleri tekil **olmayacaktır** — doğru cevapları kümelerdir.
- "Hesaplanabilir" ile "kolay" aynı şey değil: kümeleri hesaplayacak analiz hassasiyeti
  işte §5'teki planın ta kendisi.

---

## 2. Doğrulama Tablosu — İddia → Kaynak Kod Gerçeği

| # | İddia (kim buldu) | Kaynak kodda durum | Sonuç |
|---|---|---|---|
| 1 | x64'te `mov [rip+X], reg` statik kanıta hiç girmiyor (AI-3) | `devirtpro.cpp:711-715` — rip dalı `Conc`'ı `memFacts_`'e yazıp `continue`; `this` (Sym) değeri **tamamen düşürülüyor**, `staticsWritten` hiç beslenmiyor | **DOĞRULANDI** |
| 2 | Statik yazım yalnız `off == 0`'da kabul (AI-3) | `devirtpro.cpp:720` — `val.off == 0` kapısı; `this+4` (MI ikinci taban) atamaları kaçıyor | **DOĞRULANDI** |
| 3 | `new` + kurucu zinciri modellenmiyor (AI-1+AI-2+AI-3) | `devirtpro.cpp:684-693` — her `call`'da caller-saved yazmaçlar silinir, dönüş değeri yok; fixture'ta `new` vakası da yok | **DOĞRULANDI** |
| 4 | Pass'ler arası kirli bellek → yanlış "kanıt" riski (AI-1) | `devirtemu.cpp:192-204` — `RestoreDirty` giriş başına **en fazla 64 bayt** geri alır; `emulator.cpp:282` — MemLog **65536 girişte doyar**, sonrası hiç loglanmaz → geri alınamaz | **DOĞRULANDI** |
| 5 | Tail-call `jmp [reg+K]` sanalları evrende sayılmıyor (AI-1) | `devirtpro.cpp:313-320` — `CollectIndirectCalls` yalnız `x.isCall` sayar; `isJmp && isIndirect` yok | **DOĞRULANDI** |
| 6 | `call reg` kanıt taramasında R8-R15 yok (AI-2) | `devirtemu.cpp:363-364` — `kScan` yalnız 6 klasik yazmaç; x64'te vftable taşıyan yazmacın yarısı denenmez | **DOĞRULANDI** |
| 7 | `MsvcRtti::Children()` kuruluyor, hiç kullanılmıyor (AI-1) | `msvcrtti.h:69-70`, `msvcrtti.cpp:173/248` — tanım+kurulum var, **çağıran sıfır** (TypeInferer'ın kendi ELF/DWARF `children_`'ı ayrı ve kullanımda: `types.cpp:1577`) | **DOĞRULANDI** |
| 8 | Strateji 3 spekülatif; "spekülatif sıfır" iddiası boru hattı için tam değil (AI-1) | `types.cpp:1668` — "binary capinda tek impl (spekulatif devirt)" açıkça yazıyor | **DOĞRULANDI** |
| 9 | `memFacts_` toplanıyor ama okunmuyor (ben, T1) | `devirtpro.cpp:439/713/731` — yalnız yazım+temizlik; `ReadMemory` (368-395) sorgulamıyor | **DOĞRULANDI** |
| 10 | Tier-3'e boş `mapRep_` geçiliyor (ben, T1) | `devirtemu.h:96` — "shadow bölgesi boş"; dolu rapor Shell'de duruyor (`shell.h:51`) | **DOĞRULANDI** |
| 11 | `ret`'te durmama / lineer tarama yanlış-birleştirme riski (AI-2+AI-3) | `devirtpro.cpp:870-876` — bilinçli tasarım ("MSVC hata yolu"); dal birleşimi yok, farklı kollardan değer sızabilir | **DOĞRULANDI** (risk tasarım gereği) |
| 12 | PDB'deki 176K tip / hiyerarşi devirt'e beslenmiyor (ben+AI-1) | `pdb.cpp:383` LF_BCLASS okunur (struct düzeni için); `DevirtPro` PDB tip verisini hiç sorgulamıyor | **DOĞRULANDI** |

**Ders:** İlk turum (T1) kapasite boşluklarını iyi buldu ama **doğruluk hatalarını kaçırdı**;
AI-1/AI-3'ün hata avı bunları kapattı. AI-2'nin en değerli katkısı mimari disiplin
("yanlış çözüm, çözümsüzden kötüdür"), AI-1'in en değerli katkısı teori düzeltmesi +
Metin2'ye özgü zeka (Tier-5b). Dördü birleşince tablo tamamlanıyor.

---

## 3. Dört Analizin Uzlaşı Matrisi

| Konu | Ben | AI-1 | AI-2 | AI-3 | Karar |
|---|---|---|---|---|---|
| En büyük kova: heap/allocation-site + IPA | ✓ | ✓ | ✓ | ✓ | **Yap** (Faz 3) |
| Ölçüm/taksonomi önce | ✓ | ✓ (devirtstats+AICT) | ✓ (korpus) | ✓ (korpus) | **Yap** (Faz 1) |
| Doğruluk hataları önce | kısmen | ✓ | ✓ (P0) | ✓ | **Yap** (Faz 0) |
| Global store merge (ucuz büyük kazanç) | — | ✓ | — | — | **Yap** (Faz 2) |
| PDB tip füzyonu | ✓ (param tohumlama) | ✓ (CHA+children_) | ✓ (PDB derinleştir) | ✓ (#5 bağlam) | **Yap** (Faz 3) |
| Dinamik kanıt katmanı | opsiyonel | ✓ (Tier-5, QBDI) | ✓ (DynamoRIO) | — | **Yap** (Faz 5) |
| Metin2'ye özel: PyMethodDef | ✓ | ✓ | — | — | **Yap** (Faz 4) |
| Metin2'ye özel: paket/Python simülasyonu | — | ✓ (Tier-5b) | — | — | **Yap** (Faz 4) |
| Tam CFG+SSA önce, sonra her şey | sonra | sonra | **önce** | #4-5 altlık | **Ara yol** (§4.1) |
| Sembolik yürütme (Triton/angr) | — | opsiyonel | ✓ Tier-4 | — | **Ertele** (Faz 5+) |
| VMProtect tarafı (NoVmp vb.) | farklı problem | farklı problem | farklı problem | — | **Yapma** |

---

## 4. Anlaşmazlıklar ve Kararlar

### 4.1 AI-2: "Önce tam CFG+SSA+MemorySSA, yoksa agresif çözüm ekleme" — kısmen kabul

AI-2 haklı olduğu nokta: lineer değerlendiricinin ürettiği bir "kanıt", yanlış olabilir
(Tablo #11) ve yanlış tekil çözüm dürüst aday listesinden kötüdür.
Kabul etmediğim nokta: bunun çözümü tüm sistemi sıfırdan SSA motoru yazmak zorunda değil —
`RestoreDirty`/MemLog hataları (#4) ve bütçe bayrakları zaten somut ve ucuz; dal birleşimi ise
**birleşimde Cand-küme-birliği kuralıyla** (path-sensitif olmayan ama güvenli join) yüzde
doksan kapatılır. Tam SSA, Faz 3'ün IPA altlığı olarak inşa edilir; hızlı kazanımı bloke etmez.

**Kural (v9'dan itibaren):** bir site yalnız tüm yollar tek hedefe yakınsıyorsa `UNIQUE_PROVEN`;
lineer tarama kolları karıştırabilecekse sonuç `PARTIAL_CANDIDATES`'a düşer, asla tekil
söylenmez.

### 4.2 AI-3: x64 hataları birinci öncelik — kısmen kabul

#1/#2 gerçek hatalar ama Metin2 istemcisi **PE32**; x64 yolu motor sağlığı için ORTA öncelik.
Oyun hattını bloke etmez, Faz 2'de düzeltilir (toplam ~30 satır).

### 4.3 Spekülatif katman: kaldır mı, etiketli mod mu?

AI-1 Strateji 3'ün varlığını "spekülatif sıfır" iddiasıyla çelişiyor diye işaret etti;
ben T1'de açık-etiketli KAPSAM modu önermiştim. **Karar: ikisi birden** — (a) Strateji 3 ya
kaldırılır ya çıktıda `TAHMIN` etiketi taşır (boru hattı-doküman tutarlılığı); (b) KAPSAM
modu ayrı ve açık bir bayrak olarak kalır, KANIT modu varsayılan.

### 4.4 Teori: benim T1 çerçevem revize edildi

T1'de "%100 statik imkansız" dedim. Bu, evrensel çözücü için doğru; **sabit Metin2 binary'i
için fazla güçlüydü**. AI-1'in (kullanıcının itirazı üzerine yaptığı) düzeltmesi ve kullanıcının
kanıtı benimsendi (§1). Eski dokümanın ilgili cümlesi bu dokümanla revize edilir.

---

## 5. SEÇİLEN PLAN — Altı Faz

### Faz 0 — Doğruluk (soundness) düzeltmeleri [AI-1+AI-2+AI-3 ortak, ~2-4 gün]

| # | İş | Yer | Kabul kriteri |
|---|---|---|---|
| 0.1 | `RestoreDirty` tam geri yükleme (giriş başına 64B sınırı kalkar; heap tampon) | `devirtemu.cpp:186-207` | herhangi bir pass sonrası imaj baytları bit-bit orijinal |
| 0.2 | MemLog 65536 doyması kaldır (deque + sınır yükselt; aşım halinde **incomplete** işaretle) | `emulator.cpp:282` | 20K komut penceresinde sıfır kayıp |
| 0.3 | Bütçe kesmeleri bayraklı: 4-pass/6-hedef/180sn dolunca sonuç `incomplete`, sessiz kapanma yok | `devirtpro.cpp:265-274, 917-918, 961` | kesilen her site raporda görünür |
| 0.4 | Strateji 3: `TAHMIN` etiketi veya kaldırma | `types.cpp:1668` | "spekülatif sıfır" iddiası boru hattıyla literal doğru |
| 0.5 | Lineer-birleşim güvenliği: join noktalarında Cand-birliği; şüpheli conc → Cand düşürme | `devirtpro.cpp` EvalFunction | adli kanıt: hatalı tekil çözüm sayısı 0 (korpus) |

### Faz 1 — Ölçüm ve evren doğruluğu [ortak, ~3-5 gün]

1. `devirt stats`: her çözülemeyen siteye R_* gerekçe kodu (R_HEAP/R_PARAM/R_CONTAINER/R_COM/
   R_FPTR_DATA/R_AMBIG/R_WINDOW/R_NORTTI/R_ZERO) + histogram + AICT metriği (AI-1'in önerisi).
2. **Evreni düzelt:** tail-call `jmp reg / jmp [mem]` sanal dispatch evrene ekle (Tablo #5) —
   sayılar ilk kez dürüst olur.
3. Test korpusu (AI-2+AI-3): kendi MSVC derlemeleri — x86/x64, O0..O2, `/GR-`, MI/VI, heap/
   factory/callback, çoklu DLL; hedefler kaynak koddan elle doğrulanmış. `307 PASS`'in "CHECK
   sayısı" olduğu README'de netleştirilir; 2.1sn/8.5sn ölçüm ayrımı dokümante edilir.
4. RTTI atlasından `CInstanceBase` alt sınıf çapraz doğrulaması (tek-somut-sınıf teyidi).

### Faz 2 — Ucuz kazanım paketi [ben T1 + AI-1 global merge + AI-2/AI-3 x64, ~1 hafta]

1. `memFacts_` okuma yolu (fonksiyon-içi yaz→oku yönlendirmesi) — Tablo #9.
2. Tier-3'e **dolu** `mapRep_` (shadow-IAT) — Tablo #10; pencere içi import çağrıları artık
   saplamaya düşer, fault etmez.
3. `vptrAll` birleştirme (tam yazım kümesi adaylara girer).
4. **Global store merge (AI-1'in "en ucuz büyük kazanç"ı):** `memFacts_` fonksiyon-başına
   sıfırlanıyor → global yazım veritabanı: `g_cbHandler = &Fn` başka fonksiyonda yazılmışsa
   çağıran görsün. Kayıt-tipi callback'lerin (registration pattern) kilidini açar.
5. x64 doğruluk: rip-yazımını `staticsWritten`'a besle (#1), `off != 0` kabulü (#2),
   `kScan`'e R8-R15 (#6).
6. `earlyArgGuard` süresini blok-sonuna taşı; `[ebp+0xC]` desteği.
7. Sentetik bölge 16 MB / seyrek tahsis (~16K statik); PDB GUID+Age eşleşme zorunluluğu (AI-2).

### Faz 3 — Nesne akışı: büyük kaldıraç [dört analiz tam uzlaşı, ~2-4 hafta]

1. **Allocation-site heap modeli:** `call [IAT: operator new]` → `Sym(H_site)`; kurucudaki
   vptr yazımları siteye bağlanır; `mov [g], eax` statik kanıt sayılır (AI-3 #3 tarifi).
2. **Dönüş özetleri:** her fonksiyon için "S statığını / H allokasyonunu / k. parametreyi
   döndürür / belirsiz" — çağrı noktalarında eax silinmez, özete bağlanır.
3. **PDB parametre tohumlama + CHA füzyonu:** PDB imzasındaki `CMonster* a2` → giriş
   `[ebp+8/0xC]` tohumu o sınıfın alt ağacıyla; `MsvcRtti::Children()` (Tablo #7) nihayet
   kullanıma girer; LF_BCLASS hiyerarşisi devirt'e bağlanır (Tablo #12).
4. **Field-sensitive bellek:** `(nesne, ofset) → değer` tablosu; `this->m_pObj` zincirleri
   çözülür (AI-3 #4, AI-2 ObjectProvenance).
5. **CFG altlık:** temel blok grafiği üzerinde Cand-join'li veri akışı (Faz 0.5'in geneli);
   çağıran-arg bağlamı ile sınırlı derinlikli callee değerlendirmesi (AI-3 #5).
6. Capstone detaylı operand yapısına geçiş: `[base+idx*scale+disp]` ve rip-relative tek
   `MemoryExpression` ile hem statik hem emülatör tarafında (AI-2 E).

### Faz 4 — Metin2'ye özel zeka [AI-1 özgün + ben, ~2-4 hafta]

1. **PyMethodDef tarayıcı:** `.rdata`'da `{"isim", fonk, bayrak, doc}` desenini tara →
   yüzlerce fonksiyona PDB'siz bile gerçek isim + Python dispatch eşleştirmesi.
2. **Paket dispatch tablosu:** `HEADER_GC_*` → handler tablosunu statik çıkar; her header
   yolunun tip evreni kesinleşir.
3. **Tier-5b — Python/paket simülasyonu (kullanıcının içgörüsünün mühendisliği):** gömülü
   CPython'u sandbox'ta stub C-modülleriyle koştur; stub'lar yalnız **hangi C++ sınıfı
   yaratıldı / hangi callback register edildi** kaydeder; shipped `root/*.py` + `locale/*.py`
   import edilir → UI/effect sınıf evreni + callback kayıtları → allocation-site tohumlarına
   ve global overlay'e beslenir. Pack çıkarımı doğrulanır (§1.3).
4. Veri tabloları (.mse, item/skill prototype) parse → tipID→sınıf eşlemesi.
5. COM/D3D sözlüğü: SDK'dan bilinen arayüz vtable düzenleri sentetik atlas sınıfı olarak
   şırınga edilir (`Direct3DCreate9` ailesi çözülür).
6. MSVC ABI derinleştirme: adjustor thunk, virtual inheritance (vbtable), ctor/dtor vptr
   yaşam döngüsü (AI-2 D tablosundan Metin2'de karşılığı olanlar).

### Faz 5 — Dinamik kanıt ve denetim [AI-1 Tier-5 + AI-2 Tier 5, ~1-2 hafta]

1. İz kaydedici (DynamoRIO veya QBDI): `VirtualCallRecord{callerRva, callRva, this, vptr,
   slot, target}` (AI-2'nin şeması).
2. Senaryo turları: login, karakter seçimi, harita değişimi, savaş, envanter, eşya, NPC,
   skill, party/guild (AI-1'in bot listesi). Linux/Wine veya gerçek Windows kutusunda.
3. `IngestDynamicEvidence`: iz → `RUNTIME_OBSERVED` etiketli çözümler (`why="DINAMIK KANIT (iz)"`).
4. **Soundness denetimi:** gözlemlenen her hedef statik kümenin üyesi mi? Değilse statik küme
   `EXPLICIT-eksik` işaretlenir — bu, %100 sözleşmesinin (§6-M3) ölçüm aracıdır.

### Beklenen etki (TÜMÜ TAHMİN — `devirt stats` çıkınca gerçekçileşir)

| Faz sonunda | Tahmini durum (PDB'li) |
|---|---|
| v8 bugün | 4444/9160 = %48.5 sınıflı, UNKNOWN ağır |
| Faz 2 | ~+300..800 çözüm; UNKNOWN'un yapısı ilk kez görülür |
| Faz 3 | ~%65-75 UNIQUE+FINITE; heap/param kovaları büyük ölçüde kapanır |
| Faz 4 | evren tamamlanır (tail-call + PyMethodDef + paket yolları); ~%75-90 |
| Faz 5 | sıcak yollar RUNTIME_OBSERVED; hedef: UNKNOWN=0, PARTIAL=0 (§6) |

---

## 6. "%100"ün Sözleşmesi — Kabul Kriterleri

**Tanım:** %100 devirt = evrendeki (tail-call dahil) **her** dolaylı çağrı noktasının doğru
sınıflandırılmış olması ve çözülebilir olanların **tam hedef kümesinin** elde edilmiş olması.

Beşli sınıflandırma (AI-2'nin şeması benimsendi):

| Sınıf | Anlam |
|---|---|
| `UNIQUE_PROVEN` | kanıt zincirli tek hedef |
| `FINITE_SET_PROVEN` | tüm olası hedefler kesin + eksiksiz (paket dispatch, interpreter) |
| `RUNTIME_OBSERVED` | iz ile görüldü (tam kapsam kanıtı değil, etiketi açık) |
| `PARTIAL_CANDIDATES` | aday listesi eksik — **hedef: 0'a düşür** |
| `UNKNOWN` | hiçbir kanıt — **hedef: 0'a düşür** |

Ölçüler:
- **M1:** `devirt stats` raporunda `UNKNOWN=0` ve `PARTIAL_CANDIDATES=0`.
- **M2:** her `UNIQUE_PROVEN` sitesinin kanıt zinciri `devirt <adres>` ile yeniden üretilebilir.
- **M3:** tüm senaryo turlarında dinamik-gözlem ⊆ statik-küme ihlali = 0 (ihlal = küme eksik).
- **M4:** korpus testlerinde yanlış tekil çözüm = 0 (Faz 0'ın amacı).
- **M5:** spekülatif çözüm ancak `TAHMIN` etiketiyle, KANIT modunda hiçbir zaman.

---

## 7. Yapılmayacaklar (ve neden)

| Öge | Neden değil |
|---|---|
| NoVmp/Triton ile VMProtect devirt'i | Farklı problem (opcode sanallaştırma); bizim hedef C++ sanal dispatch |
| Tam Itanium ABI (GCC/Clang RTTI) | Metin2 MSVC; motor genelliği için ileride |
| Çok-modüllü (DLL) analiz | Client ana gövde tek exe; Python DLL'i Faz 4'te stub'lanıyor zaten |
| Tam MemorySSA motorunu hızlı kazanımlardan ÖNCE yazmak | AI-2'nin P0'su; §4.1'deki gerekçeyle ara yol seçildi |
| Gömülü CPython'u **tam** oyun ortamında koşturmak | GPU/D3D gerekir; Tier-5b yalnız sınıf evreni toplar, oyun oynamaz |

---

## 8. İlk Sprint (Faz 0 + 1 + 2, ~2 hafta)

1. Hafta 1: Faz 0'ın beş düzeltmesi + `devirt stats` iskeleti + tail-call evren düzeltmesi;
   her biri için fixture/test. Binary + PDB yeniden yüklenir → **gerçek kova sayıları** bu
   dokümanın §5 tahmin tablosunun yerine geçer.
2. Hafta 2: Faz 2 paketi (memFacts_ okuma, dolu mapRep_, vptrAll, global store merge, x64
   düzeltmeleri, sentetik bölge) + korpusun ilk dilimi (O0/O2, heap/factory vakaları).

---

## 9. Katkı Zinciri

- **Kullanıcı:** %100'ün bu binary için mümkün olduğunun kanıtı (ağ-value/vptr-kurucu argümanı)
  — bu dokümanın tüm teorik çerçevesi bu içgörü üzerine kuruldu.
- **Ben (T1):** 12 kök neden haritası, ölü kod bulguları, dünya turu; T1 çerçevesi bu
  dokümanda revize edildi.
- **AI-1:** teori düzeltmesi + Metin2 mimari doğrulaması + 3 gerçek bug + global store merge
  + Tier-5b.
- **AI-2:** mimari disiplin ("önce doğru"), sınıflandırma sistemi, VirtualCallRecord,
  operand-decoder/seyrek-bellek, PDB derinliği.
- **AI-3:** en keskin hata avı (x64 `continue`, `off==0`), allocation-site tarifi,
  field-sensitive bellek, korpus önerisi.

*Bu dokümandaki tüm dosya:satır referansları `bb40b88` klonunda doğrulanmıştır. Etki
sayıları açıkça tahmin olarak etiketlenmiştir; Faz 1 sonrası ölçümlerle değiştirilecektir.*
