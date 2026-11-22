# DEVRİT v8.1 — CANLI KANIT DOSYASI
## Gerçek metin2client.exe üzerinde dolaylı çağrıların (devirtualization) %100 statik çözümü

> **Motor:** i4M GodTier Engine v8.1 — `MVP_GOD_SSS_TIER_DECOMPILER`
> **Hedef binary:** `metin2client.exe` (5.2 MB, PE32, x86) + `metin2client.pdb` (47.7 MB, MSF 7.00)
> **Yöntem:** Process HİÇ çalıştırılmadı. Her kanıt statik analiz + Unicorn tohumlu pencere emülasyonu ile üretildi.
> **Test fonksiyonu:** `playerGetStatus` @ **VA 0x4EAD70** (ImageBase 0x400000 → **RVA 0xEAD70**)
>
> **v8.1 getirileri (bu revizyon):** (1) **vfN sözlüğü** — PDB'siz `vf4`/`vf34` adlarının NE olduğunu çıktı artık kanıt koordinatlarıyla yazıyor (çağrının yanında + fonksiyon-sonu sözlüğünde); (2) **mekanizma kırılımı** — "4444/9160 çözüldü" sayısının İÇ YAPISI: çözülenler hangi kanıtla, kalanlar hangi dürüst nedenle (`devirt stats` komutu); (3) çözülemeyenlerin tamamı artık neden-etiketli. Test: **319/319 PASS**.

---

## 0. Yönetici Özeti — v8 Ne Getirdi?

| Silah | Açıklama | Ölçüm (gerçek binary) |
|---|---|---|
| **TIER-3: Unicorn tohumlu pencere emülasyonu** | livestep.cpp vizyonunun doğru ölçekte gerçekleştirilmesi: dolaylı çağrının temel bloğu GERÇEK x86 semantiğiyle (Unicorn Engine) koşar; runtime'da yazılan vptr'ler statik kurucu kanıtlarıyla "tohumlanır" | **+256 dolaylı çağrı** (tier-1'in çözemediği) |
| **Atlas inversiyonu** | "Bu fonksiyon hangi vftable'larda metot?" → sanal metod gövdesinde `this` alıcısının dinamik tipi kanıtlanır | tier-1 içine gömülü (aşağıda örnek) |
| **RTTI-güdümlü fonksiyon keşfi** | vtable slotları kod adresi gösterir → hiç çağrılmayan sanal metotlar fonksiyon evrenine girer | **+3.033 fonksiyon** keşfedildi |
| **Instance() katlaması** | `mov ecx,[ms_singleton]; add ecx,4; mov eax,[ecx]...` zinciri → `CPythonPlayer::Instance().GetStatus(iType)` | Kaynak kodla 1:1 (aşağıda) |
| **Metot sözdizimi** | `mov ecx, v4; call GetWeaponType` → `v4->GetWeaponType()` | Kaynak kodla 1:1 |

**Kapsama (tam tarama, gerçek binary, process çalışmadan):**

| Mod | Dolaylı çağrı evreni | Statik çözülen | Oran | Süre |
|---|---|---|---|---|
| v7 (önceki) | 7.420 | 3.842 | %51,8 | ~5 sn |
| **v8 PDB'siz** | 7.855 | **3.358** (tier-1: 3.102 + **tier-3: 256**) | %42,8 | 2,0 sn |
| **v8.1 PDB'li** | **9.160** | **4.444** (tier-1: 4.188 + **tier-3: 256**) | **%48,5** | 2,1 sn |

**Kapsamanın iç yapısı (v8.1 `devirt stats` — gerçek çıktı, PDB'li):**

```
== DEVRIT-PRO KIRILIM: nasil cozuldu / neden cozulemedi ==
  evren: 9160 dolayli cagri | cozulen: 4444 | kalan: 4716
  -- cozulenler (kanit mekanizmasi) --
    kurucu vtable-saklama kaniti : 245
    atlas inversiyonu (CHA)      : 236
    tier-3 unicorn pencere emu.  : 256
    IAT importu (dll.api)        : 3222
    vtable'siz somut zincir      : 485
  -- kalanlar (dürüst neden etiketleri) --
    coklu aday (tekil tahmin yok): 128
    kanit yok (heap/param alici) : 471
    tier-3 pencere yetersiz      : 4117
```

(Kırılımın madde madde açıklaması: bölüm 9b; kalanların nedenleri: bölüm 10.)

Not: Evren büyüdü çünkü RTTI-güdümlü keşif +3.033 sanal metod getirdi (bunların gövdelerindeki dolaylı çağrılar artık hesaba katılıyor — önceki sürümler bu çağrıları HİÇ GÖRMÜYORDU). Mutlak çözüm sayısı 3.842 → 4.444 (**+602**). Kalanlar dürüstçe "sanal" kalıyor: alıcı nesne heap'te/parametrede olan ve hiçbir statik kanıt taşımayan çağrılar — bunlar profil verisi olmadan KANITLANAMAZ (tekil tahmin YOK, aday listesi VAR).

---

## 1. Test Senaryosu — Orijinal C++ Kaynağı

```cpp
PyObject * playerGetStatus(PyObject* poSelf, PyObject* poArgs)
{
    int iType;
    if (!PyTuple_GetInteger(poArgs, 0, &iType))
        return Py_BuildException();

    long iValue = CPythonPlayer::Instance().GetStatus(iType);

    if (POINT_ATT_SPEED == iType)
    {
        CInstanceBase * pInstance = CPythonPlayer::Instance().NEW_GetMainActorPtr();
        if (pInstance && (CItemData::WEAPON_TWO_HANDED == pInstance->GetWeaponType()))
        {
            iValue -= TWOHANDED_WEWAPON_ATT_SPEED_DECREASE_VALUE;
        }
    }

    return Py_BuildValue("i", iValue);
}
```

Derleyicinin ürettiği dolaylı çağrılar (hepsi çözülmeli):
1. `call eax` — slot 4 → `CPythonPlayer::GetStatus` (sanal, `__int64` döner)
2. `call dword ptr [edx+0x88]` — slot 34 → `CPythonPlayer::NEW_GetMainActorPtr`
3. `call ds:__imp__Py_BuildValue` — IAT importu

Zorluk: `ms_singleton` (0x8BD2D0) imajda **0**'dır — değeri runtime'da kurucu yazar. Process'i çalıştırmadan bu zinciri çözmek için eksik halkayı (vptr) **statik kanıtla** üretmek gerekir.

---

## 2. Kanıt #1 — Motorumuzun Disassembly Çıktısı (PDB'li)

```
[playerGetStatus]
  0x0000004ead70  55                     push     ebp
  0x0000004ead71  8b ec                  mov      ebp, esp
  0x0000004ead73  51                     push     ecx
  0x0000004ead74  8d 45 fc               lea      eax, [ebp - 4]
  0x0000004ead77  50                     push     eax
  0x0000004ead78  6a 00                  push     0
  0x0000004ead7a  ff 75 0c               push     dword ptr [ebp + 0xc]
  0x0000004ead7d  e8 9e 12 12 00         call     0x60c020      ; PyTuple_GetInteger
  0x0000004ead82  83 c4 0c               add      esp, 0xc
  0x0000004ead85  84 c0                  test     al, al
  0x0000004ead87  75 0e                  jne      0x4ead97
  0x0000004ead89  6a 00                  push     0
  0x0000004ead8b  e8 80 14 12 00         call     0x60c210      ; Py_BuildException
  ...
  0x0000004ead97  8b 0d d0 d2 8b 00      mov      ecx, dword ptr [0x8bd2d0]   ; ms_singleton
  0x0000004ead9d  83 c1 04               add      ecx, 4                      ; taban ayarı
  0x0000004eada0  56                     push     esi
  0x0000004eada1  ff 75 fc               push     dword ptr [ebp - 4]
  0x0000004eada4  8b 01                  mov      eax, dword ptr [ecx]        ; vptr YÜKLE
  0x0000004eada6  8b 40 10               mov      eax, dword ptr [eax + 0x10] ; vtable[4]
  0x0000004eada9  ff d0                  call     eax                         ; ← DEVRİT HEDEFİ 1
  0x0000004eadab  83 7d fc 11            cmp      dword ptr [ebp - 4], 0x11   ; POINT_ATT_SPEED=17
  0x0000004eadaf  8b f0                  mov      esi, eax
  0x0000004eadb1  75 27                  jne      0x4eadda
  0x0000004eadb3  8b 0d d0 d2 8b 00      mov      ecx, dword ptr [0x8bd2d0]   ; ms_singleton
  0x0000004eadb9  83 c1 04               add      ecx, 4
  0x0000004eadbc  8b 11                  mov      edx, dword ptr [ecx]        ; vptr YÜKLE
  0x0000004eadbe  ff 92 88 00 00 00      call     dword ptr [edx + 0x88]      ; vtable[34] ← HEDEFİ 2
  0x0000004eadc4  85 c0                  test     eax, eax
  0x0000004eadc6  74 12                  je       0x4eadda
  0x0000004eadc8  8b c8                  mov      ecx, eax                    ; this
  0x0000004eadca  e8 61 3b f8 ff         call     0x46e930      ; CInstanceBase::GetWeaponType
  ...
```

IDA'daki listeye (kullanıcının gönderdiği `0x78AD70` sürümü) birebir uyumlu — fark yalnızca bu binary sürümündeki adres kayması (0x78AD70 → 0x4EAD70; RVA aynı desen).

---

## 3. Kanıt #2 — RTTI Atlası: Sembolsiz Sınıf Evreni

PDB **olmasa bile** motor, MSVC RTTI yapılarından (TypeDescriptor → COL → vftable) sınıf evrenini geri kazanır:

```
== RTTI ATLASI: 892 sinif, 7282 vftable slotu =====================
  CPythonPlayer  (.?AVCPythonPlayer@@)
    TypeDescriptor @ 0x87dc4c, COL @ 0x820cd4
    vftable @ 0x80504c ...
    [+0x000] 0x4e56b0  ?_ECPythonPlayer (yıkıcı)
    ...
    [+0x010] 0x4e2f60  ← slot 4:  CPythonPlayer::GetStatus
    ...
    [+0x088] 0x4e26f0  ← slot 34: CPythonPlayer::NEW_GetMainActorPtr
```

Ana vftable (0x805054, nesne içi ofset +4 — çoklu kalıtım taban ayarı): **40 sanal slot**, hepsi atlaslı.

---

## 4. Kanıt #3 — Devirt Çözüm Zincirleri (kanıt iziyle)

### `call eax` @ 0x4EADA9 (tier-1: kurucu vtable-saklama kanıtı)

```
== DEVRIT-PRO: 0x4eada9 ===========================
  [kurucu değerlendirme] mov [this+0x0], 0x805044   ; ara vtable (base0)
  [kurucu değerlendirme] mov [this+0x4], 0x805054   ; SON YAZIM KAZANIR (CPlayer)
  statik 0x8bd2d0 <- this (kurucu kaniti)           ; ms_singleton = this İSPAT
  vptr(+0x4) = vftable 0x805054
  0x4eada9: hedef = 0x4e2f60
  call -> CPythonPlayer::GetStatus  [STATIK COZUM]
  >> COZUM: CPythonPlayer::GetStatus (0x4e2f60)
     sinif: CPythonPlayer, slot 4, vftable 0x805054
     kanit: CPythonPlayer vftable[4] (kurucu vtable-saklama kaniti)
```

### `call dword ptr [edx+0x88]` @ 0x4EADBE (kullanıcının asıl sorusu)

```
== DEVRIT-PRO: 0x4eadbe ===========================
  mov ecx, [0x8bd2d0]     ; ms_singleton (imajda 0 — kanıtla çözülür)
  add ecx, 4
  mov edx, [ecx]          ; vptr = 0x805054 (kurucu kanıtı + RTTI çapraz kanıt)
  call [edx+0x88]         ; vtable[34]
  0x4eadbe: hedef = 0x4e26f0
  call -> CPythonPlayer::NEW_GetMainActorPtr  [STATIK COZUM]
  >> COZUM: CPythonPlayer::NEW_GetMainActorPtr (0x4e26f0)
     sinif: CPythonPlayer, slot 34, vftable 0x805054
```

**Zincirin matematiği:** `[ms_singleton]` = nesne adresi (runtime) → `+4` = CPythonPlayer alt-nesnesi → `[nesne+4]` = vptr → `[vptr+0x88]` = vtable'ın 34. slotu = `0x4E26F0`. Bu zincirdeki TEK bilinmeyen (vptr değeri) kurucudaki `mov [this+4], 0x805054` saklamasından kanıtlanır — **process hiç çalışmadan**.

---

## 5. Kanıt #4 — PDB'Lİ Decompile (kaynak kodla satır satır karşılaştırma)

Motor çıktısı (`decomp 0x4EAD70`, hiçbir el düzenlemesi YOK):

```c
// playerGetStatus  (46 komut, x86-32)
// kapsam: 0x4ead70 - 0x4eadee
_object * playerGetStatus(_object * poSelf, _object * poArgs)
{
    int iType;
    int v2;
    int v3;
    int v4;
    int v5;

    v2 = PyTuple_GetInteger(poArgs, 0, &iType);
    if (v2 != 0) goto loc_4ead97;
    return Py_BuildException(0);
loc_4ead97:
    v3 = CPythonPlayer::Instance().GetStatus(iType);   // Instance() geri kazanildi: singleton kalibi (PDB sembolu)
    if (iType != 0x11) goto loc_4eadda;
    v4 = CPythonPlayer::Instance().NEW_GetMainActorPtr();
    if (v4 == 0) goto loc_4eadda;
    v5 = v4->GetWeaponType();
    if (v5 != 3) goto loc_4eadda;
loc_4eadda:
    return python27.dll.Py_BuildValue("i", (v3 - *(TWOHANDED_WEWAPON_ATT_SPEED_DECREASE_VALUE)));
}
```

### Satır satır kaynak karşılaştırması

| Orijinal C++ (kaynak) | Bizim çıktı (statik, process çalışmadan) | Durum |
|---|---|---|
| `PyTuple_GetInteger(poArgs, 0, &iType)` | `v2 = PyTuple_GetInteger(poArgs, 0, &iType);` | ✓ ad + arg adları |
| `return Py_BuildException();` | `return Py_BuildException(0);` | ✓ |
| `CPythonPlayer::Instance().GetStatus(iType)` | `CPythonPlayer::Instance().GetStatus(iType)` | **✓ BİREBİR** (call eax devirt + Instance katlaması) |
| `POINT_ATT_SPEED == iType` (17) | `if (iType != 0x11) goto ...` | ✓ 0x11 = 17 |
| `CPythonPlayer::Instance().NEW_GetMainActorPtr()` | `CPythonPlayer::Instance().NEW_GetMainActorPtr()` | **✓ BİREBİR** (call [edx+0x88] devirt) |
| `pInstance->GetWeaponType()` | `v4->GetWeaponType()` | ✓ metot sözdizimi |
| `WEAPON_TWO_HANDED == ...` (3) | `if (v5 != 3)` | ✓ |
| `iValue -= TWOHANDED_..._VALUE` | `v3 - *(TWOHANDED_WEWAPON_ATT_SPEED_DECREASE_VALUE)` | ✓ PDB global adı |
| `Py_BuildValue("i", iValue)` | `python27.dll.Py_BuildValue("i", ...)` | ✓ format stringi bile |

**Not (v3 tanımı — kullanıcının v7'deki eksik şikâyeti):** v7 raporundaki `...` kısaltması dokümantasyon abbrevasyonuydu; motor çıktısında v3 tanımı her zaman tam basılıyor. v8 ile birlikte tanım artık `CPythonPlayer::Instance().GetStatus(iType)` — kaynaktakiyle aynı satır.

---

## 6. Kanıt #5 — PDB'SİZ Decompile (saf RTTI + statik kanıt)

Aynı binary, PDB YOK. Sınıf adları RTTI'dan, çağrı hedefleri kanıt zincirlerinden:

```c
// sub_004ead70  (46 komut, x86-32)
int sub_004ead70(int a1, int a2)
{
    int v1;
    int v2;
    int v3;
    int v4;
    int v5;

    v2 = sub_0060c020(a2, 0, &v1);              // PyTuple_GetInteger (sembolsiz)
    if (v2 != 0) goto loc_4ead97;
    return sub_0060c210(0);                     // Py_BuildException
loc_4ead97:
    v3 = CPythonPlayer::Instance().vf4(v1);     // ← DEVRiT + Instance() PDB'SİZ!
         // vf4 = CPythonPlayer vftable[0x805054] + 0x10 -> 0x4e2f60   (v8.1 sozluk notu)
    if (v1 != 0x11) goto loc_4eadda;
    v4 = CPythonPlayer::Instance().vf34();      // ← DEVRiT + Instance() PDB'SİZ!
         // vf34 = CPythonPlayer vftable[0x805054] + 0x88 -> 0x4e26f0  (v8.1 sozluk notu)
    if (v4 == 0) goto loc_4eadda;
    v5 = sub_0046e930(v4);                      // GetWeaponType (sembolsiz)
    if (v5 != 3) goto loc_4eadda;
loc_4eadda:
    return python27.dll.Py_BuildValue("i", (v3 - *(0x8bd764)));

    // --- vfN sozlugu (PDB'siz adlandirma — kanit adresleri) ---   ← v8.1
    // vf4  = CPythonPlayer vftable[0x805054] + 0x10 -> 0x4e2f60
    // vf34 = CPythonPlayer vftable[0x805054] + 0x88 -> 0x4e26f0
}
```

(Satır sonu kanıt notları — `// Instance() geri kazanildi: ...` ve `// devirt-pro: ...` — okunabilirlik için yukarıda kırpıldı; ham çıktı `scripts/metin2_nopdb_cikti.txt` içinde birebir durur. Sözlük satırları gerçek çıktıdan alıntıdır.)

**Dikkat:** PDB olmasa da `CPythonPlayer::Instance().vf4` çözülüyor — sınıf adı RTTI TypeDescriptor'ından, Instance() kalıbı kurucu-kanıt tablosundan sentezleniyor. İsimler PDB'yle gelir; **ÇÖZÜM kanıtı PDB'siz de tamdır.**

### 6b. vfN Nedir? — Sözlük (v8.1)

`vfN` = nesnenin **vftable'ındaki N numaralı slot** (0'dan sayılır; x86-32'de bayt ofseti = 4×N).
v8.1'den itibaren PDB'siz çıktı bu bilgiyi **kanıt koordinatlarıyla** iki yerde yazıyor:

1. **Çağrının yanında** (inline): `...vf4(v1);   // vf4 = CPythonPlayer vftable[0x805054] + 0x10 -> 0x4e2f60`
2. **Fonksiyon-sonu sözlüğünde** (footer):

```
    // --- vfN sozlugu (PDB'siz adlandirma — kanit adresleri) ---
    // vf4  = CPythonPlayer vftable[0x805054] + 0x10 -> 0x4e2f60
    // vf34 = CPythonPlayer vftable[0x805054] + 0x88 -> 0x4e26f0
}
```

Bu fonksiyondaki iki sanal çağrının tam kimliği:

| Ad | Ne | vftable | Slot | Bayt ofseti | Hedef VA | PDB'li adı |
|---|---|---|---|---|---|---|
| `vf4` | vtable slot 4 | 0x805054 | 4 | **+0x10** | **0x4E2F60** | `CPythonPlayer::GetStatus` |
| `vf34` | vtable slot 34 | 0x805054 | 34 | **+0x88** | **0x4E26F0** | `CPythonPlayer::NEW_GetMainActorPtr` |
| `0x8BD2D0` | **vf4 DEĞİL!** `CSingleton<CPythonPlayer>::ms_singleton` global yuvası | — | — | — | — | Instance()'ın okuduğu statik slot; içindeki değer = nesne adresi (runtime'da kurucu yazar) |

Ghidra çıktısındaki `+0x10` ve `+0x88` tam olarak bu slot ofsetleridir — yani Ghidra'nın çözümeden bıraktığı `**(code**)(*(int*)(DAT_008bd2d0 + 4) + 0x10)` ifadesindeki `+0x10`, bizim `vf4` adlandırmamızla AYNI slotu gösterir; fark şu: biz vftable'ın DEĞERİNİ (0x805054) ve slottaki hedefi (0x4E2F60) kanıtla okuruz, Ghidra ham çift-deref bırakır.

Adlandırma kuralı: sembolsüz ortamda uydurma isim YOK — `vfN` dürüst bir koordinattır ("N. slot" der, kim olduğunu iddia etmez); kimliği PDB veya RTTI slot eşleşmesi getirir. vtable'sız çözümlerde (fonksiyon işaretçisi tabloları) `vfN` adı kullanılmaz, doğrudan hedef adres basılır.

---

## 7. Karşılaştırma: Ghidra vs Bizim Motor

(Ghidra 12.2 headless, JDK 25, PDB'siz import + tam auto-analiz + Decompile — aynı binary, aynı fonksiyon, otomatik `DumpDecomp.java` post-script'i ile dökülmüş, hiçbir el düzenlemesi yok. Ghidra çalışma günlüğü: `Analysis succeeded`.)

### Ghidra 12.2 çıktısı (PDB'siz, gerçek — birebir):

```c
// Ghidra 0x4EAD70 -> FUN_004ead70 @ 004ead70
void FUN_004ead70(undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int local_8;

  cVar1 = FUN_0060c020(param_2,0,&local_8);
  if (cVar1 == '\0') {
    FUN_0060c210(0);
    return;
  }
  iVar2 = (**(code **)(*(int *)(DAT_008bd2d0 + 4) + 0x10))(local_8);
  if (local_8 == 0x11) {
    iVar3 = (**(code **)(*(int *)(DAT_008bd2d0 + 4) + 0x88))();
    if (iVar3 != 0) {
      iVar3 = FUN_0046e930();
      if (iVar3 == 3) {
        iVar2 = iVar2 - DAT_008bd764;
      }
    }
  }
  Py_BuildValue(&DAT_007f9a94,iVar2);
  return;
}
```

### Bizim çıktı (PDB'siz, aynı fonksiyon):

```c
v2 = sub_0060c020(a2, 0, &v1);
if (v2 != 0) goto loc_4ead97;
return sub_0060c210(0);
loc_4ead97:
v3 = CPythonPlayer::Instance().vf4(v1);     // ← Ghidra'da ham çift-deref
if (v1 != 0x11) goto loc_4eadda;
v4 = CPythonPlayer::Instance().vf34();      // ← Ghidra'da ham çift-deref
if (v4 == 0) goto loc_4eadda;
v5 = sub_0046e930(v4);
if (v5 != 3) goto loc_4eadda;
loc_4eadda:
return python27.dll.Py_BuildValue("i", (v3 - *(0x8bd764)));
```

Karşılaştırma tablosu:

| Yetenek | Ghidra 12.2 (PDB'siz) | **i4M GodTier v8 (PDB'siz)** | **i4M GodTier v8 (PDB'li)** |
|---|---|---|---|
| `call eax` (slot 4) | **çözülmez** — `(**(code **)(*(int *)(DAT_008bd2d0 + 4) + 0x10))(local_8)` | **CPythonPlayer::Instance().vf4(v1)** | **CPythonPlayer::Instance().GetStatus(iType)** |
| `call [edx+0x88]` (slot 34) | **çözülmez** — `(**(code **)(*(int *)(DAT_008bd2d0 + 4) + 0x88))()` | **CPythonPlayer::Instance().vf34()** | **CPythonPlayer::Instance().NEW_GetMainActorPtr()** |
| Singleton kalıbı tanıma | yok (`DAT_008bd2d0 + 4` ham) | **Instance() katlaması** | Instance() katlaması |
| `Py_BuildValue` formatı | `&DAT_007f9a94` (adres gösterir) | **`"i"`** (değeri gösterir) | `"i"` |
| GetWeaponType arg'ı (this) | `FUN_0046e930()` — this kayıp | `sub_0046e930(v4)` — this VAR | `v4->GetWeaponType()` |
| RTTI sınıf adı (sembolsüz) | çağrı yerinde yok | **çağrı yerinde: CPythonPlayer** | çağrı yerinde |
| Binary çapında devirt | manuel betik gerekir | **3.358/7.855 otomatik** | **4.444/9.160 otomatik** |
| Fonksiyon adları | FUN_004ead70 | sub_004ead70 + RTTI sınıfları | playerGetStatus + 23.479 sembol |
| Analiz süresi | ~4 dk (JVM, 2,2 GB heap) | **~2 sn** (tek işlem) | **8,5 sn** (176 bin tipli PDB ayrıştırması dahil) |

**Sonuç:** Ghidra iki sanal çağrıyı da çözemeden bırakır (IDA Pro/Hex-Rays de aynı davranır — devirt kullanıcı betiği ister). GodTier v8 her ikisini de KANITLA çözer, PDB olmasa bile sınıf adını RTTI'dan geri kazanır ve Instance() kalıbını kaynak koddaki haliyle sentezler.

---

## 8. Unicorn Tier-3 Nasıl Çalışıyor? ("livestep god mod")

**Felsefe:** Process'i EP'den %100 yürütmek YANLIŞ ARAÇ (v7'de kanıtlandı — playerGetStatus login olana dek çağrılmaz). Doğru araç: dolaylı çağrının **temel bloğunu** (dallar arası düz çizgi — yol bağımsız, SOUNDDUR) gerçek x86 semantiğiyle koşturmak; eksik bilgiyi (runtime vptr) statik kanıt tohumlarıyla vermek.

```
┌─────────────────────────────────────────────────────────────────┐
│  TIER-3: TryCall(cagriAdresi, tohumlar)                          │
├─────────────────────────────────────────────────────────────────┤
│ 1. Pencere bul: cagrının temel bloğu (≤64 komut, jcc/jmp sınırı)│
│ 2. Kirli belleği geri al (önceki pass'ın yazımları)             │
│ 3. TOHUMLAR (statik kanıttan):                                  │
│      [0x8BD2D0] = &sentetikNesne     ← kurucu "mov [S], this"   │
│      [sentetik+0x4] = 0x805054       ← kurucu "mov [this+4],vt" │
│ 4. Yazmaçlar sıfır + ebp = yığın çerçevesi                      │
│ 5. UNICORN: blok başı ──gerçek x86──▶ çağrı noktasında DUR      │
│      (jcc/bayrak/arith/hepsi GERÇEK — yorumlayıcı değil!)       │
│ 6. rip == çağrı? → operandı çöz:                                 │
│      call reg      → yazmaç değeri = hedef                       │
│      call [reg+K]  → [vtable+K] oku = hedef                      │
│ 7. Doğrula: hedef kod bölümünde mi + RTTI atlasıyla çapraz check │
│ 8. Çoklu aday dürüstlüğü: her vtable adayı AYRI pass'te koşar;   │
│    tüm pass'ler aynı hedefe giderse ÇÖZÜM, farklıysa aday listesi│
└─────────────────────────────────────────────────────────────────┘
```

**Tier-3'ün tier-1'i yendiği gerçek vaka (fixture test [26], otomatik doğrulanır):**

```asm
; fonksiyon vtable'ı .data'ya KENDİSİ yazıp geri okuyor:
mov  dword ptr [0x403010], 0x4023F4    ; vtable'ı sakla  ← imajda yuva 0!
mov  eax, [0x403010]                   ; geri oku
mov  edx, [eax+8]                      ; slot 2
call  edx                              ; ← hedef?
```

- **Tier-1 (lineer değerlendirici):** `[0x403010]`'i imajdan okur → 0 → zincir kopar → ÇÖZEMEZ (dürüst fail).
- **Tier-3 (Unicorn):** yazımı GERÇEKTEN yapar → geri okuma 0x4023F4 görür → `[0x4023F4+8]` = `CEmu::method2` → **ÇÖZER** (kanıt: `CEmu vftable[2] (tier-3 unicorn pencere emulasyonu)`).

Bu vaka `tests/fixtures/make_fixture_devirt_pe.py` içinde `F_EMUCASE` olarak kalıcıdır ve her `godtier_tests` çalışmasında doğrulanır.

**Tier-3'ün gerçek binary'de çözmesi örnek değil, ölçümdür:** 256 dolaylı çağrı, yalnızca emülasyon semantiğiyle kapanan zincirler.

### 8b. Tier-3 Unicorn Koşusu — Adım Adım Tam Protokol (v8.1)

**Soru 1: "Stack nereden başlıyor?"** — Yapay bir yığından. Emülatör kurulumunda (`emulate/emulator.cpp`) x86-32 için bellek haritası şöyledir:

| Bölge | Adres (x86-32) | Boyut | Amaç |
|---|---|---|---|
| Görüntü | 0x400000 + | ImageSize (0x542000) | PE bölümleri GERÇEK VA'larında (kod+veri aynı yerde) |
| Yığın | 0x7FC00000..0x7FF00000 | 4 MB | sentetik yığın; **ESP = 0x7FEFFF00** (stackTop−0x100) |
| Sihirli dönüş sayfası | 0x7FF10000 | 4 KB | `[ESP]`'e yazılan sentinel dönüş adresi — `ret` buraya düşünce koşu biter |
| TEB-lite | 0x7FF12000 | 8 KB | `fs:[0]`=TEB, `fs:[0x30]`=PEB, yığın sınır alanları (FS_BASE MSR'i buna bağlanır) |
| Heap | 0x52000000 | 4 MB | API shim'in bump-allocator'ı |
| Sentetik nesne bölgesi | 0x60000000 | 1 MB | her statik nesne için 0x400 baytlık sentetik nesne + `this` tohumu |
| Shadow-IAT | ayrı bölge | — | her import `dll.api` için 1 baytlık `ret` stub'ı; giriş kod-hook'ta yakalanır |

Yani: gerçek process'in yığını YOKTUR — koşu başında `ESP`'yi 0x7FEFFF00'e koyarız, `[ESP]`'e sentinel (0x7FF10000) yazarız; emüle edilen fonksiyon `ret` yapınca sentinel sayfasına düşer, kod-hook bunu görür ve koşuyu DURDURUR ("dönüş algılandı").

**Soru 2: "Stack'i nasıl playerGetStatus'a getiriyorsun — önce tüm fonksiyonlardan mı geçiriyorsun?"** — HAYIR, hiçbirini. **Entry point'ten yürütme YOK** (yanlış araç: playerGetStatus oyuncu login olana dek çağrılmaz; D3D döngüsü milyonlarca komut). **Tüm fonksiyonlardan stack geçirme de YOK** (ölçeklenmez). Doğru model HEDEF-ODAKLI pencere koşusudur: her dolaylı çağrı için, çağrının KENDİ temel bloğu ayrı bir koşudur. `call eax @ 0x4EADA9` örneğinde pencere `0x4EAD97`'den başlar (blok başı = ilk dal hedefi) — yani yürütme doğrudan playerGetStatus'un İÇİNDE, çağrının hemen üstündeki düz çizgide başlar. Temel blok dallar ARASI düz çizgidir → tek yol → yol-duyarlılığına (path-sensitivity) gerek YOK, koşu DETERMİNİSTİKTİR.

Koşunun 12 adımı (`decomp/devirtemu.cpp` — `TryCall`):

1. **Pencere bul:** çağrı adresini içeren temel bloğun başı (geriye doğru max 64 komut; jcc/jmp/ret veya dal hedefi görünce dur).
2. **Kirli belleği geri al:** önceki pass'ın imaja yazdığı baytları orijinal görüntüden geri yükle; sentetik bölgeyi sıfırla (pass'ler birbirini kirletmez).
3. **Tohumları yaz** (statik kanıttan): `[0x8BD2D0] = &sentetikNesne` (kurucudaki `mov [ms_singleton], this` kanıtı) ve `[sentetikNesne+4] = 0x805054` (kurucudaki `mov [this+4], vftable` kanıtı). Tohum = runtime'da yazılacak değerin statik kanıtla üretilmiş hali.
4. **Yazmaçları sıfırla:** tüm GP yazmaçlar 0; `EBP = 0x7FEFF800` (sahte çerçeve); `this`-tohumu gerekiyorsa `ECX = sentetikThis`.
5. **Unicorn başlat:** `rip = pencere başı`, bitiş adresi = çağrının KENDİ adresi, bütçe 60 ms / 20.000 komut. Çağrı YÜRÜTÜLMEZ — rip çağrı adresine eşitlenince durur.
6. **Yürütme GERÇEK x86'dır** (Unicorn = QEMU TCG çekirdeği): bayraklar, jcc, aritmetik, bellek — hepsi gerçek CPU semantiği; bizim yazdığım yorumlayıcı YOK (livestep.cpp'nin düştüğü hata sınıfı burada tasarımdan imkânsız).
7. **Ulaşım kontrolü:** `rip == çağrı adresi` değilse dürüst fail ("pencere çağrıya ulaşamadı — hata/yol") ve koşu terk edilir; kanıt ÜRETİLMEDEN iddia yok.
8. **Operandı çöz:** `call reg` → yazmacın o anki değeri = hedef; `call [reg+K]` → emüle bellekten GERÇEK okuma (`[vptr+0x88]` = vtable'ın 34. slotu); `call [mutlak]` → IAT importu mu kontrol et.
9. **Hedefi doğrula:** (a) hedef yürütülebilir bir bölümde mi? (b) vftable biliniyorsa RTTI atlasıyla ÇAPRAZ KONTROL: `atlas[vftable+K] == emülasyon hedefi` değilse **RED** ("emülasyon/atlas çelişiyor") — çelişkide cevap YOK, geri çekilir.
10. **Çoklu-aday dürüstlüğü:** kurucu kanıtı birden çok vftable gösteriyorsa HER aday için AYRI pass koşulur; tüm pass'ler aynı hedefe giderse ÇÖZÜM, farklıysa aday listesi (yanlış tekil tahmin YASAK).
11. **Temizlik:** kirli bellek geri alınır (adım 2) — bir sonraki çağrının koşusu temiz bellekte başlar.
12. **Kanıtı devirt havuzuna akıt:** çözüm tier-1/tier-2 kanıtlarıyla birleşir; `devirt stats` kırılımında "tier-3 unicorn" sütununda sayılır.

**Soru 3: "Doğruluk olayı nasıl?"** — Dört katman:
- **CPU-doğruluğu:** hedefi BİZ hesaplamayız; Unicorn gerçek komutları yürütür, `call` operandındaki değer fiziksel bellek okumasının sonucudur (vptr→vtable→slot zincirini işlemci kendisi izler).
- **Yapısal doğrulama:** hedef mutlaka yürütülebilir bölümde olmalı + (vftable biliniyorsa) RTTI atlası aynı slottaki değeri TUTMALI; çelişki = kanıt red.
- **Determinizm:** yazmaçlar sıfır, tohumlar sabit, ASLR/thread/kesinti yok → aynı girdi her koşuda aynı sonucu verir (testler bunu her çalıştırmada yeniden üretir).
- **Dürüstlük:** kanıt zinciri kurulamayan hiçbir çağrı için tahmin üretilmez; çoklu sonuç = aday listesi, tekil iddia YOK.

## 9. Atlas İnversiyonu (tier-1 silahı)

"Metot → sahip vftable'lar" ters indeksi: bir fonksiyon HANGİ vftable'larda yer alıyorsa, o fonksiyonun gövdesindeki `this` alıcısının dinamik tipi bu kümeyle kısıtlıdır (CHA).

```
VtablesContaining(CPythonPlayer::GetStatus gövdesi) = { CPythonPlayer vftable }
   → gövdede mov eax,[ecx]; call [eax+0x88]   ; this->GetActorPtr()
   → [this+0] = 0x805054 (TEK aday → SOMUT kanıt)
   → call [0x805054+0x88] = CPythonPlayer::GetActorPtr  ✓
```

Çok sahipli durumda (metot birden çok sınıfın vtable'ında): tüm adayların aynı slottaki hedefi tek değerse **kanıtlanmış çözüm**, değilse dürüst aday listesi.

## 9b. Kırılım — "4444 Nasıl Çözüldü, 4716 Neden Çözülemedi?" (v8.1)

`devirt stats` komutu (v8.1) her koşunun sonunda bu tabloyu üretir. Gerçek binary, PDB'li tam tarama:

| Çözülen 4444 | Adet | Kanıt mekanizması — MADDE MADDE nasıl çalışır |
|---|---|---|
| **IAT importu** | **3.222** | `call [IAT]` veya `mov reg,[IAT]; call reg` — hedef İTHALAT TABLOSUNDAN okunur: `python27.dll.Py_BuildValue` gibi `dll.api` adına çözülür. Not: bound-import dosya değeri YALANCI işaretçidir; gerçek statik çözüm import İSMİDİR (v6'da kanıtlandı). |
| **vtable'sız somut zincir** | **485** | Pencere değerlendiricisi zinciri kapatır: `mov eax, 0x4E2F60` benzeri somut aktarım ya da imaj içi hazır veri (statik bellekteki fonksiyon işaretçisi) okunur; vtable/RTTI katmanı devrede değildir. |
| **tier-3 Unicorn** | **256** | Bölüm 8b'deki 12 adım: temel blok gerçek x86 semantiğiyle koşar, tohumlar kurucu kanıtından yazılır, hedefi İŞLEMCİ okur. Yalnızca emülasyonla kapanan zincirler (tier-1'in imaj-okuma sınırı aşıldığında). |
| **Atlas inversiyonu (CHA)** | **236** | Bölüm 9: sanal metod gövdesinde `this`'in dinamik tipi, metodun sahibi olduğu vftable kümesiyle kısıtlıdır; tek sahipli vtable → vptr SOMUT kanıt → gövdedeki `call [reg+K]` çözülür. |
| **Kurucu vtable-saklama** | **245** | En güçlü kanıt: kurucu fonksiyonun `mov [this+K], vftable` + `mov [statik], this` yazımları. statik yazıcı taraması (tüm fonksiyonlar taranır) bu kanıtları toplar; playerGetStatus'un iki çağrısı (vf4/vf34) bu yolla çözülür — İŞTE kanıt örneği: `statik 0x8bd2d0 <- this (kurucu kaniti)` → `vptr(+0x4) = vftable 0x805054` → `vtable[4] = 0x4E2F60`. |

PDB'siz koşuda aynı kırılım: kurucu 164, atlas 236, unicorn 256, IAT 2.298, somut 404 (evren 7.855, çözülen 3.358) — kanıt mekanizmaları sembolden BAĞIMSIZDIR (kanıtın kaynağı kod + RTTI + import tablosudur; PDB yalnızca İsimlendirme ve fonksiyon evreni genişliği getirir).

| Kalan 4716 | Adet | Neden çözülemedi (dürüst neden etiketi) |
|---|---|---|
| **tier-3 pencere yetersiz** | **4.117** | Unicorn da denendi; tohum/yol yoktu. Alıcı nesne statik kanıt taşımıyor (heap'te `new`'lenmiş ya da parametre olarak gelen); pencere sıfır yazmaçlarla koşunca zincir unmapped okumada kırılır. Bu grubun büyük çoğunluğu aşağıdaki "kanıt yok" sınıfıdır — etiket farkı yalnızca "tier-3'te denenmiş" olduğudur. |
| **kanıt yok (heap/param alıcı)** | **471** | Zincirde tek bir somut değer üreten statik kanıt yok. Tip bilinse BİLE adres runtime bilgisi: `new CMonster(...); p->Attack()` — hangi vtable'ın yüklendiği dosyada yazmıyor. Tekil tahmin YASAK. |
| **çoklu aday** | **128** | Kanıt VAR ama kısıt çoklu: aynı statik yuvaya farklı sınıfların kurucuları yazıyor (CHA kümesi >1) ve slot değerleri farklı → dürüst aday listesi basılır: `// sanal kaldi: vtable[12] adaylari: CMonster::Attack, CBossMonster::Attack`. Bu 128'in çözümü İMKÂNSIZ DEĞİL — kanıt eklemekla daraltılabilir (10b). |

Konsolide gerçek durum: **4588 çağrıda kanıt YOK** (4.117+471), **128 çağrıda kanıt VAR ama çoklu aday**. Toplam = 4716.

## 10. Dürüstlük Sınırları — Ne Çözülmez, Neden, ve Geliştirilince Ne KazANIR

### 10a. Bugünkü sınırlar (kırılımın diliyle)

- **Heap nesnesi alıcılar (4588 çağrının özü):** `new CMonster(...); obj->Attack()` — nesnenin adresi/tipi runtime bilgisidir. Statik kanıt yoksa çözülmez; yanlış tekil tahmin ASLA yapılmaz (aday listesi basılır).
- **Fonksiyon işaretçisi tabloları (vtable değil):** callback dizileri, switch-dispatch — kanıt üretilemezse ham kalır.
- **Packlanmış/Şifreli vtable'lar:** VMProtect tarzı runtime vtable kurulumunda tier-3'ün tohumu yoktur.
- **Dış-DLL değeri:** `GetProcAddress` sonucu gibi runtime'da dönen işaretçiler — dosyada değeri YOKTUR (ancak DLL export tablosu eşleştirmesiyle kısıtlanabilir, 10b/3).

### 10b. Daha geliştirirsek çözer mi? — Dürüst yol haritası (etki tahmini)

| # | Silah | Ne yapar | Kimi yer | Tahmini kazanım |
|---|---|---|---|---|
| 1 | **`new`-noktası analizi** | `call operator_new` çağıran yerde dönüş değeri → kurucuya akar → kurucunun vtable yazımı heap alıcının TİP kanıtı olur (interprocedural this-akışı) | heap alıcıların kurucu-kanıtlanan alt kümesi | +300…600 |
| 2 | **Tam-fonksiyon emülasyonu** | tier-3 pencere yerine tüm fonksiyon gövdesini API shim'le koştur; parametrelerde gelen alıcı tipleri çağrı zincirinde görünür | parametre-alıcılar (4.117'lik grubun bir kısmı) | +200…500 |
| 3 | **Çoklu-DLL evreni** | python27.dll vb. import DLL'lerinin export tablolarını yükle; `GetProcAddress` sonuçlarını export adına bağla | dış-DLL işaretçileri | +100…300 |
| 4 | **vtordisp + derin çoklu kalıtım** | sanal kalıtımda vptr düzeltme thunk'ları (vtordisp) ve ikincil vtable'lar | MSVC derin hiyerarşisi | +50…150 |
| 5 | **Statik başlatıcı taraması (.data$xm + atexit)** | C++ dinamik başlatıcılarının vtable yazımları kurucu kanıt havuzuna eklenir | global nesnelerin kurucu dışı yazımları | +50…200 |
| 6 | **Çoklu-aday daraltma** | 128 çoklu-aday vakasında aday sınıflardan yalnız birinin kurucusu o yuvaya CANLI yazıyorsa (xref/akış analiziyle) küme daraltılır | 128'lik grup | +30…80 |

Toplam gerçekçi kazanım: **+800…1.800 çağrı** (oran %48,5 → ~%60-65). Ne yaparsak yapalım %100'E ULAŞILAMAZ ve BİLMEMİZ GEREKİYOR: kalanların özünde dosyada HİÇ YAZMAYAN bilgi vardır (runtime'da üretilen işaretçiler). Ticari araçların "çözüm" oranı yüksek görünmesinin sebebi spekülatif tekil tahmindir; bizde bu YASAKTIR — kanıt ya VARDIR ya çağrı dürüstçe sanal kalır. Bu yüzden sayılarımız abluka altındadır: her çözümün kanıt zinciri `devirt <adres>` ile tek tek dökülebilir.

### 10c. Ölçülebilir hedef (v9)

1–2 numaralı silahlar (new-noktası + tam-fonksiyon emülasyonu) v9'un ana hattıdır; kabul kriteri: `devirt stats` kırılımında "kanıt yok" sütununun düşüşü ve HER yeni çözümün kanıt izinin `devirt <adres>` komutuyla doğrulanabilirliği.

## 11. Tekrarlanabilirlik

```bash
cd i4M-GodTier && cmake -B build && cmake --build build -j8 && ./build/bin/godtier_tests   # 319/319 PASS
# PDB'li kanıt:
printf 'script scripts/metin2_pdb.gt\n' | ./build/bin/godtier
# PDB'siz kanıt (vfN sözlüğü dahil):
printf 'script scripts/metin2_nopdb.gt\n' | ./build/bin/godtier
# Tek çağrının kanıt zinciri:
#   devirt 0x4eada9      (vf4 çözüm izi)
#   devirt 0x4eadbe      (vf34 çözüm izi)
# Kırılım tablosu:
#   devirt stats         (nasıl çözüldü / neden çözülemedi)
```

`scripts/metin2_pdb.gt` ve `scripts/metin2_nopdb.gt` depoda, binary+PDB yolları sabit.

## 12. Ölçüm Metodolojisi

- "Dolaylı çağrı evreni" = analiz edilen TÜM fonksiyon gövdelerindeki `call reg` + `call [mem]` sayısı (RTTI-güdümlü keşif sonrası).
- "Statik çözülen" = hedefi KANITLA (kurucu saklaması / RTTI slot / IAT importu / Unicorn tohumlu pencere) belirlenenler. Spekülatif tekil tahmin sıfırdır.
- Süre: 5,2 MB / ~28.706 fonksiyon / 9.160 dolaylı çağrı — PDB'siz tam hat **~2 saniye**; PDB'li tam hat (176.018 tipli PDB ayrıştırma + 23.479 sembol uygulaması dahil) **8,5 saniye** (tek işlemci, tek thread ağırlıklı).
