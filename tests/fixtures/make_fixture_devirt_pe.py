#!/usr/bin/env python3
"""
i4M GodTier v7 DEVRIT-PRO fixture uretici — metin2client.exe deseninin
ELLE INSA EDILMIS minyaturu (PDB YOK — test sembolsuz cozumu kanitlar!).

Gercek binary'den birebir alinan desen (playerGetStatus):
    mov  ecx, [ms_singleton]   ; .data (imajda 0 — kurucu yazar!)
    add  ecx, 4                ; ikincil taban ofseti
    mov  eax, [ecx]            ; vptr  (runtime)
    mov  eax, [eax+0x10]       ; slot 4  -> CPlayer::GetStatus
    call eax                   ; DEVRIT HEDEFi 1
    ...
    mov  edx, [ecx]            ; vptr
    call dword ptr [edx+0x88]  ; slot 34 -> CPlayer::GetActorPtr
                               ; DEVRIT HEDEFi 2 (bellek-operandli cagri)

Kurucu (gercekteki CPythonPlayer::CPythonPlayer gibi):
    mov  [ecx], vft_base0      ; ara vtable (kayit edilir ama zincir kullanmaz)
    lea  eax, [ecx+4]
    mov  [eax], vft_tmp        ; ara vtable (EZILECEK)
    mov  [eax], vft_player     ; FINAL CPlayer vftable (SON YAZIM KAZANIR!)
    mov  [ms_singleton], ecx   ; ISPAT: statik <- this

MSVC ABI dogrulugu (v7 motorunun bekledigi SEY):
    - vptr degeri = vftable'in ILK SLOTunun adresi (COL isaretcisi vptr-4'te
      durur; IDA'nin ??_7 etiketi COL isaretcisinin adresidir, nesneye
      yazilan deger ??_7+4'tur). Bu nedenle kurucular VFT+4 saklar.
    - COL x86: alanlar MUTLAK VA (sig=0). x64'te RVA olurdu (sig=1).
    - CExtra2 de ayni statige yazarsa -> MS_EXTRA vptr'yi 2 adayli olur:
      call [edx] DURUSTCE COZULMEZ (CExtra::method0 / CExtra2::method0).
"""
import struct, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "fixture_devirt.exe"
IMAGE_BASE = 0x400000
FILE_ALIGN, SEC_ALIGN = 0x200, 0x1000
HDRS = 0x200

# ---------------- adres plani (RVA) ----------------
TEXT_VA, RDATA_VA, DATA_VA = 0x1000, 0x2000, 0x3000

# .rdata ici (bolum-goreli ofset; RVA = RDATA_VA + off)
TD_PLAYER   = 0x000   # TypeDescriptor ".?AVCPlayer@@"
TD_EXTRA    = 0x040   # ".?AVCExtra@@"
TD_EXTRA2   = 0x080   # ".?AVCExtra2@@"
CHD_PLAYER  = 0x0C0   # ClassHierarchyDescriptor
CHD_EXTRA   = 0x0D8
CHD_EXTRA2  = 0x0F0
BCD_PLAYER  = 0x108   # BaseClassDescriptor
BCD_EXTRA   = 0x120
BCD_EXTRA2  = 0x138
BARR_PLAYER = 0x150   # BaseClassArray (1 eleman)
BARR_EXTRA  = 0x158
BARR_EXTRA2 = 0x160
COL_BASE0   = 0x170   # ara vftable'larin COL'u (CPlayer kimligi, ofset 0)
COL_PLAYER  = 0x190   # CPlayer ana COL (nesne ofseti +4!)
COL_EXTRA   = 0x1B0
COL_EXTRA2  = 0x1D0
VFT_BASE0   = 0x1F0   # ara vftable 1 [COL][slot0]
VFT_TMP     = 0x1F8   # ara vftable 2 [COL][slot0]
VFT_PLAYER  = 0x200   # CPlayer vftable: [COL][40 slot]
VFT_EXTRA   = 0x2A4   # CExtra vftable:  [COL][4 slot]   (0x200+41*4=0x2A4)
VFT_EXTRA2  = 0x2B8   # CExtra2 vftable: [COL][4 slot]   (0x2A4+5*4=0x2B8)
STR_I       = 0x2D0   # "i\0"                             (0x2B8+5*4=0x2CC -> hizala)
DLL_NAME    = 0x2D8   # "py.dll\0"
HINT_BUILD  = 0x2E0   # hint+ "Py_BuildValue"
HINT_NEW    = 0x2F8   # hint+ "PyTuple_New"
INT_ARR     = 0x310   # INT thunk dizisi [HINT_BUILD][HINT_NEW][0]
IAT_ARR     = 0x31C   # IAT (FirstThunk) [0][0][0] — loader doldurur
IMP_DESC    = 0x328   # import deskriptoru + NULL terminator
# v8: CEmu sinifi (tier-3 unicorn kanit sinifi)
TD_EMU      = 0x360
CHD_EMU     = 0x3A0
BCD_EMU     = 0x3B8
BARR_EMU    = 0x3D0
COL_EMU     = 0x3D8
VFT_EMU     = 0x3F0   # CEmu vftable: [COL][3 slot] (slot2 = F_EMU_M2)

# .data ici (RVA = DATA_VA + off)
MS_SINGLE   = DATA_VA + 0x0   # ms_singleton (imajda 0 — kurucu yazar)
MS_EXTRA    = DATA_VA + 0x4   # ms_extra (IKI kurucu yazar -> adayli!)
TWOHANDED   = DATA_VA + 0x8   # TWOHANDED_..._ATT_SPEED = 2 (imajda hazir)
EMU_OBJ     = DATA_VA + 0x10  # v8: tier-3 vakasi — vtable BURADA saklanir
                               # (imajda 0; fonksiyon KENDİ yazar — yalnız
                               #  EMULASYON yakalar, lineer değerlendirici değil!)

# .text fonksiyonlari (RVA):
F_DUMMY     = 0x1010    # vtable dolgu hedefi (ret)
F_GETSTATUS = 0x1020    # CPlayer::GetStatus (v8: sanal öz-çağrı — inversiyon vakası)
F_GETACTOR  = 0x1030    # CPlayer::GetActorPtr
F_EXTRA_M   = 0x1040    # CExtra::method0
F_EXTRA2_M  = 0x1050    # CExtra2::method0 (AYNI slot, FARKLI impl)
F_GETWTYPE  = 0x1060    # CInstanceBase::GetWeaponType benzeri
F_EMU_M2    = 0x1070    # v8: CEmu::method2 (tier-3 hedefi)
F_CTOR      = 0x1080    # CPlayer::CPlayer (vtable + singleton kaniti)
F_CTOR_EX   = 0x10A0    # CExtra::CExtra
F_CTOR_EX2  = 0x10C0    # CExtra2::CExtra2 (MS_EXTRA'ya da yazar -> belirsizlik)
F_PGS       = 0x10E0    # playerGetStatus (TEST HEDEFi)
F_AMBIG     = 0x1160    # muğlak sanal cagri (dürüst çoklu-aday)
F_EMUCASE   = 0x11E0    # v8: TIER-3 VAKASI (lineer değerlendirici BAŞARISIZ,
                        #     Unicorn emülasyon BAŞARILI — vtable'ı .data'ya
                        #     kendisi yazıp geri okuyan blok)
F_ENTRY     = 0x1220    # entry: kuruculari + testleri cagirir (kesif icin)

def va(rva): return IMAGE_BASE + rva
def rel32(src_next, dst): return struct.pack("<i", dst - src_next)

# ---------------- etiketli mini-assembler (offset hatasi imkansiz) ----------
class Asm:
    def __init__(self):
        self.b = bytearray()
        self.labels = {}
        self.fix = []          # (pos, label) — 8-bit goreli
    def here(self): return len(self.b)
    def label(self, name):
        self.labels[name] = len(self.b)
        return self
    def emit(self, *bs):
        for x in bs:
            if isinstance(x, (bytes, bytearray)):
                self.b += x
            else:
                self.b.append(x & 0xFF)
        return self
    def jcc(self, opcode, label):     # 2 bayt short jcc: 0x75 jnz, 0x74 jz...
        self.b += bytes([opcode, 0])
        self.fix.append((len(self.b) - 1, label))
        return self
    def resolve(self):
        for pos, lab in self.fix:
            off = self.labels[lab] - (pos + 1)
            assert -128 <= off <= 127, f"short jcc tasmadi: {lab} ({off})"
            self.b[pos] = off & 0xFF
        return bytes(self.b)

# ---------------- .text ----------------
def fn_ret():            return bytes([0xC3])
def fn_getstatus():
    """v8: CPlayer::GetStatus(this) — SANAL ÖZ-ÇAĞRI VAKASI.
    Gövde this->GetActorPtr() çağırır: lineer değerlendirici this vptr'yi
    BİLMEZ; v8 atlas inversiyonu (metodun sahibi: CPlayer vftable, tek)
    [this+0] = vft_player kanıtı verir → slot 34 çözülür (tier-1)."""
    c  = b"\x8B\x01"                                          # mov eax, [ecx] (this vptr)
    c += b"\xFF\x90" + struct.pack("<I", 0x88)               # call [eax+0x88] (slot 34)
    c += b"\xC2\x04\x00"                                      # ret 4
    return c

def fn_getactor():       return bytes([0xB8, 0x44, 0x33, 0x22, 0x11,  0xC2, 0x04, 0x00])
def fn_extra_m():        return bytes([0xB8, 0x77, 0, 0, 0,  0xC2, 0x04, 0x00])
def fn_extra2_m():       return bytes([0xB8, 0x88, 0, 0, 0,  0xC2, 0x04, 0x00])
def fn_getwtype():       return bytes([0xB8, 0x02, 0, 0, 0,  0xC2, 0x04, 0x00])
def fn_emu_m2():         return bytes([0xB8, 0x99, 0, 0, 0,  0xC2, 0x04, 0x00])

def fn_emucase():
    """v8: TIER-3 VAKASI — lineer değerlendirici BAŞARISIZ olmak ZORUNDA:
    vtable'ı .data'ya KENDİSİ yazıp geri okur (imajda yuva 0'dır; lineer
    okuma imaj değerini görür → 0 → zincir kopar). Unicorn pencere
    emülasyonu YAZIMI GERÇEKTEN yapar → geri okuma vtable'ı görür →
    slot 2 = CEmu::method2 çözülür. Statik-kanıt tohumu YOK — saf x86
    semantiği farkı!)."""
    c  = b"\x55\x8B\xEC"                                       # push ebp; mov ebp,esp
    c += b"\xC7\x05" + struct.pack("<II", va(EMU_OBJ), va(RDATA_VA + VFT_EMU) + 4)
    c += b"\x8B\x05" + struct.pack("<I", va(EMU_OBJ))          # mov eax, [EMU_OBJ]
    c += b"\x8B\x50\x08"                                       # mov edx, [eax+8] (slot 2)
    c += b"\xFF\xD2"                                            # call edx  <-- TIER-3
    c += b"\x8B\xE5\x5D\xC3"                                   # mov esp,ebp; pop ebp; ret
    return c

def fn_ctor():
    """CPlayer::CPlayer(this) — METIN2 DESENI (vptr = ILK SLOT adresi!)."""
    c  = b"\xC7\x01" + struct.pack("<I", va(RDATA_VA + VFT_BASE0) + 4)  # mov [ecx], vft_base0
    c += b"\x8D\x41\x04"                                                 # lea eax, [ecx+4]
    c += b"\xC7\x00" + struct.pack("<I", va(RDATA_VA + VFT_TMP) + 4)     # mov [eax], vft_tmp (EZILECEK)
    c += b"\xC7\x00" + struct.pack("<I", va(RDATA_VA + VFT_PLAYER) + 4)  # mov [eax], FINAL (SON YAZIM)
    c += b"\x89\x0D" + struct.pack("<I", va(MS_SINGLE))                  # mov [ms_singleton], ecx
    c += b"\xC2\x04\x00"                                                 # ret 4
    return c

def fn_ctor_extra():
    c  = b"\xC7\x01" + struct.pack("<I", va(RDATA_VA + VFT_EXTRA) + 4)
    c += b"\x89\x0D" + struct.pack("<I", va(MS_EXTRA))
    c += b"\xC2\x04\x00"
    return c

def fn_ctor_extra2():
    c  = b"\xC7\x01" + struct.pack("<I", va(RDATA_VA + VFT_EXTRA2) + 4)
    c += b"\x89\x0D" + struct.pack("<I", va(MS_EXTRA))                   # AYNI statik!
    c += b"\xC2\x04\x00"
    return c

def fn_playergetstatus(rva):
    """playerGetStatus — KULLANICININ GERCEK DISASSEMBLY'ININ TAM YANSIMASI:
       (1) PyTuple_GetInteger + test al,al + jne erken-ret deseni
       (2) slot 4:  mov ecx,[s]; add ecx,4; mov eax,[ecx]; mov eax,[eax+0x10]; call eax
       (3) slot 34: mov edx,[ecx]; call dword ptr [edx+0x88]
       (4) GetWeaponType dogrudan
       (5) Py_BuildValue: push "i"; push esi; call dword ptr [IAT]"""
    a = Asm()
    a.emit(0x55, 0x8B, 0xEC)                # push ebp; mov ebp, esp
    a.emit(0x51)                            # push ecx (iType yeri: [ebp-4])
    a.emit(0x8D, 0x45, 0xFC, 0x50)          # lea eax,[ebp-4]; push eax (ret)
    a.emit(0x6A, 0x00)                      # push 0 (pos)
    a.emit(0xFF, 0x75, 0x0C)                # push [ebp+0xC] (poArgs)
    a.emit(0xE8, rel32(va(rva) + a.here() + 5, va(F_DUMMY)))   # call PyTuple_GetInteger
    a.emit(0x83, 0xC4, 0x0C)                # add esp, 0xC
    a.emit(0x84, 0xC0)                      # test al, al
    a.jcc(0x75, "main")                     # jnz main govdesine
    # erken ret yolu
    a.emit(0x6A, 0x00)                      # push 0
    a.emit(0xE8, rel32(va(rva) + a.here() + 5, va(F_DUMMY)))   # call Py_BuildException
    a.emit(0x83, 0xC4, 0x04)                # add esp, 4
    a.emit(0x8B, 0xE5, 0x5D, 0xC3)          # mov esp,ebp; pop ebp; ret
    # ---- ana govde ----
    a.label("main")
    a.emit(0x8B, 0x0D, struct.pack("<I", va(MS_SINGLE)))   # mov ecx, [ms_singleton]
    a.emit(0x83, 0xC1, 0x04)                # add ecx, 4
    a.emit(0x56)                            # push esi (callee-save)
    a.emit(0xFF, 0x75, 0xFC)                # push [ebp-4] (iType)
    a.emit(0x8B, 0x01)                      # mov eax, [ecx]      (vptr)
    a.emit(0x8B, 0x40, 0x10)                # mov eax, [eax+0x10] (slot 4)
    a.emit(0xFF, 0xD0)                      # call eax            <-- DEVRIT 1
    a.emit(0x8B, 0xF0)                      # mov esi, eax (iValue)  [8B /r: esi<-eax]
    a.emit(0x83, 0x7D, 0xFC, 0x11)          # cmp [ebp-4], 0x11 (POINT_ATT_SPEED)
    a.jcc(0x74, "end")                      # je end
    # slot 34 zinciri
    a.emit(0x8B, 0x0D, struct.pack("<I", va(MS_SINGLE)))   # mov ecx, [ms_singleton]
    a.emit(0x83, 0xC1, 0x04)                # add ecx, 4
    a.emit(0x8B, 0x11)                      # mov edx, [ecx]      (vptr)
    a.emit(0xFF, 0x92, struct.pack("<I", 0x88))              # call [edx+0x88] <-- DEVRIT 2
    a.emit(0x85, 0xC0)                      # test eax, eax
    a.jcc(0x74, "end")                      # jz end
    a.emit(0x8B, 0xC8)                      # mov ecx, eax (this)
    a.emit(0xE8, rel32(va(rva) + a.here() + 5, va(F_GETWTYPE)))  # call GetWeaponType
    a.emit(0x83, 0xF8, 0x03)                # cmp eax, 3 (WEAPON_TWO_HANDED)
    a.jcc(0x75, "end")                      # jnz end
    a.emit(0x2B, 0x35, struct.pack("<I", va(TWOHANDED)))     # sub esi, [TWOHANDED]
    # ---- son: Py_BuildValue("i", iValue) ----
    a.label("end")
    a.emit(0x56)                            # push esi
    a.emit(0x68, struct.pack("<I", va(RDATA_VA + STR_I)))    # push "i"
    a.emit(0xFF, 0x15, struct.pack("<I", va(RDATA_VA + IAT_ARR)))  # call [IAT slot0]
    a.emit(0x83, 0xC4, 0x08)                # add esp, 8
    a.emit(0x5E)                            # pop esi
    a.emit(0x8B, 0xE5, 0x5D, 0xC3)          # mov esp,ebp; pop ebp; ret
    return a.resolve()

def fn_ambig(rva):
    """muğlak: ms_extra IKI sinif tarafindan kurulur — slot 0 cagrisi
    CExtra::method0 ile CExtra2::method0 arasinda KALIR (dürüst adaylik)."""
    a = Asm()
    a.emit(0x55, 0x8B, 0xEC)                              # push ebp; mov ebp,esp
    a.emit(0x8B, 0x05, struct.pack("<I", va(MS_EXTRA)))   # mov eax, [ms_extra]
    a.emit(0x8B, 0x10)                                    # mov edx, [eax] (vptr, ofset 0)
    a.emit(0xFF, 0x12)                                    # call dword ptr [edx] (slot 0)
    a.emit(0x8B, 0xE5, 0x5D, 0xC3)                        # mov esp,ebp; pop ebp; ret
    return a.resolve()

def fn_entry():
    a = Asm()
    for ctor, this in ((F_CTOR, 0x500000), (F_CTOR_EX, 0x501000), (F_CTOR_EX2, 0x502000)):
        a.emit(0xB9, struct.pack("<I", this))             # mov ecx, this
        a.emit(0xE8, rel32(va(F_ENTRY) + a.here() + 5, va(ctor)))  # call ctor
    for callee, cleanup in ((F_PGS, 8), (F_AMBIG, 0), (F_EMUCASE, 0)):
        a.emit(0xE8, rel32(va(F_ENTRY) + a.here() + 5, va(callee)))
        if cleanup:
            a.emit(0x83, 0xC4, cleanup)                   # add esp, N (cdecl)
    a.emit(0x31, 0xC0, 0xC3)                              # xor eax,eax; ret
    return a.resolve()

text = bytearray()
def pad_to(off):
    while len(text) < off - TEXT_VA:
        text.append(0x90)
for rva, code in [(F_DUMMY, fn_ret()), (F_GETSTATUS, fn_getstatus()),
                  (F_GETACTOR, fn_getactor()), (F_EXTRA_M, fn_extra_m()),
                  (F_EXTRA2_M, fn_extra2_m()), (F_GETWTYPE, fn_getwtype()),
                  (F_EMU_M2, fn_emu_m2()),
                  (F_CTOR, fn_ctor()), (F_CTOR_EX, fn_ctor_extra()),
                  (F_CTOR_EX2, fn_ctor_extra2()),
                  (F_PGS, fn_playergetstatus(F_PGS)),
                  (F_AMBIG, fn_ambig(F_AMBIG)),
                  (F_EMUCASE, fn_emucase()),
                  (F_ENTRY, fn_entry())]:
    pad_to(rva)
    assert len(text) == rva - TEXT_VA, f"adres cakismasi @ {rva:#x}"
    text += code
while len(text) % FILE_ALIGN:
    text.append(0x90)
text_raw = bytes(text)

# ---------------- .rdata ----------------
rd = bytearray()
def rput(off, data):
    if len(rd) < off:
        rd.extend(b"\x00" * (off - len(rd)))
    rd[off:off + len(data)] = data

# TypeDescriptor: [type_info vft][spare][isim\0]
rput(TD_PLAYER,  struct.pack("<II", 0, 0) + b".?AVCPlayer@@\x00")
rput(TD_EXTRA,   struct.pack("<II", 0, 0) + b".?AVCExtra@@\x00")
rput(TD_EXTRA2,  struct.pack("<II", 0, 0) + b".?AVCExtra2@@\x00")
rput(TD_EMU,     struct.pack("<II", 0, 0) + b".?AVCEmu@@\x00")
# ClassHierarchyDescriptor: [sig=0][attrs=0][numBases=1][pBaseArray MUTLAK]
for chd, barr in ((CHD_PLAYER, BARR_PLAYER), (CHD_EXTRA, BARR_EXTRA),
                  (CHD_EXTRA2, BARR_EXTRA2), (CHD_EMU, BARR_EMU)):
    rput(chd, struct.pack("<IIII", 0, 0, 1, va(RDATA_VA + barr)))
# BaseClassDescriptor: [pTD][numContained][PMD x3][attrs=0x40]
for bcd, td in ((BCD_PLAYER, TD_PLAYER), (BCD_EXTRA, TD_EXTRA),
                (BCD_EXTRA2, TD_EXTRA2), (BCD_EMU, TD_EMU)):
    rput(bcd, struct.pack("<IIIIII", va(RDATA_VA + td), 0, 0, 0, 0, 0x40))
# BaseClassArray
for barr, bcd in ((BARR_PLAYER, BCD_PLAYER), (BARR_EXTRA, BCD_EXTRA),
                  (BARR_EXTRA2, BCD_EXTRA2), (BARR_EMU, BCD_EMU)):
    rput(barr, struct.pack("<I", va(RDATA_VA + bcd)))
# COL x86: [sig=0][offset][cdOffset][pTD MUTLAK][pCHD MUTLAK]
rput(COL_BASE0,  struct.pack("<IIIII", 0, 0, 0, va(RDATA_VA + TD_PLAYER), va(RDATA_VA + CHD_PLAYER)))
rput(COL_PLAYER, struct.pack("<IIIII", 0, 4, 0, va(RDATA_VA + TD_PLAYER), va(RDATA_VA + CHD_PLAYER)))  # ofset +4!
rput(COL_EXTRA,  struct.pack("<IIIII", 0, 0, 0, va(RDATA_VA + TD_EXTRA),  va(RDATA_VA + CHD_EXTRA)))
rput(COL_EXTRA2, struct.pack("<IIIII", 0, 0, 0, va(RDATA_VA + TD_EXTRA2), va(RDATA_VA + CHD_EXTRA2)))
rput(COL_EMU,    struct.pack("<IIIII", 0, 0, 0, va(RDATA_VA + TD_EMU),    va(RDATA_VA + CHD_EMU)))
# vftable'ler: [COL isaretcisi][slot0][slot1]...  (vptr = ilk SLOT adresi)
rput(VFT_BASE0, struct.pack("<I", va(RDATA_VA + COL_BASE0)) + struct.pack("<I", va(F_DUMMY)))
rput(VFT_TMP,   struct.pack("<I", va(RDATA_VA + COL_BASE0)) + struct.pack("<I", va(F_DUMMY)))
vf = struct.pack("<I", va(RDATA_VA + COL_PLAYER))
for i in range(40):
    t = F_GETSTATUS if i == 4 else (F_GETACTOR if i == 34 else F_DUMMY)
    vf += struct.pack("<I", va(t))
rput(VFT_PLAYER, vf)
ve = struct.pack("<I", va(RDATA_VA + COL_EXTRA))
for i in range(4):
    ve += struct.pack("<I", va(F_EXTRA_M if i == 0 else F_DUMMY))
rput(VFT_EXTRA, ve)
ve2 = struct.pack("<I", va(RDATA_VA + COL_EXTRA2))
for i in range(4):
    ve2 += struct.pack("<I", va(F_EXTRA2_M if i == 0 else F_DUMMY))
rput(VFT_EXTRA2, ve2)
# v8: CEmu vftable — slot 2 = F_EMU_M2 (tier-3 hedefi)
ve_ = struct.pack("<I", va(RDATA_VA + COL_EMU))
for i in range(3):
    ve_ += struct.pack("<I", va(F_EMU_M2 if i == 2 else F_DUMMY))
rput(VFT_EMU, ve_)
rput(STR_I, b"i\x00")
# --- import tablosu (gercek!): py.dll!Py_BuildValue + py.dll!PyTuple_New ---
rput(DLL_NAME,   b"py.dll\x00")
rput(HINT_BUILD, struct.pack("<H", 0) + b"Py_BuildValue\x00")
rput(HINT_NEW,   struct.pack("<H", 0) + b"PyTuple_New\x00")
rput(INT_ARR, struct.pack("<III", RDATA_VA + HINT_BUILD,
                          RDATA_VA + HINT_NEW, 0))   # INT girdileri RVA'dir (VA degil!)
rput(IAT_ARR, b"\x00" * 12)            # loader doldurur
rput(IMP_DESC, struct.pack("<IIIII", RDATA_VA + INT_ARR, 0, 0,
                           RDATA_VA + DLL_NAME, RDATA_VA + IAT_ARR)
           + b"\x00" * 20)             # NULL terminator deskriptor
while len(rd) % FILE_ALIGN:
    rd.append(0)
rdata_raw = bytes(rd)

# ---------------- .data ----------------
data_raw = struct.pack("<IIIII", 0, 0, 2, 0, 0)  # ms_single, ms_extra, TWOHANDED, pad, EMU_OBJ=0
data_raw += b"\x00" * ((-len(data_raw)) % FILE_ALIGN)

# ---------------- PE header (alan-exact IMAGE_OPTIONAL_HEADER32) -----------
def pe_header():
    nsec = 3
    NT_OFF = 0x40
    hdr = bytearray(HDRS)
    hdr[0:2] = b"MZ"
    hdr[0x3C:0x40] = struct.pack("<I", NT_OFF)
    hdr[NT_OFF:NT_OFF + 4] = b"PE\x00\x00"
    fh_off = NT_OFF + 4
    # COFF: machine=0x14C, nsec, optsz=0xE0, chars=EXECUTABLE|32BIT
    hdr[fh_off:fh_off + 20] = struct.pack("<HHIIIHH", 0x14C, nsec, 0, 0, 0, 0xE0, 0x0102)
    o = fh_off + 20
    def opt(fmt, *v):
        nonlocal o
        n = struct.calcsize("<" + fmt)
        hdr[o:o + n] = struct.pack("<" + fmt, *v)
        o += n
    opt("H", 0x10B)                       # +0   Magic (PE32)
    opt("BB", 14, 0)                      # +2   linker surumu
    opt("III", len(text_raw), len(rdata_raw) + len(data_raw), 0)   # +4/8/12 boyutlar
    opt("III", F_ENTRY, TEXT_VA, RDATA_VA)  # +16/20/24 EP, BaseOfCode, BaseOfData
    opt("IIII", IMAGE_BASE, SEC_ALIGN, FILE_ALIGN, 0)  # +28/32/36/40
    opt("HHHHHH", 4, 0, 0, 0, 4, 0)       # +40.. OS/img/subsys surumleri
    opt("III", 0x4000, HDRS, 0)           # +56/60/64 SizeOfImage, SizeOfHeaders, CheckSum
    opt("HH", 3, 0)                       # +68/70 Subsystem=console, DllChar
    opt("IIII", 0x100000, 0x1000, 0x100000, 0x1000)  # +72.. stack/heap
    opt("II", 0, 16)                      # +88/92 LoaderFlags, NumberOfRvaAndSizes
    # +96: veri dizinleri (16 x 8)
    dirs = bytearray(16 * 8)
    # [1] Import table
    struct.pack_into("<II", dirs, 1 * 8, RDATA_VA + IMP_DESC, 40)
    # [12] IAT
    struct.pack_into("<II", dirs, 12 * 8, RDATA_VA + IAT_ARR, 12)
    hdr[o:o + len(dirs)] = dirs
    o += len(dirs)
    assert o == fh_off + 20 + 0xE0, f"opt header boyutu bozuk: {o:#x}"
    # section tablosu: KANONIK konum (fh_off+20+optsz)
    so = fh_off + 20 + 0xE0
    secs = [
        (b".text",  text_raw,  TEXT_VA,  HDRS,                                       0x60000020),
        (b".rdata", rdata_raw, RDATA_VA, HDRS + len(text_raw),                       0x40000040),
        (b".data",  data_raw,  DATA_VA,  HDRS + len(text_raw) + len(rdata_raw),      0xC0000040),
    ]
    for name, raw, rva, foff, chars in secs:
        hdr[so:so + 40] = struct.pack("<8sIIIIIIHHI", name, len(raw), rva, len(raw),
                                      foff, 0, 0, 0, 0, chars)
        so += 40
    return bytes(hdr)

out = pe_header() + text_raw + rdata_raw + data_raw
open(OUT, "wb").write(out)
print(f"{OUT}: {len(out)} bayt yazildi")
print(f"  playerGetStatus @ {va(F_PGS):#x}  (decomp test hedefi)")
print(f"  CPlayer ctor    @ {va(F_CTOR):#x}  (kanit: son-yazim-kazanir)")
print(f"  CPlayer vftable @ {va(RDATA_VA + VFT_PLAYER) + 4:#x} ilk slot (40 slot, .?AVCPlayer@@)")
print(f"  ms_singleton    @ {va(MS_SINGLE):#x} (imajda 0!)")
print(f"  IAT slot0       @ {va(RDATA_VA + IAT_ARR):#x} (py.dll.Py_BuildValue)")
print(f"  v8 tier-3 vakasi: F_EMUCASE @ {va(F_EMUCASE):#x}, CEmu vft @ {va(RDATA_VA + VFT_EMU) + 4:#x}, hedef F_EMU_M2 @ {va(F_EMU_M2):#x}")
print(f"  v8 inversiyon vakasi: GetStatus @ {va(F_GETSTATUS):#x} icinde call [eax+0x88]")
