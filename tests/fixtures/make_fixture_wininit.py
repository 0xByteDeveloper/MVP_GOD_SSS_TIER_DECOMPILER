#!/usr/bin/env python3
"""
i4M GodTier v9.2 WinInit fixture üretici — fixture_wininit.exe (PE32 x86).

Amaç: Windows process-init benzetiminin (Tier-5a) KANITLANABİLİR testi.
İçindekiler (metin2client.exe init deseninin minyatürü):
  1. TLS callback (0x401080): g_vptr_slot'a vftable yazar — Windows'ta
     EP'den ÖNCE koşar; statik tarayıcılar callback'i FONKSİYON olarak
     keşfedemez (kodda çağrısı yok, yalnız TLS dizini verisinde referans
     var) → YALNIZ WinInit görebilir ("TLS-only kanıt zinciri")
  2. ctor_part (0x4010A0): HeapAlloc (IAT) + g_heapobj'e yazar + heap'e
     vtable yazar — statik değerlendiricide call sonrası eax boşalır →
     yalnız init-anlık görüntüsü çözer ("heap-only kanıt zinciri")
  3. EP (0x401000): ctor_part + victim1 + victim2 çağırır sonra
     USER32.GetMessageA (DUVAR API) — WinInit burada dürüstçe durur
  4. victim1 (0x401020): [g_vptr_slot]→[+8]→call ecx  (test çağrısı #1)
  5. victim2 (0x401030): [g_heapobj]→[+0]→call [ecx+4] (test çağrısı #2)
"""
import struct, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "fixture_wininit.exe"
IMAGE_BASE = 0x400000
SEC_ALIGN, FILE_ALIGN = 0x1000, 0x200
HDRS_SIZE = 0x200

# ---------------------------------------------------------------- .text ----
def rel32(target, next_insn):
    return struct.pack("<i", target - next_insn)

IAT_HEAPALLOC = 0x402100      # .rdata sonunda (aşağıda inşa edilir)
IAT_GETMESSAGE = 0x402108

text = bytearray()
def emit(addr, *chunks):
    """addr: beklenen VA (assert ile düzen doğrulanır)"""
    assert IMAGE_BASE + 0x1000 + len(text) == addr, hex(addr)
    for c in chunks:
        text.extend(c)

def pad_to(addr):
    while IMAGE_BASE + 0x1000 + len(text) < addr:
        text.append(0)

# EP @ 0x401000 — CRT-init benzeri akış: ctor → victim'ler → DUVAR
emit(0x401000,
     b"\xe8" + rel32(0x4010A0, 0x401005),      # call ctor_part
     b"\xe8" + rel32(0x401020, 0x40100A),      # call victim1
     b"\xe8" + rel32(0x401030, 0x40100F))      # call victim2
emit(0x40100F,
     b"\x6a\x00" * 4,                          # push 0 x4 (GetMessageA args)
     b"\xff\x15" + struct.pack("<I", IAT_GETMESSAGE),  # call [GetMessageA] — DUVAR
     b"\xc3")                                  # ret (asla ulaşılırsa)
pad_to(0x401020)
# victim1 @ 0x401020 — TLS-only zincir
emit(0x401020,
     b"\xa1" + struct.pack("<I", 0x403004),    # mov eax, [g_vptr_slot]
     b"\x8b\x48\x08",                          # mov ecx, [eax+8]   (vft slot 2)
     b"\xff\xd1",                              # call ecx           ← TEST #1 @ 0x401028
     b"\xc3")
pad_to(0x401030)
# victim2 @ 0x401030 — heap-only zincir
emit(0x401030,
     b"\xa1" + struct.pack("<I", 0x403008),    # mov eax, [g_heapobj]
     b"\x8b\x08",                              # mov ecx, [eax]     (heap vptr)
     b"\xff\x51\x04",                          # call [ecx+4]       ← TEST #2 @ 0x401037
     b"\xc3")
# hedefler
pad_to(0x401040)
emit(0x401040, b"\xb8\x11\x00\x00\x00", b"\xc3")   # func_target1
pad_to(0x401050)
emit(0x401050, b"\xb8\x22\x00\x00\x00", b"\xc3")   # func_target2
pad_to(0x401060)
emit(0x401060, b"\xc3")                            # funcA
pad_to(0x401070)
emit(0x401070, b"\xc3")                            # funcB
pad_to(0x401080)
# TLS callback @ 0x401080 (stdcall: DllHandle, Reason, Reserved → ret 12)
emit(0x401080,
     b"\xb8" + struct.pack("<I", 0x402000),    # mov eax, fake_vft1
     b"\xa3" + struct.pack("<I", 0x403004),    # mov [g_vptr_slot], eax
     b"\xc2\x0c\x00")                          # ret 12
pad_to(0x4010A0)
# ctor_part @ 0x4010A0 — heap kurulumu (statikte KANITLANAMAZ)
emit(0x4010A0,
     b"\x68\x40\x00\x00\x00",                  # push 0x40          (dwBytes)
     b"\x6a\x00",                              # push 0             (dwFlags)
     b"\x68\x00\x10\xab\x00",                  # push 0x00AB1000    (hHeap)
     b"\xff\x15" + struct.pack("<I", IAT_HEAPALLOC),  # call [HeapAlloc]
     b"\xa3" + struct.pack("<I", 0x403008),    # mov [g_heapobj], eax
     b"\xb9" + struct.pack("<I", 0x40200C),    # mov ecx, fake_vft2
     b"\x89\x08",                              # mov [eax], ecx     (heap vptr)
     b"\xc3")
text_raw = bytes(text) + b"\x00" * ((-len(text)) % FILE_ALIGN)

# ---------------------------------------------------------------- .rdata ---
FAKE_VFT1 = 0x402000      # [funcA, funcB, func_target1]  → slot 2 (+8) = hedef1
FAKE_VFT2 = 0x40200C      # [funcA, func_target2]         → slot 1 (+4) = hedef2
rdata = bytearray()
def remit(addr, *chunks):
    assert IMAGE_BASE + 0x2000 + len(rdata) == addr, hex(addr)
    for c in chunks:
        rdata.extend(c)

remit(FAKE_VFT1,
      struct.pack("<III", 0x401060, 0x401070, 0x401040))
remit(FAKE_VFT2,
      struct.pack("<II", 0x401060, 0x401050))
remit(0x402014,                                          # TLS callback dizisi
      struct.pack("<II", 0x401080, 0))
remit(0x40201C,                                          # IMAGE_TLS_DIRECTORY (PE32, 24B)
      struct.pack("<IIIIII", 0, 0, 0x40300C, 0x402014, 0, 0))
# import yapıları
DLL_K32 = 0x402034
DLL_U32 = 0x402041
HN_HEAP = 0x40204C        # hint/name: \0\0HeapAlloc\0 (12B)
HN_MSG  = 0x402058        # \0\0GetMessageA\0 (14B)
INT_K32 = 0x402068        # [rva(HN_HEAP), 0]
INT_U32 = 0x402070        # [rva(HN_MSG), 0]
DESC    = 0x402078        # 3 x 20 bayt descriptor + null
rdata += b"KERNEL32.dll\x00"
rdata += b"USER32.dll\x00"
rdata += b"\x00\x00HeapAlloc\x00"
rdata += b"\x00\x00GetMessageA\x00"
assert IMAGE_BASE + 0x2000 + len(rdata) == 0x402066, hex(IMAGE_BASE + 0x2000 + len(rdata))
while IMAGE_BASE + 0x2000 + len(rdata) < INT_K32: rdata.append(0)
rdata += struct.pack("<II", HN_HEAP - IMAGE_BASE, 0)      # INT_KERNEL32
rdata += struct.pack("<II", HN_MSG - IMAGE_BASE, 0)       # INT_USER32
desc = struct.pack("<IIIII", INT_K32 - IMAGE_BASE, 0, 0, DLL_K32 - IMAGE_BASE, IAT_HEAPALLOC - IMAGE_BASE)
desc += struct.pack("<IIIII", INT_U32 - IMAGE_BASE, 0, 0, DLL_U32 - IMAGE_BASE, IAT_GETMESSAGE - IMAGE_BASE)
desc += struct.pack("<IIIII", 0, 0, 0, 0, 0)
assert IMAGE_BASE + 0x2000 + len(rdata) == DESC, hex(IMAGE_BASE + 0x2000 + len(rdata))
rdata += desc
while IMAGE_BASE + 0x2000 + len(rdata) < IAT_HEAPALLOC: rdata.append(0)
rdata += struct.pack("<II", HN_HEAP - IMAGE_BASE, 0)      # IAT_KERNEL32 @ 0x402100
rdata += struct.pack("<II", HN_MSG - IMAGE_BASE, 0)       # IAT_USER32    @ 0x402108
rdata_raw = bytes(rdata) + b"\x00" * ((-len(rdata)) % FILE_ALIGN)

# ---------------------------------------------------------------- .data ----
data_raw = b"\x00" * 0x10   # g_ctor_done, g_vptr_slot, g_heapobj, g_tls_index
data_raw += b"\x00" * ((-len(data_raw)) % FILE_ALIGN)

# ----------------------------------------------------------- dosya düzeni --
text_file  = FILE_ALIGN                      # 0x200
rdata_file = text_file + len(text_raw)
data_file  = rdata_file + len(rdata_raw)
IMAGE_SIZE = 0x4000 + SEC_ALIGN

buf = bytearray(HDRS_SIZE)
def put(o, d): buf[o:o+len(d)] = d
NT_OFF = 0x40
put(0, b"MZ")
put(0x3C, struct.pack("<I", NT_OFF))
put(NT_OFF, b"PE\x00\x00")
put(NT_OFF + 4, struct.pack("<HHIIIHH", 0x14C, 3, 0, 0, 0, 224, 0x0102))
OPT = NT_OFF + 24
def opt(o, fmt, *v): put(OPT + o, struct.pack("<" + fmt, *v))
opt(0,  "H", 0x10B)             # magic PE32
opt(2,  "B", 14); opt(3, "B", 0)
opt(4,  "I", len(text_raw))     # SizeOfCode
opt(8,  "I", len(rdata_raw)); opt(12, "I", len(data_raw))
opt(16, "I", 0x1000)            # AddressOfEntryPoint
opt(20, "I", 0x1000)            # BaseOfCode
opt(24, "I", 0x2000)            # BaseOfData
opt(28, "I", IMAGE_BASE)        # ImageBase (u32)
opt(32, "I", SEC_ALIGN); opt(36, "I", FILE_ALIGN)
opt(40, "H", 6); opt(42, "H", 0)
opt(44, "H", 0); opt(46, "H", 0)
opt(48, "H", 6); opt(50, "H", 0)
opt(52, "I", 0)
opt(56, "I", IMAGE_SIZE)
opt(60, "I", HDRS_SIZE)
opt(64, "I", 0)
opt(68, "H", 3)                 # subsystem: console
opt(70, "H", 0)                 # DllCharacteristics
opt(72, "I", 0x100000); opt(76, "I", 0x1000)
opt(80, "I", 0x100000); opt(84, "I", 0x1000)
opt(88, "I", 0)
opt(92, "I", 16)
DD = 96
def dirp(i, rva, size): opt(DD + i * 8, "II", rva, size)
dirp(1, DESC - IMAGE_BASE, 60)          # import
dirp(9, 0x201C, 24)                     # TLS dizini

SH = NT_OFF + 4 + 20 + 224
def shdr(i, name, vsize, va, rawsz, rawoff, chars):
    o = SH + i * 40
    buf[o:o+8] = name.ljust(8, b"\x00")
    put(o + 8, struct.pack("<IIII", vsize, va, rawsz, rawoff))
    put(o + 36, struct.pack("<I", chars))
shdr(0, b".text",  len(text_raw),  0x1000, len(text_raw),  text_file,  0x60000020)
shdr(1, b".rdata", len(rdata_raw), 0x2000, len(rdata_raw), rdata_file, 0x40000040)
shdr(2, b".data",  len(data_raw),  0x3000, len(data_raw),  data_file,  0xC0000040)
assert SH + 3 * 40 <= HDRS_SIZE

with open(OUT, "wb") as f:
    f.write(buf)
    f.write(text_raw)
    f.write(rdata_raw)
    f.write(b"\x00" * (data_file - (rdata_file + len(rdata_raw))))
    f.write(data_raw)

print(f"OK: {OUT} ({data_file + len(data_raw)} bayt)")
print(f"  EP=0x401000  victim1 call=0x401028  victim2 call=0x401037")
print(f"  tls_cb=0x401080  fake_vft1=0x402000  fake_vft2=0x40200C")
print(f"  IAT: HeapAlloc=0x{IAT_HEAPALLOC:x} GetMessageA=0x{IAT_GETMESSAGE:x}")
