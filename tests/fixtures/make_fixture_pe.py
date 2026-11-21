#!/usr/bin/env python3
"""
i4M GodTier test fixture PE üretici (v2 — belgelenmiş offset'lerle inşa).
Elle PE32+ x64 exe üretir:
 - .text  (0x1000): entry (mov eax,0x37; add eax,5; ret) + loop fonksiyonu
 - .rdata (0x2000): stringler + AES S-box + import yapısı + CodeView(PDB)
 - .data  (0x3000): DIR64 reloc hedefi işaretçi
 - .reloc (0x4000): DIR64 relocation bloğu
 - importlar: KERNEL32.dll (5 API) + USER32.dll (MessageBoxA)
"""
import struct, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "fixture.exe"
IMAGE_BASE = 0x140000000
SEC_ALIGN, FILE_ALIGN = 0x1000, 0x200
HDRS_SIZE = 0x200

# ---------------- kod ----------------
# entry: once loop'u cagir (call rel32), sonra eax=0x37+5
def call_rel32(target, next_insn):
    import struct as _s
    return b"\xe8" + _s.pack("<i", target - next_insn)
code_entry = bytes([
    0xB8, 0x00, 0x00, 0x00, 0x00,   # mov eax, 0 (yer tutucu; call asagida hesaplanir)
])
# kod: call loop; mov eax,0x37; add eax,5; ret  -> 5+5+3+1 = 14 bayt
entry_code = call_rel32(14, 5) + bytes([
    0xB8, 0x37, 0x00, 0x00, 0x00,   # mov eax, 0x37
    0x83, 0xC0, 0x05,               # add eax, 5
    0xC3])                          # ret
code_entry = entry_code
code_loop = bytes([
    0x31, 0xC9,                     # xor ecx,ecx
    0xB8, 0x00, 0x00, 0x00, 0x00,   # mov eax,0
    0xB9, 0x0A, 0x00, 0x00, 0x00,   # mov ecx,10
    0x01, 0xC8,                     # add eax,ecx   <- L
    0xFF, 0xC9,                     # dec ecx
    0x75, 0xFA,                     # jnz L
    0xC3])                          # ret
text_raw = code_entry + code_loop
text_raw += b"\x00" * ((-len(text_raw)) % FILE_ALIGN)

# ---------------- .rdata ----------------
strs = b"GodTier Fixture\x00Hello from i4M\x00"
AES_SBOX = bytes([
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75])

k32_names = [b"ExitProcess", b"GetModuleHandleA", b"CreateFileA", b"HeapAlloc", b"IsDebuggerPresent"]
u32_names = [b"MessageBoxA"]

RDATA_VA = 0x2000
# rdata düzeni: [strings][sbox][DLL adları][hint/name][INT1][INT2][descriptors][cv][debugdir]
blob_parts = []
off = 0
def take(data):
    global off
    blob_parts.append(data)
    o = off
    off += len(data)
    return (o, len(blob_parts) - 1)  # (byte offset, chunk index)
dll1 = take(b"KERNEL32.dll\x00")
dll2 = take(b"USER32.dll\x00")
hn = []
for nm in k32_names + u32_names:
    hn.append(take(struct.pack("<H", 0) + nm + b"\x00"))
if off % 8:
    take(b"\x00" * (8 - off % 8))
# INT'ler: yer tutucular KESIN aynı boyutta olmalı (poke sonrasi kayma olmasin)
INT_PLACE = []
INT_PLACE.append(take(b"\x00" * (8 * 6)))   # INT1: 5 isim + NULL = 48
INT_PLACE.append(take(b"\x00" * (8 * 2)))   # INT2: 1 isim + NULL = 16
imp_rva_base = lambda o: RDATA_VA + len(strs) + len(AES_SBOX) + o
def thunks(idxs):
    t = b""
    for i in idxs:
        t += struct.pack("<Q", imp_rva_base(hn[i][0]))
    t += struct.pack("<Q", 0)
    return t
# INT'leri geri yaz
def poke(ref, data):
    blob_parts[ref[1]] = data
poke(INT_PLACE[0], thunks(range(5)))
poke(INT_PLACE[1], thunks(range(5, 6)))

desc_off = off
descs = b""
descs += struct.pack("<IIIII", imp_rva_base(INT_PLACE[0][0]), 0, 0, imp_rva_base(dll1[0]), imp_rva_base(INT_PLACE[0][0]))
descs += struct.pack("<IIIII", imp_rva_base(INT_PLACE[1][0]), 0, 0, imp_rva_base(dll2[0]), imp_rva_base(INT_PLACE[1][0]))
descs += struct.pack("<IIIII", 0, 0, 0, 0, 0)
take(descs)

# CodeView (PDB)
guid = bytes(range(16))
pdb_path = b"D:\\projeler\\godtier\\fixture.pdb"
cv = b"RSDS" + guid + struct.pack("<I", 1) + pdb_path + b"\x00"
cv_off = take(cv)
# Debug dizin girdisi (28 bayt): ptr = raw offset (aşağıda doldurulacak — placeholder)
dd_off = take(b"\x00" * 28)
rdata_body = strs + AES_SBOX + b"".join(blob_parts)
# debug dizin girdisini doldur
dd_abs = len(strs) + len(AES_SBOX) + dd_off[0]
cv_abs = len(strs) + len(AES_SBOX) + cv_off[0]
rdata_file_off = FILE_ALIGN + len(text_raw)   # .text'ten sonra
dd = struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(cv), RDATA_VA + len(strs) + len(AES_SBOX) + cv_off[0], rdata_file_off + cv_abs)
rdata_body = rdata_body[:dd_abs] + dd + rdata_body[dd_abs + 28:]
rdata_raw = rdata_body + b"\x00" * ((-len(rdata_body)) % FILE_ALIGN)

# ---------------- .data / .reloc ----------------
DATA_VA, RELOC_VA = 0x3000, 0x4000
data_raw = struct.pack("<Q", IMAGE_BASE + DATA_VA)   # reloc hedefi
data_raw += b"\x00" * ((-len(data_raw)) % FILE_ALIGN)
reloc = struct.pack("<II", DATA_VA, 8 + 2) + struct.pack("<H", (10 << 12) | 0)
reloc_raw = reloc + b"\x00" * ((-len(reloc)) % FILE_ALIGN)

# ---------------- dosya yerleşimi ----------------
text_file  = FILE_ALIGN                      # 0x200
rdata_file = text_file + len(text_raw)
data_file  = rdata_file + len(rdata_raw)
reloc_file = data_file + len(data_raw)
IMAGE_SIZE = RELOC_VA + SEC_ALIGN

# ---------------- header inşası ----------------
buf = bytearray(HDRS_SIZE)
def put(o, data): buf[o:o+len(data)] = data

# DOS
buf[0:2] = b"MZ"
put(0x3C, struct.pack("<I", HDRS_SIZE))  # e_lfanew: header'lar dosya sonunda? hayır!
# NOT: e_lfanew = 0x40 yapalım; NT header'ları DOS'tan hemen sonra koyarız
NT_OFF = 0x40
put(0x3C, struct.pack("<I", NT_OFF))

# NT: sig + file header + optional (240)
put(NT_OFF, b"PE\x00\x00")
fh = struct.pack("<HHIIIHH", 0x8664, 4, 0, 0, 0, 240, 0x0022)
put(NT_OFF + 4, fh)
OPT = NT_OFF + 24
def opt(o, fmt, *v): put(OPT + o, struct.pack("<" + fmt, *v))
opt(0,  "H", 0x20b)            # magic PE32+
opt(2,  "B", 14); opt(3, "B", 0)
opt(4,  "I", len(text_raw))    # SizeOfCode
opt(8,  "I", len(rdata_raw)); opt(12, "I", len(data_raw))
opt(16, "I", 0x1000)           # AddressOfEntryPoint
opt(20, "I", 0x1000)           # BaseOfCode
opt(24, "Q", IMAGE_BASE)
opt(32, "I", SEC_ALIGN); opt(36, "I", FILE_ALIGN)
opt(40, "H", 6); opt(42, "H", 0)     # OS ver
opt(44, "H", 0); opt(46, "H", 0)     # image ver
opt(48, "H", 6); opt(50, "H", 0)     # subsys ver
opt(52, "I", 0)
opt(56, "I", IMAGE_SIZE)
opt(60, "I", HDRS_SIZE)
opt(64, "I", 0)                # checksum
opt(68, "H", 3)                # subsystem: console
opt(70, "H", 0x8160)           # DllCharacteristics: HIGHENTROPYVA|DYNAMIC_BASE|NX|TERMINAL_SERVER_AWARE
opt(72, "Q", 0x100000); opt(80, "Q", 0x1000)
opt(88, "Q", 0x100000); opt(96, "Q", 0x1000)
opt(104, "I", 0)
opt(108, "I", 16)
# data dizinleri (her biri 8 bayt, 112'den başlar)
DD = 112
def dirp(i, rva, size): opt(DD + i * 8, "II", rva, size)
dirp(1, RDATA_VA + len(strs) + len(AES_SBOX) + desc_off, len(descs))   # import
dirp(5, RELOC_VA, len(reloc))                                          # basereloc
dirp(6, RDATA_VA + len(strs) + len(AES_SBOX) + dd_off[0], 28)                                         # debug

# section header'ları (NT_OFF + 4 + 20 + 240)
SH = NT_OFF + 4 + 20 + 240
def shdr(i, name, vsize, va, rawsz, rawoff, chars):
    o = SH + i * 40
    buf[o:o+8] = name.ljust(8, b"\x00")
    put(o + 8, struct.pack("<IIII", vsize, va, rawsz, rawoff))
    put(o + 36, struct.pack("<I", chars))
shdr(0, b".text",  len(text_raw),  0x1000, len(text_raw),  text_file,  0x60000020)
shdr(1, b".rdata", len(rdata_raw), 0x2000, len(rdata_raw), rdata_file, 0x40000040)
shdr(2, b".data",  len(data_raw),  0x3000, len(data_raw),  data_file,  0xC0000040)
shdr(3, b".reloc", len(reloc_raw), 0x4000, len(reloc_raw), reloc_file, 0x42000040)

assert SH + 4 * 40 <= HDRS_SIZE, f"header tasmadi: {SH + 160} > {HDRS_SIZE}"

with open(OUT, "wb") as f:
    f.write(buf)
    f.write(text_raw)
    f.write(rdata_raw);  f.write(b"\x00" * (data_file - (text_file + len(text_raw) + len(rdata_raw))))
    f.write(data_raw)
    f.write(b"\x00" * (reloc_file - (data_file + len(data_raw))))
    f.write(reloc_raw)

print(f"OK: {OUT} ({reloc_file + len(reloc_raw)} bayt)")
print(f"  entry rva=0x1000, loop rva=0x{0x1000 + len(code_entry):x}, sbox rva=0x{0x2000 + len(strs):x}")
