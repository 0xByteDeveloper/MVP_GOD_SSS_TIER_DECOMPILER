#!/usr/bin/env python3
"""
i4M GodTier API fixture PE üretici.
Entry, shadow IAT üzerinden API çağırır (emülatör + apishim testi):
  - user32.MessageBoxA(NULL, text, caption, MB_OK)   -> shim: log + IDOK
  - kernel32.IsDebuggerPresent()                     -> shim: false (anti-debug temiz)
  - kernel32.ExitProcess(0x2A)                       -> shim: emülasyonu bitirir
"""
import struct, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "fixture_api.exe"
IMAGE_BASE = 0x140000000
SEC_ALIGN, FILE_ALIGN = 0x1000, 0x200
HDRS_SIZE = 0x200
RDATA_VA = 0x2000

k32_names = [b"ExitProcess", b"IsDebuggerPresent"]
u32_names = [b"MessageBoxA"]

strs = b"GodTier API emulasyon testi\x00i4M GodTier Engine\x00"

blob_parts = []
off = 0
def take(data):
    global off
    blob_parts.append(data)
    o = off
    off += len(data)
    return (o, len(blob_parts) - 1)

dll1 = take(b"KERNEL32.dll\x00")
dll2 = take(b"USER32.dll\x00")
hn = []
for nm in k32_names + u32_names:
    hn.append(take(struct.pack("<H", 0) + nm + b"\x00"))
if off % 8:
    take(b"\x00" * (8 - off % 8))
INT1 = take(b"\x00" * (8 * 3))   # 2 isim + NULL
INT2 = take(b"\x00" * (8 * 2))   # 1 isim + NULL

imp_rva_base = lambda o: RDATA_VA + len(strs) + o
def thunks(idxs):
    t = b""
    for i in idxs:
        t += struct.pack("<Q", imp_rva_base(hn[i][0]))
    t += struct.pack("<Q", 0)
    return t
blob_parts[INT1[1]] = thunks(range(2))
blob_parts[INT2[1]] = thunks(range(2, 3))

desc_off = off
descs  = struct.pack("<IIIII", imp_rva_base(INT1[0]), 0, 0, imp_rva_base(dll1[0]), imp_rva_base(INT1[0]))
descs += struct.pack("<IIIII", imp_rva_base(INT2[0]), 0, 0, imp_rva_base(dll2[0]), imp_rva_base(INT2[0]))
descs += struct.pack("<IIIII", 0, 0, 0, 0, 0)
take(descs)
# hizalama
if off % 8:
    take(b"\x00" * (8 - off % 8))
text_off = take(b"\x00" * 8)      # kodun rdata ici kopyasi DEGIL — placeholder, asagida poke
msg_off = take(b"\x00" * 0)       # mesajlar zaten strs icinde

# rdata: strings + blob
rdata_body = strs + b"".join(blob_parts)
rdata_raw = rdata_body + b"\x00" * ((-len(rdata_body)) % FILE_ALIGN)

# IAT slot VA'lari (MessageBoxA: INT2 ilk girisi)
mb_iat_va = IMAGE_BASE + RDATA_VA + len(strs) + INT2[0]
idb_iat_va = IMAGE_BASE + RDATA_VA + len(strs) + INT1[0] + 8   # IsDebuggerPresent 2. slot
exit_iat_va = IMAGE_BASE + RDATA_VA + len(strs) + INT1[0]      # ExitProcess 1. slot
msg_va = IMAGE_BASE + RDATA_VA + 0          # "GodTier API emulasyon testi"
cap_va = IMAGE_BASE + RDATA_VA + 29         # "i4M GodTier Engine"

# ---- entry kodu ----
code = b""
code += b"\x31\xc9"                                   # xor ecx,ecx (hWnd)
# lea rdx, [rip+disp32] -> msg
def lea_rip(reg, target, cur):
    # 48 8D 15 disp32 (rdx) / 4C 8D 05 (r8)
    if reg == "rdx": op = b"\x48\x8d\x15"
    elif reg == "r8": op = b"\x4c\x8d\x05"
    else: raise ValueError
    next_insn = cur + len(op) + 4
    return op + struct.pack("<i", target - next_insn)
cur = IMAGE_BASE + 0x1000 + len(code)
code += lea_rip("rdx", msg_va, cur); cur = IMAGE_BASE + 0x1000 + len(code)
code += lea_rip("r8", cap_va, cur); cur = IMAGE_BASE + 0x1000 + len(code)
code += b"\x45\x31\xc0"                               # xor r8d,r8d ... aslinda r9 lazim:
# duzeltme: r9d (MB_OK)
code = code[:-3] + b"\x45\x31\xc9"                    # xor r9d,r9d
cur = IMAGE_BASE + 0x1000 + len(code)
# call qword [rip+disp32] -> MessageBoxA IAT
def call_rip_mem(target_va, cur):
    op = b"\xff\x15"
    next_insn = cur + len(op) + 4
    return op + struct.pack("<i", target_va - next_insn)
code += call_rip_mem(mb_iat_va, cur); cur = IMAGE_BASE + 0x1000 + len(code)
# call [rip] -> IsDebuggerPresent
code += call_rip_mem(idb_iat_va, cur); cur = IMAGE_BASE + 0x1000 + len(code)
# mov ecx, 0x2A ; call [rip] -> ExitProcess(0x2A)
code += b"\xb9" + struct.pack("<I", 0x2A); cur = IMAGE_BASE + 0x1000 + len(code)
code += call_rip_mem(exit_iat_va, cur)

text_raw = code + b"\x00" * ((-len(code)) % FILE_ALIGN)
data_raw = b"\x00" * FILE_ALIGN
reloc_raw = b"\x00" * FILE_ALIGN

text_file  = FILE_ALIGN
rdata_file = text_file + len(text_raw)
data_file  = rdata_file + len(rdata_raw)
reloc_file = data_file + len(data_raw)
IMAGE_SIZE = 0x4000

buf = bytearray(HDRS_SIZE)
def put(o, data): buf[o:o+len(data)] = data
NT_OFF = 0x40
buf[0:2] = b"MZ"
put(0x3C, struct.pack("<I", NT_OFF))
put(NT_OFF, b"PE\x00\x00")
put(NT_OFF + 4, struct.pack("<HHIIIHH", 0x8664, 4, 0, 0, 0, 240, 0x0022))
OPT = NT_OFF + 24
def opt(o, fmt, *v): put(OPT + o, struct.pack("<" + fmt, *v))
opt(0, "H", 0x20b); opt(2, "B", 14); opt(3, "B", 0)
opt(4, "I", len(text_raw)); opt(8, "I", len(rdata_raw)); opt(12, "I", len(data_raw))
opt(16, "I", 0x1000); opt(20, "I", 0x1000)
opt(24, "Q", IMAGE_BASE)
opt(32, "I", SEC_ALIGN); opt(36, "I", FILE_ALIGN)
opt(40, "H", 6); opt(42, "H", 0); opt(44, "H", 0); opt(46, "H", 0)
opt(48, "H", 6); opt(50, "H", 0); opt(52, "I", 0)
opt(56, "I", IMAGE_SIZE); opt(60, "I", HDRS_SIZE); opt(64, "I", 0)
opt(68, "H", 3); opt(70, "H", 0x8160)
opt(72, "Q", 0x100000); opt(80, "Q", 0x1000); opt(88, "Q", 0x100000); opt(96, "Q", 0x1000)
opt(104, "I", 0); opt(108, "I", 16)
opt(120, "II", RDATA_VA + len(strs) + desc_off, len(descs))  # import dir (dir[1])

SH = NT_OFF + 4 + 20 + 240
def shdr(i, name, vsize, va, rawsz, rawoff, chars):
    o = SH + i * 40
    buf[o:o+8] = name.ljust(8, b"\x00")
    put(o + 8, struct.pack("<IIII", vsize, va, rawsz, rawoff))
    put(o + 36, struct.pack("<I", chars))
shdr(0, b".text",  len(text_raw),  0x1000, len(text_raw),  text_file,  0x60000020)
shdr(1, b".rdata", len(rdata_raw), 0x2000, len(rdata_raw), rdata_file, 0x40000040)
shdr(2, b".data",  0x200,          0x3000, len(data_raw),  data_file,  0xC0000040)
shdr(3, b".reloc", 0x200,          0x4000, len(reloc_raw), reloc_file, 0x42000040)
assert SH + 160 <= HDRS_SIZE

with open(OUT, "wb") as f:
    f.write(buf)
    f.write(text_raw)
    f.write(rdata_raw)
    f.write(b"\x00" * (data_file - (text_file + len(text_raw) + len(rdata_raw))))
    f.write(data_raw)
    f.write(b"\x00" * (reloc_file - (data_file + len(data_raw))))
    f.write(reloc_raw)

print(f"OK: {OUT}")
print(f"  MessageBoxA IAT slot: 0x{mb_iat_va:x}")
print(f"  IsDebuggerPresent IAT: 0x{idb_iat_va:x}")
print(f"  ExitProcess IAT: 0x{exit_iat_va:x}")
