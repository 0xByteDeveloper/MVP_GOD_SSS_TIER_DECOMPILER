#!/usr/bin/env python3
"""
i4M GodTier test fixture PDB üretici — MSF 7.00 spec'ına uygun el yapımı PDB.
İçerik:
 - stream 1: PDB info (GUID + age)
 - stream 2: TPI — OgrenciPdb struct'ı (numara/notlar[8]/ortalama/isim[24])
             + int(int,int) prosedür tipi + arglist
 - stream 3: modül sembolleri — S_GPROC32 "toplama_pdb" (seg1 off 0x1000) +
             S_BPREL32 param adları (dizi@8, adet@12) + "dongu_pdb" (off 0x100E)
 - stream 4: globals — PUB32 x2 + DATA32 gSayiPdb (seg3)
Karşılık gelen PE: fixture.exe (ImageBase 0x140000000, .text RVA 0x1000)
"""
import struct, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "fixture.pdb"
BLOCK = 512

# ---------------- yardımcılar ----------------
def u16(v): return struct.pack("<H", v & 0xFFFF)
def u32(v): return struct.pack("<I", v & 0xFFFFFFFF)

def rec(leaf, body):
    """TPI kaydı: len(2, gövde+2 dahil) + leaf(2) + body; çift bayt hizala."""
    raw = u16(leaf) + body
    ln = len(raw)
    if ln & 1:
        raw += b"\x00"
        ln += 1
    return u16(ln) + raw

def numleaf(v):
    """Küçük pozitif değerler için kısa numleaf (u16 < 0x8000)."""
    assert 0 <= v < 0x8000
    return u16(v)

def cstr(s):
    return s.encode() + b"\x00"

# ---------------- TPI ----------------
T_T_INT   = 0x0074   # int32
T_T_FLOAT = 0x0040   # float32
T_T_CHAR  = 0x0010   # char8

# tip indeksleri (tiBegin = 0x1000'den)
IDX_FIELDLIST = 0x1000
IDX_ARR_INT8  = 0x1001   # int[8]
IDX_ARR_CH24  = 0x1002   # char[24]
IDX_STRUCT    = 0x1003   # OgrenciPdb
IDX_ARGLIST   = 0x1004
IDX_PROC      = 0x1005

# LF_FIELDLIST (0x1203): LF_MEMBER kayıtları
# LF_MEMBER (0x150D): attr(2) + tidx(4) + off(numleaf) + name + pad
def member(tidx, off, name):
    # fieldlist İÇİ leaf: uzunluk öneki YOK; hizalama pad'i 0xF0+n (CodeView)
    body = u16(0x150D) + u16(0) + u32(tidx) + numleaf(off) + cstr(name)
    if len(body) & 1:
        body += b"\xF1"           # 1 bayt atla pad'i
    return body

fld = b""
fld += member(T_T_INT, 0, "numara")
fld += member(IDX_ARR_INT8, 4, "notlar")
fld += member(T_T_FLOAT, 24, "ortalama")
fld += member(IDX_ARR_CH24, 28, "isim")
rec_fieldlist = rec(0x1203, fld)

# LF_ARRAY (0x1503): elemtype(4) + indextype(4) + size(numleaf)
rec_arr_i8 = rec(0x1503, u32(T_T_INT) + u32(T_T_INT) + numleaf(32))
rec_arr_c24 = rec(0x1503, u32(T_T_CHAR) + u32(T_T_INT) + numleaf(24))

# LF_STRUCTURE (0x1504): count(2) pad(2) fieldlist(4) prop(2) derived(2)
#   vshape(2) pad(2) pad(2) size(numleaf@16) name(@18) — PDBX okuma düzeni
# PDBX okuma düzeni: fieldlist@4, size@16, name@18
# count@0 pad@2 field@4 prop@8 derived@10 vshape@12 pad@14 size@16 name@18
st_body = (u16(4) + b"\x00\x00" + u32(IDX_FIELDLIST) + u16(0) + u16(0) +
           u16(0) + b"\x00\x00" + numleaf(52) + cstr("OgrenciPdb"))
rec_struct = rec(0x1504, st_body)

# LF_ARGLIST (0x1201): count(4) + tidx(4)*n
rec_arglist = rec(0x1201, u32(2) + u32(T_T_INT) + u32(T_T_INT))

# LF_PROCEDURE (0x1008): rv(4) + callconv(2) + nparams(2) + arglist(4)
rec_proc = rec(0x1008, u32(T_T_INT) + u16(0) + u16(2) + u32(IDX_ARGLIST))

# TPI gövdesi: header (ver=5, hdrSize=56, tiBegin, tiEnd, 0...) + kayıtlar
tpi_records = (rec_fieldlist + rec_arr_i8 + rec_arr_c24 + rec_struct +
               rec_arglist + rec_proc)
TPI_BEGIN = 0x1000
tpi_end = TPI_BEGIN + 6
tpi_header_size = 56
tpi_hdr = u32(5) + u32(tpi_header_size) + u32(TPI_BEGIN) + u32(tpi_end) + u32(0xFFFFFFFF)
tpi_hdr += b"\x00" * (tpi_header_size - len(tpi_hdr))
tpi = tpi_hdr + tpi_records

# ---------------- PDB info stream ----------------
info = u32(30000)            # sürüm/imza zamanı (PDBX: sigTime @+4)
info = u32(0x5EEDBEEF) + u32(0x5EEDBEEF) + u32(1)   # ver? sigTime, age=1
info = u32(30000) + u32(12345) + u32(1) + bytes.fromhex(
    "11223344556677889900AABBCCDDEEFF")
# PDBX: sigTime = rd32(+4), age = rd32(+8), guid = +12

# ---------------- modül sembol akışı ----------------
def symrec(kind, body):
    raw = u16(kind) + body
    ln = len(raw)
    if ln & 1:
        raw += b"\x00"
        ln += 1          # pad baytı reclen'e dahil
    return u16(ln) + raw

# S_GPROC32 (0x1110): pParent(4) pEnd(4) pNext(4) len(4) DbgStart(4) DbgEnd(4)
#                     typind(4) offStart(4) segStart(2) cflags(1) name
def gproc(name, off, size, tidx, children=b""):
    name_b = cstr(name)
    body_head = struct.pack("<IIIIII", 0, 0, 0, size, 0, 0) + u32(tidx) + u32(off) + u16(1) + b"\x00"
    body = body_head + name_b
    ln = len(body)
    if ln & 1:
        body += b"\x00"
    hdr = u16(4 + ln) + u16(0x1110) + body   # pEnd alanını aşağıda dolduracağız
    # pEnd = kayıt sonrası (çocuklar dahil) — basitlik: başta 0 bırak;
    # PDBX okur pEnd=0'ı "0 > n" filtresiyle atlar, çocuklar yine taranır
    return hdr + children + symrec(0x0006, b"")   # S_END

# S_BPREL32 (0x110B): off(4) + tidx(4) + name
def bprel(off, tidx, name):
    return symrec(0x110B, struct.pack("<i", off) + u32(tidx) + cstr(name))

def build_gproc(name, off, size, tidx, children):
    """S_GPROC32: pEnd alanı pozisyon-bazlı patch gerektirir."""
    children_full = children + symrec(0x0006, b"")   # + S_END
    body = (struct.pack("<IIIIII", 0, 0, 0, size, 0, 0) +
            u32(tidx) + u32(off) + u16(1) + b"\x00" + cstr(name))
    if len(body) & 1:
        body += b"\x00"
    ln = len(body) + 2          # reclen: kind(2) dahil, len(2) hariç
    rec = u16(ln) + u16(0x1110) + body
    return rec, children_full, 2 + ln

def mod_stream():
    entries = [
        ("toplama_pdb", 0, 14, IDX_PROC, bprel(8, 0x0075, "dizi") + bprel(12, 0x0074, "adet")),
        ("dongu_pdb", 0xE, 14, 0x0003, bprel(8, 0x0074, "sayac")),
    ]
    built = [build_gproc(*e) for e in entries]
    buf = bytearray()
    marks = []
    for rec, kids_full, rec_total in built:
        marks.append((len(buf), rec_total, len(kids_full)))
        buf += rec
        buf += kids_full
    # pEnd = kayıt başı + kayıt boyu + çocuklar(+S_END) — mutlak akış offseti
    for (start, rec_total, kids_len) in marks:
        buf[start + 8:start + 12] = struct.pack("<I", start + rec_total + kids_len)
    if len(buf) < 200:
        buf += b"\x00" * (200 - len(buf))
    return bytes(buf)

mod = mod_stream()

# ---------------- globals akışı (PUB32 + DATA32) ----------------
def pub32(name, seg, off):
    body = u32(3) + u32(off) + u16(seg) + cstr(name)   # pubflags=3 (function|public)
    return symrec(0x110E, body)

def data32(name, seg, off, tidx):
    body = u32(tidx) + u32(off) + u16(seg) + cstr(name)
    return symrec(0x110D, body)

globs = b""
globs += pub32("toplama_pdb", 1, 0)
globs += pub32("dongu_pdb", 1, 0xE)
globs += data32("gSayiPdb", 3, 0, 0x0074)
globs = globs.ljust(4096 + 200, b"\x00")   # globals taraması >= 4096 ister

# ---------------- MSF kurulumu ----------------
streams = [b"", info, tpi, mod, globs]
n_streams = len(streams)

def blocks_needed(sz):
    return (sz + BLOCK - 1) // BLOCK if sz > 0 else 0

# yerleşim: blok 0 = superblock, blok 1 = dir block map
#           blok 2+ = stream verileri
assign = {}
cur_block = 2
for i, st in enumerate(streams):
    nb = blocks_needed(len(st))
    assign[i] = list(range(cur_block, cur_block + nb))
    cur_block += nb

# directory içerik: nStreams + sizes + block listeleri
dirbuf = u32(n_streams)
for i, st in enumerate(streams):
    dirbuf += u32(len(st) if len(st) > 0 else 0)
for i, st in enumerate(streams):
    if len(st) == 0:
        continue
    for b in assign[i]:
        dirbuf += u32(b)
dir_bytes = len(dirbuf)
dir_blocks = list(range(cur_block, cur_block + blocks_needed(dir_bytes)))
cur_block += blocks_needed(dir_bytes)
n_blocks = cur_block

# dosya: blokları yaz
data_blocks = {}
for i, st in enumerate(streams):
    if not st:
        continue
    for k, b in enumerate(assign[i]):
        chunk = st[k * BLOCK:(k + 1) * BLOCK].ljust(BLOCK, b"\x00")
        data_blocks[b] = chunk
for k, b in enumerate(dir_blocks):
    chunk = dirbuf[k * BLOCK:(k + 1) * BLOCK].ljust(BLOCK, b"\x00")
    data_blocks[b] = chunk

# superblock
sig = b"Microsoft C/C++ MSF 7.00\r\n\x1a+\x00"
sb = sig + b"\x00" * (0x20 - len(sig))
sb += u32(BLOCK)        # 0x20 blocksize
sb += u32(2)            # 0x24 freeblockmap (önemli değil)
sb += u32(n_blocks)     # 0x28 numblocks
sb += u32(dir_bytes)    # 0x2C dirsize
sb += u32(0)            # 0x30 unknown
sb += u32(1)            # 0x34 blockmap addr (blok 1)
sb += b"\x00" * (BLOCK - len(sb))

# blok 1: directory'nin blok adresleri
blockmap = b"".join(u32(b) for b in dir_blocks).ljust(BLOCK, b"\x00")

out = bytearray(b"\x00" * (n_blocks * BLOCK))
out[0:BLOCK] = sb
out[BLOCK:2 * BLOCK] = blockmap
for b, chunk in data_blocks.items():
    out[b * BLOCK:(b + 1) * BLOCK] = chunk

open(OUT, "wb").write(bytes(out))
print(f"PDB yazildi: {OUT} ({len(out)} bayt, {n_blocks} blok)")
print(f"  streamler: info={len(info)} tpi={len(tpi)} mod={len(mod)} globals={len(globs)}")
print(f"  struct: OgrenciPdb (4 uye), proc: int(int,int), func: toplama_pdb@0x140001000")
