#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
i4M-GodTier v6 ARM fixture üreticisi (kaynak kod + üretici birlikte saklanır).

ARM64 (kurban_arm64.elf) ve ARM32 (kurban_arm32.elf) ELF'lerini BİLİNEN
komut kodlamalarıyla (cross-compiler GEREKMEZ — askeri seviye öz-yeterlilik)
üretilir. Testin doğruladığı yetenekler:
  - ELF e_machine -> mimari tespiti (0xB7 AArch64, 0x28 ARM)
  - Capstone ARM64/ARM32 disassembly
  - BL hedeflerinden fonksiyon keşfi + xref (call)
  - cbz/b.cond koşullu dalları (jcc) + geri döngü (loop tespiti)
  - adr x0, [rodata] -> string xref'i (ARM64)
  - bx lr / ret dönüşleri
"""
import struct, sys, os

OUT = os.path.dirname(os.path.abspath(__file__))

# ----------------------------------------------------------------------------
# ARM64 (AArch64) kodlamaları
# ----------------------------------------------------------------------------
def a64_bl(src, dst):
    off = (dst - src) >> 2
    assert -(1 << 25) <= off < (1 << 25)
    return 0x94000000 | (off & 0x3FFFFFF)

def a64_b(src, dst):
    off = (dst - src) >> 2
    return 0x14000000 | (off & 0x3FFFFFF)

def a64_bcond(src, dst, cond):          # cond: eq=0, ne=1, lt=0xB, ge=0xA ...
    off = (dst - src) >> 2
    return 0x54000000 | ((off & 0x7FFFF) << 5) | cond

def a64_cbz(src, dst, rt):              # rt: x0=0
    off = (dst - src) >> 2
    return 0xB4000000 | ((off & 0x7FFFF) << 5) | rt

def a64_movz(rd, imm, hw=0, sf=1):      # movz x0,#5
    return (0xD2800000 if sf else 0x52800000) | (hw << 21) | ((imm & 0xFFFF) << 5) | rd

def a64_add_imm(rd, rn, imm):           # add x0, x0, #8
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd

def a64_adr(rd, src, dst):              # adr x0, label (±1MB)
    off = dst - src
    immlo = off & 3
    immhi = (off >> 2) & 0x7FFFF
    return 0x10000000 | (immlo << 29) | (immhi << 5) | rd

A64_RET   = 0xD65F03C0
A64_NOP   = 0xD503201F
A64_ADD_W = lambda rd, rn, rm: 0x0B000000 | (rm << 16) | (rn << 5) | rd  # add w3,w1,w2

def build_arm64():
    BASE   = 0x400000
    TEXT   = BASE + 0x100               # 0x400100
    STRVA  = BASE + 0x200               # 0x400200 (rodata string)
    strArm = b"ARM64 GodTier askeri test\x00"

    # --- _start: 0x400100 ---
    start = TEXT
    f1 = TEXT + 0x20                    # 0x400120
    f2 = TEXT + 0x30                    # 0x400130
    f3 = TEXT + 0x50                    # 0x400150
    code = []
    def emit(v): code.append(v & 0xFFFFFFFF)
    emit(a64_movz(0, 5))                # 100: mov x0, #5
    emit(a64_bl(start + 4, f1))         # 104: bl f1 (0x400120)
    emit(a64_bl(start + 8, f2))         # 108: bl f2 (0x400130)
    emit(a64_movz(0, 0))                # 10c: mov w0, #0
    emit(A64_RET)                       # 110: ret
    emit(A64_NOP); emit(A64_NOP); emit(A64_NOP)  # 114-11c: hizalama
    # --- f1: 0x400120 ---
    emit(a64_movz(0, 7))                # 120: mov w0, #7
    emit(A64_RET)                       # 124: ret
    emit(A64_NOP); emit(A64_NOP)        # 128-12c
    # --- f2: 0x400130 (koşullu dal + döngü + çağrı) ---
    # döngü: x1=3; tekrar: cbz x1, cikis; x1-- ... b geri
    emit(a64_movz(1, 3))                # 130: mov x1, #3
    loop = f2 + 8                       # 138
    emit(A64_NOP)                       # 134
    emit(a64_cbz(f2 + 8, f2 + 0x18, 1)) # 138: cbz x1, 0x400148 (cikis)
    emit(0xCB010021 if False else 0xD1000421)  # 13c: sub x1, x1, #1
    emit(a64_b(f2 + 0x10, loop))        # 140: b 0x400138 (geri döngü)
    emit(a64_bcond(f2 + 0x14, f1, 0))   # 144: b.eq f1 (koşullu ileri dal)
    emit(a64_bl(f2 + 0x18, f3))         # 148: bl f3
    emit(A64_RET)                       # 14c: ret
    # --- f3: 0x400150 (rodata string erişimi) ---
    emit(a64_adr(0, f3, STRVA))         # 150: adr x0, 0x400200
    emit(A64_RET)                       # 154: ret

    text = b"".join(struct.pack("<I", c) for c in code)
    assert len(text) <= 0x100, len(text)

    # --- ELF64 üret ---
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2      # ELFCLASS64
    ehdr[5] = 1      # LSB
    ehdr[6] = 1      # EV_CURRENT
    ehdr[7] = 0      # SYSV
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16,
        2,             # e_type = ET_EXEC
        0xB7,          # e_machine = EM_AARCH64
        1,             # e_version
        TEXT,          # e_entry
        64,            # e_phoff
        0,             # e_shoff (aşağıda)
        0,             # e_flags
        64, 56, 1, 0, 0, 0)
    # phdr: tek PT_LOAD (R+X), dosya offset 0 -> vaddr BASE
    phdr = struct.pack("<IIQQQQQQ",
        1,                    # PT_LOAD
        5,                    # PF_R|PF_X
        0, BASE, 0x1000, 0x1000, 0x1000, 0x1000)
    data = bytearray(bytes(ehdr) + phdr)
    data += b"\x00" * (0x100 - len(data))        # 0x100'e hizala
    data += text
    data += b"\x00" * (0x200 - len(data))        # rodata hizala
    data += strArm
    data += b"\x00" * (0x300 - len(data))
    # section headers + shstrtab (parser section tablosu ister)
    shstr = b"\x00.text\x00.rodata\x00.shstrtab\x00"
    shstr_off = 0x300
    data += shstr
    data += b"\x00" * ((8 - len(data) % 8) % 8)
    shoff = len(data)
    nul = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    def sh(name, typ, flags, addr, off, size):
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, size, 0, 0, 1, 0)
    shs = nul + sh(1, 1, 6, TEXT, 0x100, len(text)) \
             + sh(7, 1, 2, STRVA, 0x200, len(strArm)) \
             + sh(15, 3, 0, 0, shstr_off, len(shstr))
    data += shs
    struct.pack_into("<Q", data, 0x28, shoff)    # e_shoff
    struct.pack_into("<H", data, 0x3A, 64)      # e_shentsize (Elf64_Shdr)
    struct.pack_into("<H", data, 0x3C, 4)       # e_shnum
    struct.pack_into("<H", data, 0x3E, 3)       # e_shstrndx
    path = os.path.join(OUT, "kurban_arm64.elf")
    open(path, "wb").write(data)
    print("yazildi:", path, len(data), "bayt")

# ----------------------------------------------------------------------------
# ARM32 (ARM modu) kodlamaları
# ----------------------------------------------------------------------------
def a32_bl(src, dst):
    off = (dst - src - 8) >> 2          # ARM: hedef = pc + 8 + off*4
    return 0xEB000000 | (off & 0xFFFFFF)

def a32_b(src, dst):
    off = (dst - src - 8) >> 2
    return 0xEA000000 | (off & 0xFFFFFF)

def a32_mov_rd_imm(rd, imm):           # mov r0, #7
    return 0xE3A00000 | (rd << 12) | (imm & 0xFF)

A32_BXLR = 0xE12FFF1E                  # bx lr
A32_NOP  = 0xE1A00000                  # mov r0, r0 (nop)
A32_CMP  = lambda rn, imm: 0xE3500000 | (rn << 16) | (imm & 0xFF)   # cmp rN, #imm
def a32_beq(src, dst):
    off = (dst - src - 8) >> 2
    return 0x0A000000 | (off & 0xFFFFFF)

def build_arm32():
    BASE = 0x400000
    TEXT = BASE + 0x100
    f1 = TEXT + 0x18
    code = []
    def emit(v): code.append(v & 0xFFFFFFFF)
    emit(a32_mov_rd_imm(0, 5))          # 100: mov r0, #5
    emit(a32_bl(TEXT + 4, f1))          # 104: bl f1
    emit(a32_mov_rd_imm(0, 0))          # 108: mov r0, #0
    emit(A32_BXLR)                      # 10c: bx lr
    emit(A32_NOP); emit(A32_NOP)        # hizalama
    emit(a32_mov_rd_imm(0, 7))          # 118 (f1): mov r0, #7
    emit(A32_BXLR)                      # 11c: bx lr
    text = b"".join(struct.pack("<I", c) for c in code)

    ehdr = bytearray(52)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 1      # ELFCLASS32
    ehdr[5] = 1      # LSB
    ehdr[6] = 1
    struct.pack_into("<HHIIIIIHHHHHH", ehdr, 16,
        2,             # ET_EXEC
        0x28,          # EM_ARM
        1, TEXT, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    # Elf32_Phdr: (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
    #              p_flags, p_align) — alan sırası Elf64'ten FARKLI (flags sonda)
    phdr = struct.pack("<IIIIIIII",
        1, 0, BASE, BASE, 0x290, 0x1000, 5, 0x1000)
    data = bytearray(bytes(ehdr) + phdr)
    data += b"\x00" * (0x100 - len(data))
    data += text
    data += b"\x00" * (0x200 - len(data))
    shstr = b"\x00.text\x00.shstrtab\x00"
    shstr_off = 0x200
    data += shstr
    data += b"\x00" * ((8 - len(data) % 8) % 8)
    shoff = len(data)
    nul = struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    def sh(name, typ, flags, addr, off, size):
        return struct.pack("<IIIIIIIIII", name, typ, flags, addr, off, size, 0, 0, 1, 0)
    shs = nul + sh(1, 1, 6, TEXT, 0x100, len(text)) + sh(8, 3, 0, 0, shstr_off, len(shstr))
    data += shs
    struct.pack_into("<I", data, 0x20, shoff)
    struct.pack_into("<H", data, 0x2E, 40)      # e_shentsize (Elf32_Shdr)
    struct.pack_into("<H", data, 0x30, 3)
    struct.pack_into("<H", data, 0x32, 2)
    path = os.path.join(OUT, "kurban_arm32.elf")
    open(path, "wb").write(bytes(data))
    print("yazildi:", path, len(data), "bayt")

if __name__ == "__main__":
    build_arm64()
    build_arm32()
    sys.exit(0)
