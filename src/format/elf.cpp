// ============================================================================
//  i4M GodTier Engine — format/elf.cpp
// ============================================================================
#include "format/elf.h"
#include "core/log.h"
#include "core/util.h"
#include <cstring>
#include <algorithm>

namespace gt {

bool ELF::Load(const std::string& path) {
    raw_ = ReadFileBytes(path);
    if (raw_.size() < 64) return false;
    if (memcmp(raw_.data(), "\x7f" "ELF", 4) != 0) return false;
    if (!Parse()) { raw_.clear(); return false; }
    return true;
}

bool ELF::Parse() {
    is64_ = raw_[4] == 2;
    if (!is64_) { LogWarn("ELF32: destek sınırlı (x86-64 odaklıyız), parser yine de okur"); }
    type_ = R16(16);
    machine_ = R16(18);
    if (is64_) {
        entryVa_ = R64(24);
        shoff_ = R64(40);
        shentsize_ = R16(58); shnum_ = R16(60); shstrndx_ = R16(62);
    } else {
        entryVa_ = R32(24);
        shoff_ = R32(32);
        shentsize_ = R16(46); shnum_ = R16(48); shstrndx_ = R16(50);
    }
    if (machine_ != 62 && machine_ != 3)
        LogWarn("ELF makine %u (x86 değil) — analiz sınırlı olabilir", machine_);
    ParseSections();
    ParseSegments();
    ParseSymbols();
    ParseDynamic();
    ParsePlt();
    if (minVaddr_ == (u64)-1) minVaddr_ = 0;
    return true;
}

u64 ELF::ImageBase() const { return minVaddr_ == (u64)-1 ? 0 : minVaddr_; }
u64 ELF::ImageSize() const { return maxVaddrEnd_ ? maxVaddrEnd_ - ImageBase() : raw_.size(); }

std::string ELF::FormatName() const {
    std::string s = is64_ ? "ELF64" : "ELF32";
    if (type_ == 2) s += " (EXEC)";
    else if (type_ == 3) s += " (DYN/PIE)";
    return s;
}

// v6: e_machine -> mimari (0x3E x86-64, 0xB7 AArch64, 0x28 ARM)
Arch ELF::GetArch() const {
    switch (machine_) {
        case 0x03: return Arch::X86_32;
        case 0x3E: return Arch::X86_64;
        case 0xB7: return Arch::ARM64;
        case 0x28: return Arch::ARM32;
        default:   return is64_ ? Arch::X86_64 : Arch::X86_32;
    }
}

bool ELF::ParseSections() {
    if (!shoff_ || !shnum_) return true;
    u64 shstrOff = 0, shstrSize = 0;
    auto shNameOff = [&](u64 idx) -> u64 {
        u64 sh = shoff_ + idx * shentsize_;
        if (!InRaw(sh, shentsize_)) return 0;
        u32 nameOff = R32(sh);
        return shstrOff + nameOff;
    };
    if (shstrndx_ < shnum_) {
        u64 sh = shoff_ + (u64)shstrndx_ * shentsize_;
        if (InRaw(sh, shentsize_)) {
            shstrOff = is64_ ? R64(sh + 24) : R32(sh + 16);
            shstrSize = is64_ ? R64(sh + 32) : R32(sh + 20);
        }
    }
    for (u16 i = 0; i < shnum_; i++) {
        u64 sh = shoff_ + (u64)i * shentsize_;
        if (!InRaw(sh, shentsize_)) break;
        u32 nameOff = R32(sh);
        u32 type = R32(sh + 4);
        // Elf32_Shdr: name(0) type(4) FLAGS(8) addr(12) offset(16) size(20)
        // Elf64_Shdr: name(0) type(4) flags(8,8B) addr(16) offset(24) size(32)
        // (v6 fix: ELF32 flags daha önce sh+24'ten (sh_link!) okunuyordu —
        //  32-bit ELF'lerde .text'in EXEC bayrağı kayboluyordu)
        u64 flags = is64_ ? R64(sh + 8) : R32(sh + 8);
        u64 addr  = is64_ ? R64(sh + 16) : R32(sh + 12);
        u64 off   = is64_ ? R64(sh + 24) : R32(sh + 16);
        u64 size  = is64_ ? R64(sh + 32) : R32(sh + 20);
        if (addr && addr != (u64)-1) {
            minVaddr_ = std::min(minVaddr_, addr);
            maxVaddrEnd_ = std::max(maxVaddrEnd_, addr + size);
        }
        if (type == 0) continue; // SHT_NULL
        SectionInfo si;
        u64 no = shstrOff + nameOff;
        si.name = InRaw(no, 1) ? (const char*)&raw_[no] : ("sec" + std::to_string(i));
        si.va = addr; si.vsize = size; si.rawOffset = off; si.rawSize = size;
        si.executable = (flags & 0x4) != 0;  // SHF_EXECINSTR
        si.writable   = (flags & 0x1) != 0;  // SHF_WRITE
        si.readable   = true;
        si.characteristics = (u32)flags;
        sections_.push_back(si);
    }
    return true;
}

bool ELF::ParseSegments() {
    u64 phoff = is64_ ? R64(32) : R32(28);
    u16 phentsize = is64_ ? R16(54) : R16(42);
    u16 phnum = is64_ ? R16(56) : R16(44);
    if (!phoff || !phnum) return true;
    for (u16 i = 0; i < phnum; i++) {
        u64 p = phoff + (u64)i * phentsize;
        if (!InRaw(p, (u64)phentsize)) break;
        u32 type = R32(p);
        u64 vaddr, filesz, offset;
        if (is64_) {
            u32 flags = R32(p + 4);
            offset = R64(p + 8); vaddr = R64(p + 16); filesz = R64(p + 32);
            if (type == 1 /*PT_LOAD*/) {
                loadSegs_.push_back({vaddr, filesz});
                minVaddr_ = std::min(minVaddr_, vaddr);
                maxVaddrEnd_ = std::max(maxVaddrEnd_, vaddr + filesz);
            }
            if (type == 3 /*PT_INTERP*/) {
                u64 q = offset;
                if (InRaw(q, 1)) interp_ = (const char*)&raw_[q];
            }
            (void)flags;
        } else {
            offset = R32(p + 4); vaddr = R32(p + 8);
            u32 filesz32 = R32(p + 16);
            filesz = filesz32;
            if (type == 1) {
                loadSegs_.push_back({vaddr, filesz});
                minVaddr_ = std::min(minVaddr_, vaddr);
                maxVaddrEnd_ = std::max(maxVaddrEnd_, vaddr + filesz);
            }
            if (type == 3 && InRaw(offset, 1)) interp_ = (const char*)&raw_[offset];
        }
    }
    return true;
}

bool ELF::ParseSymbols() {
    // .symtab + .dynsym: ikisini de sembol listesine katarız
    for (auto& sec : sections_) {
        bool isSymtab = sec.name == ".symtab" || sec.name == ".dynsym";
        if (!isSymtab) continue;
        u64 entsize = is64_ ? 24 : 16;
        u64 linkedStr = 0, linkedStrSize = 0;
        // linkli string tablosunu bul (sh_link)
        for (u16 i = 0; i < shnum_; i++) {
            u64 sh = shoff_ + (u64)i * shentsize_;
            if (!InRaw(sh, shentsize_)) break;
            u64 off = is64_ ? R64(sh + 24) : R32(sh + 16);
            if (off == sec.rawOffset) {
                u32 link = R32(sh + 40);
                if (link < shnum_) {
                    u64 lsh = shoff_ + (u64)link * shentsize_;
                    if (InRaw(lsh, shentsize_)) {
                        linkedStr = is64_ ? R64(lsh + 24) : R32(lsh + 16);
                        linkedStrSize = is64_ ? R64(lsh + 32) : R32(lsh + 20);
                    }
                }
                break;
            }
        }
        if (!linkedStr) continue;
        for (u64 o = sec.rawOffset; o + entsize <= sec.rawOffset + sec.rawSize; o += entsize) {
            u32 nameIdx = R32(o);
            u64 value, size; u16 shndx; u8 info;
            if (is64_) {
                info = R8(o + 4); shndx = R16(o + 6);
                value = R64(o + 8); size = R64(o + 16);
            } else {
                value = R32(o + 4); size = R32(o + 8); info = R8(o + 12); shndx = R16(o + 14);
            }
            if (!nameIdx || shndx == 0 /*SHN_UNDEF*/) continue;
            u8 styp = (info & 0xF);
            if (styp == 4 /*STT_FILE*/ || styp == 3 /*STT_SECTION*/ || styp == 0 /*STT_NOTYPE: FILE benzeri va=0*/)
                continue;
            u64 np = linkedStr + nameIdx;
            if (!InRaw(np, 1)) continue;
            const char* nm = (const char*)&raw_[np];
            if (!nm[0]) continue;
            SymbolInfo s;
            s.name = Demangle(nm);
            s.va = value;
            s.size = size;
            s.isFunction = (styp == 2) /*STT_FUNC*/;
            symbols_.push_back(s);
        }
    }
    return true;
}

bool ELF::ParseDynamic() {
    // .dynamic: DT_NEEDED -> import DLL karşılığı, DT_SONAME -> export adı
    for (auto& sec : sections_) {
        if (sec.name != ".dynamic") continue;
        u64 entsize = is64_ ? 16 : 8;
        std::string strtab;
        // .dynstr'yi bul
        for (auto& s2 : sections_) if (s2.name == ".dynstr" && s2.rawSize) {
            strtab.assign((const char*)&raw_[s2.rawOffset], (size_t)s2.rawSize);
            break;
        }
        for (u64 o = sec.rawOffset; o + entsize <= sec.rawOffset + sec.rawSize; o += entsize) {
            u64 tag, val;
            if (is64_) { tag = R64(o); val = R64(o + 8); }
            else { tag = R32(o); val = R32(o + 4); }
            if (tag == 0) break;
            if (tag == 1 /*DT_NEEDED*/ && val < strtab.size()) {
                ImportDll d; d.name = strtab.c_str() + val;
                imports_.push_back(d);
            }
        }
    }
    // .dynsym fonksiyonları export olarak da sun
    for (auto& s : symbols_) {
        if (!s.isFunction) continue;
        ExportFunc e; e.name = s.name; e.va = s.va;
        if (s.va >= ImageBase() && s.va < ImageBase() + ImageSize())
            exports_.push_back(e);
    }
    return true;
}

u64 ELF::RawToVa(u64 off) const {
    for (auto& [vaddr, filesz] : loadSegs_) {
        // segment offset bilgisini saklamadık; section bazlı da dene
        (void)filesz; (void)vaddr;
    }
    for (auto& s : sections_)
        if (off >= s.rawOffset && off < s.rawOffset + s.rawSize && s.va)
            return s.va + (off - s.rawOffset);
    return (u64)-1;
}

u64 ELF::VaToRaw(u64 va) const {
    for (auto& s : sections_)
        if (s.va && va >= s.va && va < s.va + s.vsize) {
            u64 d = va - s.va;
            if (d < s.rawSize) return s.rawOffset + d;
            return (u64)-1;
        }
    return (u64)-1;
}

std::string ELF::SymbolAt(u64 va) const {
    for (auto& s : symbols_) if (s.va == va) return s.name;
    return "";
}

// ----------------------------------------------------------------------------
// PLT/GOT: .rela.plt (JUMP_SLOT) + .rela.dyn (GLOB_DAT) + .plt/.plt.got tarama
// Amaç: "call 0x1030" -> "printf", "call [rip+X]" -> "__libc_start_main"
// ----------------------------------------------------------------------------
static std::string SymBaseName(const std::string& s) {
    // "printf@GLIBC_2.2.5" -> "printf"
    size_t at = s.find('@');
    return at == std::string::npos ? s : s.substr(0, at);
}

bool ELF::ParsePlt() {
    if (!is64_) return true;   // 32-bit PLT düzeni farklı: sessiz geç

    // 1) .dynsym isimlerini indeks sırasıyla topla (UNDEF importlar dahil)
    std::vector<std::string> dynNames;
    const SectionInfo* dynsym = nullptr;
    for (auto& s : sections_) if (s.name == ".dynsym") { dynsym = &s; break; }
    std::string dynstr;
    for (auto& s : sections_) if (s.name == ".dynstr" && s.rawSize) {
        dynstr.assign((const char*)&raw_[s.rawOffset], (size_t)s.rawSize);
        break;
    }
    if (dynsym && !dynstr.empty()) {
        for (u64 o = dynsym->rawOffset; o + 24 <= dynsym->rawOffset + dynsym->rawSize; o += 24) {
            u32 nameIdx = R32(o);
            dynNames.push_back(nameIdx < dynstr.size()
                ? std::string(dynstr.c_str() + nameIdx) : std::string());
        }
    }

    // 2) relocation'lar: GOT yuvası -> isim
    auto addReloc = [&](u64 off, u64 entsize, u16 typeWanted) {
        for (u64 o = off; o + entsize <= off + 0x100000; o += entsize) {
            if (!InRaw(o, entsize)) break;
            u64 rOffset = R64(o);
            u64 rInfo   = R64(o + 8);
            u32 type    = (u32)(rInfo & 0xFFFFFFFFull);
            u32 symIdx  = (u32)(rInfo >> 32);
            if (type != typeWanted || !symIdx || symIdx >= dynNames.size()) continue;
            std::string nm = SymBaseName(dynNames[symIdx]);
            if (nm.empty()) continue;
            gotByVa_[rOffset] = nm;
        }
    };
    for (auto& s : sections_) {
        if (s.name == ".rela.plt") addReloc(s.rawOffset, 24, 7 /*JUMP_SLOT*/);
        if (s.name == ".rela.dyn") addReloc(s.rawOffset, 24, 6 /*GLOB_DAT*/);
    }

    // 3) .plt / .plt.got tarama: her 16 baytlık slot "ff 25 disp32" (jmp [rip+X])
    //    ile başlıyorsa GOT yuvasını hesapla ve eşleştir
    for (auto& sec : sections_) {
        if (sec.name != ".plt" && sec.name != ".plt.got") continue;
        for (u64 va = sec.va; va + 6 <= sec.va + sec.vsize; va += 16) {
            u64 off = sec.rawOffset + (va - sec.va);
            if (!InRaw(off, 6)) break;
            if (raw_[off] != 0xFF || raw_[off + 1] != 0x25) continue;  // jmp [rip+d]
            i32 disp;
            memcpy(&disp, &raw_[off + 2], 4);
            u64 got = va + 6 + (u64)(i64)disp;
            auto it = gotByVa_.find(got);
            if (it != gotByVa_.end()) {
                pltByVa_[va] = it->second;
                pltVaByName_[it->second] = va;
            }
        }
    }
    return true;
}

std::string ELF::PltName(u64 va) const {
    auto it = pltByVa_.find(va);
    return it == pltByVa_.end() ? "" : it->second;
}

std::string ELF::GotName(u64 va) const {
    auto it = gotByVa_.find(va);
    return it == gotByVa_.end() ? "" : it->second;
}

u64 ELF::PltVaOf(const std::string& name) const {
    auto it = pltVaByName_.find(name);
    return it == pltVaByName_.end() ? 0 : it->second;
}

} // namespace gt
