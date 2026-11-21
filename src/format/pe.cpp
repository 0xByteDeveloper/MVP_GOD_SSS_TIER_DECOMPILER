// ============================================================================
//  i4M GodTier Engine — format/pe.cpp
// ============================================================================
#include "format/pe.h"
#include "core/log.h"
#include "core/util.h"
#include <cstring>

namespace gt {

// --- paketsiz PE başlık yapıları (derleyici bağımsız, hizalamasız okuma) ---
struct PeNtHeaders {
    u32 sig; u16 machine; u16 numSections; u32 timestamp;
    u32 symPtr; u32 numSyms; u16 optSize; u16 characteristics;
};
struct PeOptStd {
    u16 magic; u8 linkVerMajor, linkVerMinor; u32 sizeOfCode, sizeOfInit, sizeOfUninit;
    u32 entryRva; u32 baseOfCode; u32 baseOfData; // 32-bit'te baseOfData var, 64'te yok
};
struct PeOptWinCommon {
    u32 imageBase32; u32 sectionAlign; u32 fileAlign;
    u16 osVerMaj, osVerMin, imgVerMaj, imgVerMin, subSysMaj, subSysMin;
    u32 win32Ver, sizeOfImage, sizeOfHeaders, checksum;
    u16 subsystem, dllChars;
    u32 stackRes, stackCom, heapRes, heapCom;
    u32 loaderFlags, numRvaSizes;
};

static const u16 IMAGE_FILE_MACHINE_I386 = 0x014c;
static const u16 IMAGE_FILE_MACHINE_AMD64 = 0x8664;

std::string PE::RStr(u64 o, u64 maxLen) const {
    if (o >= raw_.size()) return "";
    u64 end = o;
    while (end < raw_.size() && raw_[end] && end - o < maxLen) end++;
    return std::string((const char*)&raw_[o], end - o);
}

std::string PE::RStrRva(u32 rva, u64 maxLen) const {
    u32 off = RvaToOffset(rva);
    if (!off && rva >= headersSize_) return "";
    return RStr(off ? off : rva, maxLen);
}

u32 PE::RvaToOffset(u32 rva) const {
    // s.va tam VA içerir; RVA karşılaştırması için ImageBase düş
    for (auto& s : sections_) {
        u64 rvaStart = s.va - imageBase_;
        u64 span = std::max<u64>(s.vsize, s.rawSize);
        if (rva >= rvaStart && rva < rvaStart + span) {
            u64 delta = rva - rvaStart;
            if (delta < s.rawSize) return (u32)(s.rawOffset + delta);
            return 0; // .bss benzeri: dosyada karşılığı yok
        }
    }
    if (rva < headersSize_) return rva;
    return 0;
}

bool PE::Load(const std::string& path) {
    raw_ = ReadFileBytes(path);
    if (raw_.size() < 0x40) { LogErr("Dosya çok küçük (PE değil?)"); return false; }
    if (!Parse()) { raw_.clear(); return false; }
    return true;
}

bool PE::Parse() {
    if (R16(0) != 0x5A4D) { LogErr("MZ imzası yok"); return false; }
    u32 peOff = R32(0x3C);
    if (!InRaw(peOff, 4 + sizeof(PeNtHeaders))) { LogErr("PE ofseti bozuk"); return false; }
    if (R32(peOff) != 0x00004550) { LogErr("PE\\0\\0 imzası yok"); return false; }

    u64 nt = peOff + 4;
    PeNtHeaders ntH{};
    ntH.sig = R32(nt - 4);
    ntH.machine = R16(nt); ntH.numSections = R16(nt + 2); ntH.timestamp = R32(nt + 4);
    ntH.symPtr = R32(nt + 8); ntH.numSyms = R32(nt + 12);
    ntH.optSize = R16(nt + 16); ntH.characteristics = R16(nt + 18);

    machine_ = ntH.machine;
    numSections_ = ntH.numSections;
    timestamp_ = ntH.timestamp;
    characteristics_ = ntH.characteristics;
    coffSymPtr_ = ntH.symPtr; coffSymCount_ = ntH.numSyms;

    if (machine_ != IMAGE_FILE_MACHINE_I386 && machine_ != IMAGE_FILE_MACHINE_AMD64) {
        LogWarn("Bilinmeyen makine tipi 0x%04x — yine de devam", machine_);
    }

    u64 opt = nt + 20;
    if (!InRaw(opt, 64)) { LogErr("Optional header yok"); return false; }
    u16 magic = R16(opt);
    if (magic == 0x20b) is64_ = true;
    else if (magic == 0x10b) is64_ = false;
    else { LogErr("Bilinmeyen optional header magic 0x%x", magic); return false; }

    u64 p = opt;
    entryRva_ = R32(p + 16);
    if (!is64_) {
        imageBase_ = R32(p + 28);
        p = opt + 96;  // data dizinleri
    } else {
        imageBase_ = R64(p + 24);
        p = opt + 112;
    }
    imageSize_ = R32(opt + 56);
    headersSize_ = R32(opt + 60);
    checksum_ = R32(opt + 64);
    subsystem_ = R16(opt + 68);
    dllChars_ = R16(opt + 70);

    // Data dizinleri (16 adet)
    u32 numDirs = R32(p - 4);
    if (numDirs > 16) numDirs = 16;
    struct Dir { u32 rva, size; };
    auto dir = [&](int i) -> Dir {
        u64 q = p + (u64)i * 8;
        if (!InRaw(q, 8) || i >= (int)numDirs) return {0, 0};
        return { R32(q), R32(q + 4) };
    };
    Dir dImport = dir(1), dExport = dir(0), dReloc = dir(5), dDebug = dir(6),
        dTls = dir(9), dDelay = dir(13);
    importDirRva_ = dImport.rva; importDirSize_ = dImport.size;
    exportDirRva_ = dExport.rva; exportDirSize_ = dExport.size;
    relocDirRva_ = dReloc.rva;  relocDirSize_ = dReloc.size;
    debugDirRva_ = dDebug.rva;  debugDirSize_ = dDebug.size;
    tlsDirRva_ = dTls.rva;      tlsDirSize_ = dTls.size;
    delayDirRva_ = dDelay.rva;  delayDirSize_ = dDelay.size;

    if (!ParseSections()) return false;
    ParseImports();
    ParseExports();
    ParseRelocs();
    ParseDebug();
    ParseTLS();
    ParseRich();
    ParseCoffSymbols();
    return true;
}

bool PE::ParseSections() {
    u64 secTab = 0;
    // section tablosu: optional header'ın hemen sonrası
    u32 peOff = R32(0x3C);
    u16 optSize = R16(peOff + 4 + 16);
    secTab = peOff + 4 + 20 + optSize;
    sections_.reserve(numSections_);
    for (u16 i = 0; i < numSections_; i++) {
        u64 s = secTab + (u64)i * 40;
        if (!InRaw(s, 40)) break;
        SectionInfo si;
        char name[9] = {};
        memcpy(name, &raw_[s], 8);
        si.name = name;
        u32 vsize = R32(s + 8), vaddr = R32(s + 12);
        si.rawSize = R32(s + 16); si.rawOffset = R32(s + 20);
        si.characteristics = R32(s + 36);
        si.vsize = vsize ? vsize : si.rawSize;
        si.va = imageBase_ + vaddr;
        si.executable = (si.characteristics & 0x20000000) != 0; // MEM_EXECUTE
        si.writable   = (si.characteristics & 0x80000000) != 0; // MEM_WRITE
        si.readable   = (si.characteristics & 0x40000000) != 0; // MEM_READ
        sections_.push_back(si);
    }
    if (sections_.empty()) { LogWarn("Section tablosu boş"); }
    return true;
}

bool PE::ParseImports() {
    if (!importDirRva_) return true;
    // her deskriptör 20 bayt
    for (u32 i = 0;; i++) {
        u64 d = RvaToOffset(importDirRva_ + i * 20);
        if (!d || !InRaw(d, 20)) break;
        u32 oftRva = R32(d);          // OriginalFirstThunk (INT)
        u32 nameRva = R32(d + 12);
        u32 iatRva = R32(d + 16);
        if (!nameRva) break;
        ImportDll dll;
        dll.name = RStrRva(nameRva);
        u32 thunkRva = oftRva ? oftRva : iatRva;
        if (thunkRva) {
            for (u32 j = 0;; j++) {
                u64 t = RvaToOffset(thunkRva + (u64)j * (is64_ ? 8 : 4));
                if (!t || !InRaw(t, is64_ ? 8 : 4)) break;
                u64 entry = is64_ ? R64(t) : R32(t);
                if (!entry) break;
                ImportFunc fn;
                fn.iatVa = imageBase_ + iatRva + (u64)j * (is64_ ? 8 : 4);
                if (is64_ ? (entry & 0x8000000000000000ull) : (entry & 0x80000000u)) {
                    fn.ordinal = (u16)(entry & 0xFFFF);
                } else {
                    u64 hintOff = RvaToOffset((u32)(entry & 0x7FFFFFFF));
                    if (hintOff && InRaw(hintOff, 2)) {
                        fn.hint = (int)R16(hintOff);
                        fn.name = RStr(hintOff + 2, 512);
                    }
                }
                dll.funcs.push_back(fn);
            }
        }
        if (!dll.funcs.empty()) imports_.push_back(dll);
    }
    // Delay-load DLL isimleri
    if (delayDirRva_) {
        for (u32 i = 0;; i++) {
            u64 d = RvaToOffset(delayDirRva_ + i * 32);
            if (!d || !InRaw(d, 32)) break;
            u32 attr = R32(d);
            u32 nameRva = R32(d + 16);
            if (!nameRva) break;
            if (!(attr & 1)) delayDlls_.push_back(RStrRva(nameRva));
        }
    }
    return true;
}

bool PE::ParseExports() {
    if (!exportDirRva_) return true;
    u64 d = RvaToOffset(exportDirRva_);
    if (!d || !InRaw(d, 40)) return true;
    u32 nameRva = R32(d + 12);
    u32 ordBase = R32(d + 16);
    u32 numNames = R32(d + 24);
    u32 addrRva = R32(d + 28), namesRva = R32(d + 32), ordsRva = R32(d + 36);

    std::vector<u32> ordTable(numNames ? numNames : 1, 0);
    for (u32 i = 0; i < numNames; i++) {
        u64 no = RvaToOffset(namesRva + i * 4);
        if (!no) continue;
        u64 oo = RvaToOffset(ordsRva + i * 2);
        u16 ord = oo && InRaw(oo, 2) ? R16(oo) : 0;
        if (i < ordTable.size()) ordTable[i] = ord;
        std::string nm = RStrRva(R32(no));
        u64 ao = RvaToOffset(addrRva + (u64)ord * 4);
        u32 fnRva = ao && InRaw(ao, 4) ? R32(ao) : 0;
        ExportFunc e;
        e.name = nm;
        e.va = imageBase_ + fnRva;
        e.ordinal = (u16)(ordBase + ord);
        exports_.push_back(e);

        SymbolInfo s; s.name = nm; s.va = e.va; s.isFunction = true;
        symbols_.push_back(s);
    }
    return true;
}

bool PE::ParseRelocs() {
    if (!relocDirRva_ || !relocDirSize_) return true;
    u64 p = 0;
    while (p < relocDirSize_) {
        u64 b = RvaToOffset(relocDirRva_ + (u32)p);
        if (!b || !InRaw(b, 8)) break;
        u32 pageRva = R32(b);        // blok BAŞINDAKİ sayfa RVA'sı
        u32 blockSize = R32(b + 4);
        if (blockSize < 8 || blockSize > 0x10000) break;
        u32 count = (blockSize - 8) / 2;
        for (u32 i = 0; i < count; i++) {
            u16 e = R16(b + 8 + (u64)i * 2);
            u16 type = e >> 12;
            u16 off = e & 0xFFF;
            if (!type) continue; // IMAGE_REL_BASED_ABSOLUTE (padding)
            RelocEntry r;
            r.va = imageBase_ + pageRva + off;
            r.type = type;
            relocs_.push_back(r);
        }
        p += blockSize;
    }
    return true;
}

bool PE::ParseDebug() {
    if (!debugDirRva_) return true;
    u64 d = RvaToOffset(debugDirRva_);
    if (!d || !InRaw(d, 28)) return true;
    u32 type = R32(d + 12);
    if (type != 2) return true; // 2 = CODEVIEW
    u32 ptr = R32(d + 24);
    if (!ptr || !InRaw(ptr, 24)) return true;
    if (R32(ptr) != 0x53445352) return true; // "RSDS"
    debug_.hasPdb = true;
    char guid[33];
    for (int i = 0; i < 16; i++)
        std::snprintf(guid + i * 2, 3, "%02X", raw_[ptr + 4 + i]);
    debug_.pdbGuid = std::string(guid) + ToHex(R32(ptr + 20), 8);
    debug_.pdbPath = RStr(ptr + 24, 1024);
    return true;
}

bool PE::ParseTLS() {
    if (!tlsDirRva_) return true;
    u64 d = RvaToOffset(tlsDirRva_);
    if (!d || !InRaw(d, is64_ ? 40 : 24)) return true;
    hasTls_ = true;
    u32 cbRva = R32(d + 12); // AddressOfCallBacks (her iki bit genişliğinde aynı ofset)
    if (cbRva) {
        tlsCallbacksVa_ = imageBase_ + cbRva;
        // callback listesini say (yalnızca rapor; ASLR'li dosyada VA'lar reloc'suz okunur)
    }
    return true;
}

bool PE::ParseRich() {
    // Rich header: DOS stub içinde "DanS" .. "Rich" arası
    if (raw_.size() < 0x80) return true;
    u32 richOff = 0;
    for (u32 o = 0x40; o + 4 <= 0x200 && o < raw_.size(); o += 4) {
        if (R32(o) == 0x68636952) { richOff = o; break; } // "Rich"
    }
    if (!richOff) return true;
    u32 xorKey = R32(richOff + 4);
    u32 danS = R32(0x40) ^ xorKey;
    if (danS != 0x536E6144) return true; // "DanS" doğrula
    for (u32 o = 0x48; o < richOff; o += 8) {
        if (o + 8 > richOff) break;
        u16 compId = (u16)(R32(o) ^ xorKey);
        u32 cnt = R32(o + 4) ^ xorKey;
        RichEntry e;
        e.id = compId & 0xFF;
        e.build = compId >> 8;
        e.count = cnt;
        if (e.id || e.build) rich_.push_back(e);
    }
    return true;
}

bool PE::ParseCoffSymbols() {
    // MinGW/clang üretimi PE'lerde COFF sembol tablosu fonksiyon isimlerini taşır
    if (!coffSymPtr_ || !coffSymCount_) return true;
    if (!InRaw(coffSymPtr_, (u64)coffSymCount_ * 18)) return true;
    u64 strTab = coffSymPtr_ + (u64)coffSymCount_ * 18;
    if (!InRaw(strTab, 4)) return true;
    u32 strSize = R32(strTab);

    auto symName = [&](u64 s) -> std::string {
        u32 z = R32(s);                 // sıfırsa: string tablo ofseti
        if (z == 0) return "";
        u32 nn[2]; memcpy(nn, &raw_[s + 4], 8);
        if (nn[0] == 0 && nn[1] == 0) return "";
        // kısa isim (8 bayt) ya da string tablosu
        char shortName[9] = {};
        memcpy(shortName, &raw_[s + 4], 8);
        bool printable = true;
        for (int i = 0; i < 8 && shortName[i]; i++)
            if ((unsigned char)shortName[i] < 0x20 || (unsigned char)shortName[i] > 0x7E) { printable = false; break; }
        if (nn[0] == 0 && nn[1] != 0 && printable) {
            // z aslında isnin ilk 4 baytı... COFF: isim 8 baytlık alanda ya da
            // ilk 4 bayt 0 + sonraki 4 bayt string tablosu ofseti
        }
        if (nn[0] == 0) {
            u32 off = nn[1];
            if (off && off < strSize) return RStr(strTab + 4 + off, 1024);
        }
        if (printable && shortName[0]) return shortName;
        return "";
    };

    for (u32 i = 0; i < coffSymCount_; i++) {
        u64 s = coffSymPtr_ + (u64)i * 18;
        u32 value = R32(s + 8);
        u16 secNum = R16(s + 12);
        u16 type = R16(s + 14);
        u8  storage = R8(s + 16);
        u8  numAux = R8(s + 17);
        if (secNum == 0 || numAux) { i += numAux; continue; }
        // yalnızca fonksiyon sembolleri (type 0x20 = DT_FCN) veya extern metin
        if (!(type == 0x20) && !(storage == 2 && type == 0)) continue;
        std::string nm = symName(s);
        if (nm.empty()) continue;
        SymbolInfo sym;
        sym.name = Demangle(nm);
        sym.va = (secNum <= sections_.size())
                 ? sections_[secNum - 1].va + value
                 : imageBase_ + value;
        sym.isFunction = true;
        symbols_.push_back(sym);
    }
    return true;
}

std::string PE::FormatName() const {
    std::string s = is64_ ? "PE32+ (x64)" : "PE32 (x86)";
    if (IsDll()) s += " DLL";
    return s;
}

u64 PE::RawToVa(u64 off) const {
    if (off < headersSize_) return imageBase_ + off;
    for (auto& s : sections_)
        if (off >= s.rawOffset && off < s.rawOffset + s.rawSize)
            return s.va + (off - s.rawOffset);
    return (u64)-1;
}

u64 PE::VaToRaw(u64 va) const {
    u32 rva = (u32)(va - imageBase_);
    return RvaToOffset(rva) ? RvaToOffset(rva) : (u64)-1;
}

std::string PE::SymbolAt(u64 va) const {
    for (auto& s : symbols_) if (s.va == va) return s.name;
    for (auto& e : exports_) if (e.va == va) return e.name;
    return "";
}

} // namespace gt
