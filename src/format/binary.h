// ============================================================================
//  i4M GodTier Engine — format/binary.h
//  PE ve ELF için ortak soyutlama. İlham: LIEF'in tek API'si + pe-parse'in
//  disiplinli callback üslubu. Tek arayüzden iki format da aynı şekilde
//  sorgulanır; üst katmanlar (disasm/decomp/emulate) format bilmez.
// ============================================================================
#pragma once
#include "core/types.h"
#include <string>
#include <vector>

namespace gt {

struct SectionInfo {
    std::string name;
    u64 va = 0;            // sanal adres (ImageBase dahil)
    u64 vsize = 0;         // sanal boyut
    u64 rawOffset = 0;     // dosyadaki konum
    u64 rawSize = 0;       // dosyadaki boyut
    u32 characteristics = 0; // format bağımlı flag'ler
    bool executable = false, writable = false, readable = true;
};

struct ImportFunc {
    std::string name;      // boşsa ordinal import
    u16 ordinal = 0;
    u64 iatVa = 0;         // IAT yuvasının sanal adresi
    int hint = 0;
};

struct ImportDll {
    std::string name;
    std::vector<ImportFunc> funcs;
};

struct ExportFunc {
    std::string name;
    u64 va = 0;
    u16 ordinal = 0;
};

struct SymbolInfo {
    std::string name;
    u64 va = 0;
    u64 size = 0;
    bool isFunction = false;
};

struct RelocEntry {
    u64 va = 0;
    u16 type = 0;          // format bağımlı (PE: DIR64/HIGHLOW...; ELF: R_X86_64_RELATIVE)
};

struct StringRef {
    u64 va = 0;
    std::string text;
    bool wide = false;     // UTF-16LE mi
};

struct DebugInfo {
    bool hasPdb = false;
    std::string pdbPath;
    std::string pdbGuid;   // 32 hextext + age
};

class Binary {
public:
    virtual ~Binary() = default;

    // --- kimlik ---
    virtual std::string FormatName() const = 0;   // "PE32+" / "ELF64" ...
    virtual Arch GetArch() const = 0;
    virtual bool Is64() const = 0;

    // --- temel alanlar ---
    virtual u64  ImageBase() const = 0;
    virtual u64  ImageSize() const = 0;
    virtual u64  EntryPoint() const = 0;          // VA
    virtual const std::vector<SectionInfo>& Sections() const = 0;
    virtual const std::vector<ImportDll>&  Imports() const = 0;
    virtual const std::vector<ExportFunc>& Exports() const = 0;
    virtual const std::vector<SymbolInfo>& Symbols() const = 0;
    virtual const std::vector<RelocEntry>& Relocs() const = 0;
    virtual DebugInfo GetDebugInfo() const = 0;

    // --- dosya <-> sanal adres dönüşümleri ---
    virtual u64  RawToVa(u64 fileOffset) const = 0;
    virtual u64  VaToRaw(u64 va) const = 0;       // yoksa (u64)-1

    // --- ham dosya baytları ---
    const std::vector<u8>& Raw() const { return raw_; }
    u64 RawSize() const { return raw_.size(); }

    // --- sembol çözümü (export + COFF/ELF sembolleri birleşik) ---
    // boş dönerse "sub_XXXXXXXX" üretmek çağrıcının işi
    virtual std::string SymbolAt(u64 va) const { (void)va; return ""; }

    // --- PLT/GOT çözümü (ELF; PE boş döner) ---
    // PLT stub adresi -> "printf" gibi import adı
    virtual std::string PltName(u64 va) const { (void)va; return ""; }
    // GOT yuvası adresi -> import adı (call/jmp qword [rip+X] hedefi)
    virtual std::string GotName(u64 va) const { (void)va; return ""; }
    // import adının PLT stub adresi (0 = yok)
    virtual u64   PltVaOf(const std::string& name) const { (void)name; return 0; }

    // --- fabrika ---
    static Binary* Open(const std::string& path); // PE/ELF koklar, uygun parser döner

protected:
    std::vector<u8> raw_;
};

} // namespace gt
