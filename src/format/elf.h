// ============================================================================
//  i4M GodTier Engine — format/elf.h
//  ELF32/ELF64 parser: header, section'lar, segment'ler, sembol tabloları
//  (.symtab + .dynsym), dinamik bilgiler, relocations.
//  İlham: LIEF çoklu format yaklaşımı + angr CLE loader dersleri.
// ============================================================================
#pragma once
#include "format/binary.h"
#include <cstring>
#include <map>

namespace gt {

class ELF final : public Binary {
public:
    bool Load(const std::string& path);

    std::string FormatName() const override;
    // v6: e_machine -> mimari (0x3E x86-64, 0xB7 AArch64, 0x28 ARM)
    Arch GetArch() const override;
    bool Is64() const override { return is64_; }

    u64  ImageBase() const override;
    u64  ImageSize() const override;
    u64  EntryPoint() const override { return entryVa_; }
    const std::vector<SectionInfo>& Sections() const override { return sections_; }
    const std::vector<ImportDll>&  Imports() const override { return imports_; }
    const std::vector<ExportFunc>& Exports() const override { return exports_; }
    const std::vector<SymbolInfo>& Symbols() const override { return symbols_; }
    const std::vector<RelocEntry>& Relocs() const override { return relocs_; }
    DebugInfo GetDebugInfo() const override { return {}; }

    u64 RawToVa(u64 off) const override;
    u64 VaToRaw(u64 va) const override;
    std::string SymbolAt(u64 va) const override;

    // PLT/GOT çözümü (importsByVa'nın ELF karşılığı)
    std::string PltName(u64 va) const override;
    std::string GotName(u64 va) const override;
    u64   PltVaOf(const std::string& name) const override;
    const std::map<u64, std::string>& PltMap() const { return pltByVa_; }

    // ELF'e özgü
    int  Type() const { return type_; }             // ET_EXEC / ET_DYN ...
    const std::string& Interpreter() const { return interp_; }
    const std::vector<std::pair<u64,u64>>& LoadSegments() const { return loadSegs_; } // (vaddr, filesz)

private:
    bool Parse();
    bool ParseSections();
    bool ParseSegments();
    bool ParseSymbols();
    bool ParseDynamic();
    bool ParsePlt();          // .rela.plt/.rela.dyn + .plt/.plt.got -> isim haritası

    bool InRaw(u64 off, u64 size) const { return off + size <= raw_.size() && off + size >= off; }
    u8   R8(u64 o)  const { return raw_[o]; }
    u16  R16(u64 o) const { u16 v; memcpy(&v, &raw_[o], 2); return v; }
    u32  R32(u64 o) const { u32 v; memcpy(&v, &raw_[o], 4); return v; }
    u64  R64(u64 o) const { u64 v; memcpy(&v, &raw_[o], 8); return v; }

    bool is64_ = true;
    u16 type_ = 0, machine_ = 0;
    u64 entryVa_ = 0;
    u64 minVaddr_ = (u64)-1, maxVaddrEnd_ = 0;
    std::string interp_;
    std::vector<SectionInfo> sections_;
    std::vector<SymbolInfo>  symbols_;
    std::vector<ImportDll>   imports_;
    std::vector<ExportFunc>  exports_;
    std::vector<RelocEntry>  relocs_;
    std::vector<std::pair<u64,u64>> loadSegs_;
    std::map<u64, std::string> pltByVa_;    // PLT stub VA -> "printf"
    std::map<u64, std::string> gotByVa_;    // GOT yuvası VA -> "printf"
    std::map<std::string, u64> pltVaByName_;
    // section header konumları
    u64 shoff_ = 0; u16 shentsize_ = 0, shnum_ = 0, shstrndx_ = 0;
};

} // namespace gt
