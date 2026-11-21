// ============================================================================
//  i4M GodTier Engine — format/pe.h
//  Tam özellikli PE32/PE32+ parser.
//  İçerik: DOS/NT header, section'lar, import (bound dahil tespit), export,
//  base relocation, TLS dizini, debug dizini (PDB GUID+path tespiti — IDA/
//  Ghidra'nın "PDB'siz kalmaz" dedikleri yer burası), rich header,
//  COFF sembol tablosu (MinGW üretimlerinde fonksiyon isimleri!).
// ============================================================================
#pragma once
#include "format/binary.h"
#include <cstring>

namespace gt {

class PE final : public Binary {
public:
    bool Load(const std::string& path);

    std::string FormatName() const override;
    Arch GetArch() const override { return is64_ ? Arch::X86_64 : Arch::X86_32; }
    bool Is64() const override { return is64_; }

    u64  ImageBase() const override { return imageBase_; }
    u64  ImageSize() const override { return imageSize_; }
    u64  EntryPoint() const override { return imageBase_ + entryRva_; }
    const std::vector<SectionInfo>& Sections() const override { return sections_; }
    const std::vector<ImportDll>&  Imports() const override { return imports_; }
    const std::vector<ExportFunc>& Exports() const override { return exports_; }
    const std::vector<SymbolInfo>& Symbols() const override { return symbols_; }
    const std::vector<RelocEntry>& Relocs() const override { return relocs_; }
    DebugInfo GetDebugInfo() const override { return debug_; }

    u64 RawToVa(u64 off) const override;
    u64 VaToRaw(u64 va) const override;

    std::string SymbolAt(u64 va) const override;

    // --- PE'ye özgü ekstralar ---
    u16  Machine() const { return machine_; }
    u16  DllCharacteristics() const { return dllChars_; }
    u32  Checksum() const { return checksum_; }
    u16  Subsystem() const { return subsystem_; }
    u64  Timestamp() const { return timestamp_; }
    bool HasRelocs() const { return !relocs_.empty(); }
    bool IsDll() const { return characteristics_ & 0x2000; }

    // Rich header (MSVC derleyici geçmişi) — PE-bear dersi
    struct RichEntry { u16 id, build; u32 count; };
    const std::vector<RichEntry>& RichHeader() const { return rich_; }

    // TLS dizini
    bool HasTLS() const { return hasTls_; }
    u64  TlsCallbacksVa() const { return tlsCallbacksVa_; }

    const std::vector<std::string>& DelayDlls() const { return delayDlls_; }

private:
    bool Parse();
    bool ParseSections();
    bool ParseImports();
    bool ParseExports();
    bool ParseRelocs();
    bool ParseDebug();
    bool ParseTLS();
    bool ParseRich();
    bool ParseCoffSymbols();

    // dosya okuma yardımcıları (raw_ üzerinde, taşma güvenli)
    bool InRaw(u64 off, u64 size) const { return off + size <= raw_.size() && off + size >= off; }
    u8   R8(u64 o)  const { return raw_[o]; }
    u16  R16(u64 o) const { u16 v; memcpy(&v, &raw_[o], 2); return v; }
    u32  R32(u64 o) const { u32 v; memcpy(&v, &raw_[o], 4); return v; }
    u64  R64(u64 o) const { u64 v; memcpy(&v, &raw_[o], 8); return v; }
    std::string RStr(u64 o, u64 maxLen = 4096) const;     // null-terminated
    std::string RStrRva(u32 rva, u64 maxLen = 4096) const;

    u32 RvaToOffset(u32 rva) const;

    u16  machine_ = 0, dllChars_ = 0, subsystem_ = 0, numSections_ = 0;
    u32  entryRva_ = 0, checksum_ = 0, characteristics_ = 0;
    u64  imageBase_ = 0, imageSize_ = 0, timestamp_ = 0, headersSize_ = 0;
    u32  importDirRva_ = 0, importDirSize_ = 0;
    u32  exportDirRva_ = 0, exportDirSize_ = 0;
    u32  relocDirRva_ = 0, relocDirSize_ = 0;
    u32  debugDirRva_ = 0, debugDirSize_ = 0;
    u32  tlsDirRva_ = 0, tlsDirSize_ = 0;
    u32  delayDirRva_ = 0, delayDirSize_ = 0;
    bool is64_ = false, hasTls_ = false;
    u64  tlsCallbacksVa_ = 0;
    u64  coffSymPtr_ = 0; u32 coffSymCount_ = 0, coffStrPtr_ = 0;

    std::vector<SectionInfo> sections_;
    std::vector<ImportDll>   imports_;
    std::vector<ExportFunc>  exports_;
    std::vector<SymbolInfo>  symbols_;
    std::vector<RelocEntry>  relocs_;
    std::vector<RichEntry>   rich_;
    std::vector<std::string> delayDlls_;
    DebugInfo debug_;
};

} // namespace gt
