// ============================================================================
//  i4M GodTier Engine — format/dwarf.h
//  DWARF v4/v5 debug bilgisi importu (.debug_abbrev/.debug_info/.debug_str/
//  .debug_str_offsets/.debug_line_str).
//
//  Ne çıkarır:
//   - DW_TAG_subprogram  -> fonksiyon adları + low_pc/high_pc adres aralıkları
//   - DW_TAG_structure_type / class_type / union -> GERÇEK üye adları,
//     offset'ler, tipler (field_4 yerine notlar!)
//   - DW_TAG_formal_parameter -> parametre adları + tipler (imza onayı)
//   - DW_TAG_inlined_subroutine -> inline edilmiş aralıklar (gövde notu)
//  Bunu ne için kullanır:
//   - TypeInferer: geri kazanılan struct'lara gerçek üye adlarını giydirir,
//     imzaları DWARF kanıtıyla pekiştirir (IDA+PDB / Ghidra DWARF modu gibi)
// ============================================================================
#pragma once
#include "format/binary.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace gt {

struct DwarfFunc {
    u64 lowPc = 0, highPc = 0;      // [low, high) — high offset olarak saklanır
    std::string name;               // "toplama" / "Dikdortgen::alan"
    std::string linkageName;        // mangled (_ZN...)
    bool hasRange = false;
    // imza kanıtı (varsa)
    std::string retType;
    struct Param { std::string name, typeName; u64 typeRef = (u64)-1; };
    std::vector<Param> params;
    u64 retTypeRef = (u64)-1;   // ertelenmiş tip çözümü
    bool isStatic = false;
    bool isVirtual = false;
};

struct DwarfMember {
    std::string name;               // gerçek üye adı ("notlar")
    u64 offset = 0;
    u32 byteSize = 0;               // 0 = bilinmiyor
    std::string typeName;           // "int [8]" gibi
    bool isArray = false;
    u64 arrayLen = 0;               // eleman sayısı (0 = bilinmiyor)
    u64 typeRef = (u64)-1;          // v6: ertelenmiş tip çözümü (-O2 ileri referans)
};

struct DwarfStruct {
    std::string name;               // "Ogrenci"
    u64 size = 0;
    std::vector<DwarfMember> members;
    bool isUnion = false;
    bool isClass = false;
    std::vector<std::string> bases; // v5: DW_TAG_inheritance taban sınıfları (CHA)
    std::vector<u64> baseRefs;      // v5: taban tip DIE ofsetleri (ileri ref. çözümü)
};

struct DwarfInline {
    u64 low = 0, high = 0;          // çağıran içindeki inline aralığı
    std::string funcName;           // inline EDİLEN fonksiyon adı
    u64 originRef = (u64)-1;        // abstract origin (ertelenmiş ad çözümü)
};

struct DwarfGlobal {
    std::string name;
    u64 addr = 0;                   // low_pc veya location sabiti (0 = bilinmiyor)
    std::string typeName;
};

class DwarfInfo {
public:
    // Binary'den .debug_* section'larını okur (ELF raw + section tablosu)
    bool LoadFromBinary(const Binary& bin);

    bool Valid() const { return cus_ > 0 || !funcs_.empty(); }
    const std::vector<DwarfFunc>& Funcs() const { return funcs_; }
    const std::vector<DwarfStruct>& Structs() const { return structs_; }
    const std::vector<DwarfInline>& Inlines() const { return inlines_; }
    const std::vector<DwarfGlobal>& Globals() const { return globals_; }

    // va'ya düşen (aralık içi) fonksiyon — inline aralıkları hariç
    const DwarfFunc* FuncCovering(u64 va) const;
    const DwarfStruct* StructByName(const std::string& n) const;
    const DwarfInline* InlineAt(u64 va) const;        // va bir inline aralığında mı

    // hata raporu
    const std::string& Error() const { return err_; }
    size_t CuCount() const { return cus_; }
    size_t DieCount() const { return dies_; }

private:
    bool ParseAbbrevs(const u8* p, size_t n);
    bool ParseOneCu(const u8* p, size_t n);

    // form okuyucular
    std::string ReadStrp(u64 off) const;
    std::string ReadStrx(u64 idx) const;

    std::vector<DwarfFunc> funcs_;
    std::vector<DwarfStruct> structs_;
    std::vector<DwarfInline> inlines_;
    std::vector<DwarfGlobal> globals_;
    void ResolvePendingBases();   // v5: ileri referanslı kalıtım adları (CHA)

    // tip referansları için basit tip düğüm havuzu
    struct TypeNode {
        u16 tag = 0;
        std::string name;
        u64 byteSize = 0;
        u64 typeRef = (u64)-1;      // DIE offset (uygun türlerde)
        u16 encoding = 0;           // base_type DW_AT_encoding
        u64 arrayCount = (u64)-1;   // subrange üst sınır + 1
        std::string typeName;       // çözümlenmiş (lazy)
        bool typeNameSolved = false;
    };
    std::map<u64, TypeNode> typeNodes_;     // DIE offset -> node
    std::string SolveTypeName(u64 dieOff, int depth);

    // abbrev tablosu
    struct AttrSpec { u16 at = 0, form = 0; i64 implicitConst = 0; };
    struct Abbrev { u64 code = 0; u16 tag = 0; bool hasChildren = false;
                    std::vector<AttrSpec> attrs; };
    std::map<u64, Abbrev> abbrevs_;

    // section verileri (referans, sahiplik yok)
    std::vector<u8> own_;                   // gerekirse kopya
    const u8* info_ = nullptr;  size_t infoSize_ = 0;
    const u8* str_ = nullptr;   size_t strSize_ = 0;
    const u8* strOffsets_ = nullptr; size_t strOffsetsSize_ = 0;
    const u8* lineStr_ = nullptr; size_t lineStrSize_ = 0;
    u64 strOffsetsBase_ = 8;               // DWARF5 başlık boyutu varsayımı

    // CU başına DW_AT_str_offsets_base güncellemesi için
    void SetStrOffsetsBase(u64 b) { strOffsetsBase_ = b; }

    size_t cus_ = 0, dies_ = 0;
    std::string err_;
};

} // namespace gt
