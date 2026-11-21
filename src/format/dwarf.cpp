// ============================================================================
//  i4M GodTier Engine — format/dwarf.cpp
//  DWARF v4/v5 ayrıştırıcı (GCC/Clang -g çıktısı). Yalnızca decompiler'ın
//  ihtiyaç duyduğu etiketler işlenir; kalan formlar atlanır (span hesaplı).
//  İlham: pyelftools DWARF yapısı + llvm-dwarfdump davranışı.
// ============================================================================
#include "format/dwarf.h"
#include "format/elf.h"
#include "core/log.h"
#include <cstring>
#include <algorithm>

namespace gt {
namespace {

// ---- LEB128 ----
u64 ReadULEB(const u8*& p, const u8* end) {
    u64 v = 0; int shift = 0;
    while (p < end) {
        u8 b = *p++;
        v |= (u64)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 63) break;
    }
    return v;
}
i64 ReadSLEB(const u8*& p, const u8* end) {
    u64 v = 0; int shift = 0; u8 b = 0;
    while (p < end) {
        b = *p++;
        v |= (u64)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
        if (shift > 63) break;
    }
    if (shift < 64 && (b & 0x40)) v |= (u64)-1 << shift;
    return (i64)v;
}

// ---- DWARF sabitleri ----
constexpr u16 DW_TAG_array_type = 0x01;
constexpr u16 DW_TAG_class_type = 0x02;
constexpr u16 DW_TAG_enumeration_type = 0x04;
constexpr u16 DW_TAG_formal_parameter = 0x05;
constexpr u16 DW_TAG_member = 0x0D;
constexpr u16 DW_TAG_pointer_type = 0x0F;
constexpr u16 DW_TAG_compile_unit = 0x11;
constexpr u16 DW_TAG_structure_type = 0x13;
constexpr u16 DW_TAG_subroutine_type = 0x15;
constexpr u16 DW_TAG_typedef = 0x16;
constexpr u16 DW_TAG_union_type = 0x17;
constexpr u16 DW_TAG_inheritance = 0x1C;
constexpr u16 DW_TAG_subrange_type = 0x21;
constexpr u16 DW_TAG_base_type = 0x24;
constexpr u16 DW_TAG_const_type = 0x26;
constexpr u16 DW_TAG_subprogram = 0x2E;
constexpr u16 DW_TAG_variable = 0x34;
constexpr u16 DW_TAG_volatile_type = 0x35;
constexpr u16 DW_TAG_inlined_subroutine = 0x1D;

constexpr u16 DW_AT_name = 0x03;
constexpr u16 DW_AT_byte_size = 0x0B;
constexpr u16 DW_AT_low_pc = 0x11;
constexpr u16 DW_AT_high_pc = 0x12;
constexpr u16 DW_AT_language = 0x13;
constexpr u16 DW_AT_upper_bound = 0x2F;
constexpr u16 DW_AT_abstract_origin = 0x31;
constexpr u16 DW_AT_count = 0x37;
constexpr u16 DW_AT_data_member_location = 0x38;
constexpr u16 DW_AT_linkage_name = 0x6E;
constexpr u16 DW_AT_type = 0x49;
constexpr u16 DW_AT_ranges = 0x55;
constexpr u16 DW_AT_str_offsets_base = 0x72;
constexpr u16 DW_AT_encoding = 0x3E;
constexpr u16 DW_AT_specification = 0x47;
constexpr u16 DW_AT_external = 0x3F;
constexpr u16 DW_AT_virtual = 0x4C;
constexpr u16 DW_AT_declaration = 0x3C;
constexpr u16 DW_AT_entry_pc = 0x46;

// formlar
constexpr u16 DW_FORM_addr = 0x01;
constexpr u16 DW_FORM_data1 = 0x0B, DW_FORM_data2 = 0x05, DW_FORM_data4 = 0x06,
              DW_FORM_data8 = 0x07;
constexpr u16 DW_FORM_string = 0x08;
constexpr u16 DW_FORM_block = 0x09, DW_FORM_block1 = 0x0A;
constexpr u16 DW_FORM_flag = 0x0C, DW_FORM_flag_present = 0x19;
constexpr u16 DW_FORM_sdata = 0x0D;
constexpr u16 DW_FORM_strp = 0x0E;
constexpr u16 DW_FORM_udata = 0x0F;
constexpr u16 DW_FORM_ref_addr = 0x10;
constexpr u16 DW_FORM_ref1 = 0x11, DW_FORM_ref2 = 0x12,
              DW_FORM_ref4 = 0x13, DW_FORM_ref8 = 0x14, DW_FORM_ref_udata = 0x15;
constexpr u16 DW_FORM_indirect = 0x16;
constexpr u16 DW_FORM_sec_offset = 0x17;
constexpr u16 DW_FORM_exprloc = 0x18;
constexpr u16 DW_FORM_line_strp = 0x1F;
constexpr u16 DW_FORM_ref_sig8 = 0x20;
constexpr u16 DW_FORM_implicit_const = 0x21;
constexpr u16 DW_FORM_loclistx = 0x22, DW_FORM_rnglistx = 0x23;
constexpr u16 DW_FORM_ref_sup4 = 0x1C, DW_FORM_ref_sup8 = 0x24;
constexpr u16 DW_FORM_strx = 0x1A, DW_FORM_strx1 = 0x25,
              DW_FORM_strx2 = 0x26, DW_FORM_strx3 = 0x27, DW_FORM_strx4 = 0x28;
constexpr u16 DW_FORM_addrx = 0x1B, DW_FORM_addrx1 = 0x29, DW_FORM_addrx2 = 0x2A,
              DW_FORM_addrx3 = 0x2B, DW_FORM_addrx4 = 0x2C;

struct FormVal {
    u64 u = 0;
    i64 s = 0;
    std::string str;
    bool isStr = false;
    bool ok = false;
};

} // anonim

// ----------------------------------------------------------------------------
// abbrev tablosu
// ----------------------------------------------------------------------------
bool DwarfInfo::ParseAbbrevs(const u8* p, size_t n) {
    abbrevs_.clear();
    const u8* end = p + n;
    while (p < end) {
        Abbrev a;
        a.code = ReadULEB(p, end);
        if (a.code == 0) break;
        a.tag = (u16)ReadULEB(p, end);
        a.hasChildren = *p++ != 0;
        while (p < end) {
            u64 at = ReadULEB(p, end);
            u64 form = ReadULEB(p, end);
            if (at == 0 && form == 0) break;
            i64 iconst = 0;
            if (form == DW_FORM_implicit_const) iconst = ReadSLEB(p, end);
            a.attrs.push_back({(u16)at, (u16)form, iconst});
        }
        abbrevs_[a.code] = std::move(a);
    }
    return !abbrevs_.empty();
}

// ----------------------------------------------------------------------------
// string tabloları
// ----------------------------------------------------------------------------
std::string DwarfInfo::ReadStrp(u64 off) const {
    if (!str_ || off >= strSize_) return "";
    size_t cap = strSize_ - (size_t)off;
    size_t len = strnlen((const char*)(str_ + off), cap);
    return std::string((const char*)(str_ + off), len);
}
std::string DwarfInfo::ReadStrx(u64 idx) const {
    if (!strOffsets_ || !str_) return "";
    u64 pos = strOffsetsBase_ + idx * 4;   // DWARF5 32-bit: 4 bayt/entry
    if (pos + 4 > strOffsetsSize_) return "";
    u32 off; memcpy(&off, strOffsets_ + pos, 4);
    return off < strSize_ ? std::string((const char*)(str_ + off)) : "";
}

// ----------------------------------------------------------------------------
// tip adı çözümleme (dolaylı referanslar)
// ----------------------------------------------------------------------------
std::string DwarfInfo::SolveTypeName(u64 dieOff, int depth) {
    if (depth > 12) return "...";
    auto it = typeNodes_.find(dieOff);
    if (it == typeNodes_.end()) return "";
    TypeNode& t = it->second;
    if (t.typeNameSolved) return t.typeName;
    t.typeNameSolved = true;    // özyineleme koruması
    std::string out;
    switch (t.tag) {
    case DW_TAG_base_type: {
        // kodlama -> C adı
        switch (t.encoding) {
        case 1: out = t.byteSize == 1 ? "char" : "int"; break;      // DW_ATE_address yok, signed
        case 4: out = "float"; break;
        case 5: out = t.byteSize == 8 ? "double" : "float"; break;  // signed
        case 6: out = "char"; break;
        case 7: out = "unsigned char"; break;
        default:
            if (t.name.empty()) out = t.byteSize == 8 ? "__int64" : "int";
            else out = t.name;
        }
        // isim varsa onu tercih et (GCC "long int" gibi doldurur)
        if (!t.name.empty()) out = t.name;
        break;
    }
    case DW_TAG_pointer_type: {
        std::string inner = t.typeRef == (u64)-1 ? "void"
                            : SolveTypeName(t.typeRef, depth + 1);
        out = inner + " *";
        break;
    }
    case DW_TAG_const_type:
        out = t.typeRef == (u64)-1 ? "const void"
              : "const " + SolveTypeName(t.typeRef, depth + 1);
        break;
    case DW_TAG_volatile_type:
        out = t.typeRef == (u64)-1 ? "volatile void"
              : SolveTypeName(t.typeRef, depth + 1);
        break;
    case DW_TAG_array_type: {
        std::string elem = t.typeRef == (u64)-1 ? "int"
                           : SolveTypeName(t.typeRef, depth + 1);
        char b[64];
        if (t.arrayCount != (u64)-1)
            snprintf(b, sizeof b, " [%llu]", (unsigned long long)t.arrayCount);
        else snprintf(b, sizeof b, "[]");
        out = elem + std::string(b);
        break;
    }
    case DW_TAG_structure_type: case DW_TAG_class_type: case DW_TAG_union_type:
        out = t.name.empty() ? "<anon>" : t.name;
        break;
    case DW_TAG_typedef: case DW_TAG_enumeration_type:
        out = t.name.empty() ? (t.typeRef == (u64)-1 ? "int"
              : SolveTypeName(t.typeRef, depth + 1)) : t.name;
        break;
    default:
        out = t.name;
    }
    t.typeName = out;
    return out;
}

// ----------------------------------------------------------------------------
// tek CU ayrıştırma
// ----------------------------------------------------------------------------
bool DwarfInfo::ParseOneCu(const u8* p, size_t n) {
    if (n < 8) return false;
    u32 unitLen; memcpy(&unitLen, p, 4);
    if (unitLen == 0xFFFFFFFF) return false;    // 64-bit DWARF: nadir, geç
    size_t cuEnd = 4 + unitLen;
    if (cuEnd > n) cuEnd = n;
    u16 version; memcpy(&version, p + 4, 2);
    if (version < 2 || version > 5) return false;
    const u8* q = p + 6;
    u8 addrSize = 8;
    if (version >= 5) {
        u8 unitType = *q++;
        addrSize = *q++;
        u64 abbrevOff; memcpy(&abbrevOff, q, 4); q += 4;    // 32-bit DWARF
        if (unitType != 1 && unitType != 4) return true;    // sadece full/partial CU
    } else {
        u64 abbrevOff; memcpy(&abbrevOff, q, 4); q += 4;
        addrSize = *q++;
    }
    (void)addrSize;
    // DIE yığını
    struct Frame {
        u16 tag; u64 off; bool hasChildren;
        // aktif toplama alanları
        std::string name, linkName;
        u64 low = 0, high = 0; bool hasLow = false;
        u64 byteSize = 0; u64 typeRef = (u64)-1;
        u64 memberOff = (u64)-1;    // data_member_location
        u64 arrayCount = (u64)-1;
        u64 origin = (u64)-1;
        bool isStatic = false, isVirtual = false, isDeclaration = false;
        DwarfStruct pendingStruct;  // üyeleri toplayan yapı
        int paramPos = 0;           // formal_parameter sırası
        DwarfFunc pendingFunc;
        std::vector<DwarfFunc::Param> pendingParams;
    };
    std::vector<Frame> stack;
    const u8* end = p + cuEnd;
    bool cuStrBaseSet = false;

    while (q < end) {
        u64 dieOff = (u64)(q - p);      // CU-göreli offset (ref4 ile uyumlu)
        u64 code = ReadULEB(q, end);
        if (code == 0) {                // null terminator: kardeş sonu
            if (!stack.empty()) {
                Frame& f = stack.back();
                // yığını kapat: tip kaydı / struct / fonksiyon derle
                auto& T = typeNodes_[f.off];
                T.tag = f.tag; T.name = f.name; T.byteSize = f.byteSize;
                T.typeRef = f.typeRef; T.arrayCount = f.arrayCount;
                if (f.tag == DW_TAG_structure_type || f.tag == DW_TAG_class_type ||
                    f.tag == DW_TAG_union_type) {
                    if (!f.pendingStruct.members.empty() && !f.name.empty()) {
                        f.pendingStruct.name = f.name;
                        f.pendingStruct.size = f.byteSize;
                        f.pendingStruct.isUnion = f.tag == DW_TAG_union_type;
                        f.pendingStruct.isClass = f.tag == DW_TAG_class_type;
                        structs_.push_back(f.pendingStruct);
                    } else if (!f.name.empty() && f.byteSize && stack.size() >= 2) {
                        // üyesiz ama adlı: yine kaydet (ileri bildirim karışsın diye en
                        // zenginini tutacağız — aynı adı iki kez ekleme)
                        bool dup = false;
                        for (auto& s : structs_)
                            if (s.name == f.name) { dup = true; break; }
                        if (!dup) {
                            DwarfStruct s;
                            s.name = f.name; s.size = f.byteSize;
                            s.isUnion = f.tag == DW_TAG_union_type;
                            s.isClass = f.tag == DW_TAG_class_type;
                            s.baseRefs = f.pendingStruct.baseRefs;   // v5: kalıtım korunur
                            s.bases = f.pendingStruct.bases;
                            structs_.push_back(s);
                        }
                    }
                }
                if (f.tag == DW_TAG_subprogram && f.hasLow && !f.name.empty()) {
                    f.pendingFunc.name = f.name;
                    f.pendingFunc.linkageName = f.linkName;
                    f.pendingFunc.lowPc = f.low;
                    f.pendingFunc.highPc = f.high;
                    f.pendingFunc.hasRange = true;
                    f.pendingFunc.isStatic = f.isStatic;
                    f.pendingFunc.isVirtual = f.isVirtual;
                    f.pendingFunc.params = f.pendingParams;
                    // dönüş tipi: kendi DW_AT_type'ı ya da specification
                    // zincirinden (definition DIE'larında tip bildirimde kalır)
                    u64 tr = f.typeRef;
                    if (tr == (u64)-1 && f.origin != (u64)-1) {
                        auto oit = typeNodes_.find(f.origin);
                        if (oit != typeNodes_.end() && oit->second.typeRef != (u64)-1)
                            tr = oit->second.typeRef;
                    }
                    f.pendingFunc.retTypeRef = tr;   // ertelenmiş çözüm
                    if (getenv("GODTIER_DW_DEBUG"))
                        std::printf("[DW-FUNC] %s [%llx,%llx) params=%zu ret=%s\n",
                                    f.pendingFunc.name.c_str(),
                                    (unsigned long long)f.pendingFunc.lowPc,
                                    (unsigned long long)f.pendingFunc.highPc,
                                    f.pendingFunc.params.size(),
                                    f.pendingFunc.retType.c_str());
                    funcs_.push_back(f.pendingFunc);
                }
                if (f.tag == DW_TAG_inlined_subroutine && f.hasLow) {
                    DwarfInline di;
                    di.low = f.low; di.high = f.high;
                    di.originRef = f.origin;   // ad çözümü ertelenir (ileri ref.)
                    if (di.low) inlines_.push_back(di);
                }
                if (f.tag == DW_TAG_variable && !f.name.empty()) {
                    DwarfGlobal g;
                    g.name = f.name;
                    g.addr = f.low;            // DW_AT_location yerine low_pc kanalı
                    g.typeName = f.typeRef == (u64)-1 ? ""
                                : SolveTypeName(f.typeRef, 0);
                    globals_.push_back(g);
                }
                stack.pop_back();
            }
            continue;
        }
        auto ait = abbrevs_.find(code);
        if (ait == abbrevs_.end()) {
            if (getenv("GODTIER_DW_DEBUG"))
                std::printf("[DW] abbrev yok: code=%llu off=%llu (cu off=%llu)\n",
                            (unsigned long long)code,
                            (unsigned long long)(q - p),
                            (unsigned long long)(p - info_));
            break;     // abbrev yok: dur (güvenli)
        }
        const Abbrev& ab = ait->second;
        Frame f;
        f.tag = ab.tag; f.off = dieOff;
        f.hasChildren = ab.hasChildren;

        // attribute'ları oku
        for (auto& as : ab.attrs) {
            FormVal v;
            u64 form = as.form;
            if (form == DW_FORM_indirect) { form = ReadULEB(q, end); }
            switch (form) {
            case DW_FORM_addr:      v.u = 0; memcpy(&v.u, q, 8); q += 8; v.ok = true; break;
            case DW_FORM_data1:     v.u = *q++; v.s = (i8)v.u; v.ok = true; break;
            case DW_FORM_data2:     memcpy(&v.u, q, 2); q += 2; v.s = (i16)v.u; v.ok = true; break;
            case DW_FORM_data4:     memcpy(&v.u, q, 4); q += 4; v.s = (i32)v.u; v.ok = true; break;
            case DW_FORM_data8:     memcpy(&v.u, q, 8); q += 8; v.s = (i64)v.u; v.ok = true; break;
            case DW_FORM_string:    v.str = (const char*)q; q += v.str.size() + 1;
                                    v.isStr = true; v.ok = true; break;
            case DW_FORM_strp: {    u64 o = 0; memcpy(&o, q, 4); q += 4;
                                    v.str = ReadStrp(o); v.isStr = true; v.ok = true; break; }
            case DW_FORM_line_strp: { u64 o = 0; memcpy(&o, q, 4); q += 4;
                                    if (lineStr_ && o < lineStrSize_)
                                        v.str = (const char*)(lineStr_ + o);
                                    v.isStr = true; v.ok = true; break; }
            case DW_FORM_strx: {    u64 ix = ReadULEB(q, end);
                                    v.str = ReadStrx(ix); v.isStr = true; v.ok = true; break; }
            case DW_FORM_strx1:     v.str = ReadStrx(*q++); v.isStr = true; v.ok = true; break;
            case DW_FORM_strx2: {   u16 ix; memcpy(&ix, q, 2); q += 2;
                                    v.str = ReadStrx(ix); v.isStr = true; v.ok = true; break; }
            case DW_FORM_strx3: {   u32 ix = 0; memcpy(&ix, q, 3); q += 3;
                                    v.str = ReadStrx(ix); v.isStr = true; v.ok = true; break; }
            case DW_FORM_strx4: {   u32 ix; memcpy(&ix, q, 4); q += 4;
                                    v.str = ReadStrx(ix); v.isStr = true; v.ok = true; break; }
            case DW_FORM_ref1:      v.u = *q++; v.ok = true; break;
            case DW_FORM_ref2:      memcpy(&v.u, q, 2); q += 2; v.ok = true; break;
            case DW_FORM_ref4:      memcpy(&v.u, q, 4); q += 4; v.ok = true; break;
            case DW_FORM_ref8:      memcpy(&v.u, q, 8); q += 8; v.ok = true; break;
            case DW_FORM_ref_udata: v.u = ReadULEB(q, end); v.ok = true; break;
            case DW_FORM_ref_addr:  memcpy(&v.u, q, 4); q += 4; v.ok = true; break;
            case DW_FORM_sec_offset: memcpy(&v.u, q, 4); q += 4; v.ok = true; break;
            case DW_FORM_sdata:     v.s = ReadSLEB(q, end); v.u = (u64)v.s; v.ok = true; break;
            case DW_FORM_udata:     v.u = ReadULEB(q, end); v.s = (i64)v.u; v.ok = true; break;
            case DW_FORM_exprloc: case DW_FORM_block: {
                u64 len = ReadULEB(q, end);
                if (q + len > end) { q = end; } else {
                    // DW_OP_plus_uconst (0x23) + ULEB: member offset kanalı
                    if (len >= 2 && q[0] == 0x23) {
                        const u8* q2 = q + 1;
                        v.u = ReadULEB(q2, q + len); v.s = (i64)v.u; v.ok = true;
                    }
                    q += len;
                }
                break;
            }
            case DW_FORM_block1: {  u8 len = *q++;
                                    if (q + len <= end) {
                                        if (len >= 2 && q[0] == 0x23) {
                                            const u8* q2 = q + 1;
                                            v.u = ReadULEB(q2, q + len);
                                            v.s = (i64)v.u; v.ok = true;
                                        }
                                    }
                                    q += len; break; }
            case DW_FORM_flag:      v.u = *q++; v.ok = true; break;
            case DW_FORM_flag_present: v.u = 1; v.ok = true; break;
            case DW_FORM_ref_sig8:  q += 8; break;
            case DW_FORM_rnglistx: case DW_FORM_loclistx: ReadULEB(q, end); break;
            case DW_FORM_implicit_const:   // değer abbrev tablosunda: DIE'da 0 bayt
                v.u = (u64)as.implicitConst; v.s = as.implicitConst; v.ok = true; break;
            case DW_FORM_addrx:     ReadULEB(q, end); break;
            case DW_FORM_addrx1:    q += 1; break;
            case DW_FORM_addrx2:    q += 2; break;
            case DW_FORM_addrx3:    q += 3; break;
            case DW_FORM_addrx4:    q += 4; break;
            case DW_FORM_ref_sup4: case DW_FORM_ref_sup8: q += (form == DW_FORM_ref_sup4 ? 4 : 8); break;
            default:                q = end; break;    // bilinmeyen: pes
            }
            if (v.ok) {
                switch (as.at) {
                case DW_AT_name:           if (v.isStr) f.name = v.str; break;
                case DW_AT_linkage_name:   if (v.isStr) f.linkName = v.str; break;
                case DW_AT_low_pc:         f.low = v.u; f.hasLow = true; break;
                case DW_AT_entry_pc:       // inline DIE: ranges yerine giriş adresi
                    if (!f.hasLow) { f.low = v.u; f.hasLow = true; }
                    break;
                case DW_AT_high_pc:        f.high = v.u; break;   // offset (v4+) ya da adres
                case DW_AT_byte_size:      f.byteSize = v.u; break;
                case DW_AT_type:           f.typeRef = v.u; break;
                case DW_AT_data_member_location: f.memberOff = v.u; break;
                case DW_AT_upper_bound:    f.arrayCount = v.u + 1; break;
                case DW_AT_count:          f.arrayCount = v.u; break;
                case DW_AT_abstract_origin: f.origin = v.u; break;
                case DW_AT_specification:  f.origin = v.u; break;
                case DW_AT_str_offsets_base: strOffsetsBase_ = v.u; break;
                case DW_AT_encoding:
                    if (f.tag == DW_TAG_base_type) typeNodes_[dieOff].encoding = (u16)v.u;
                    break;
                case DW_AT_external:  f.isStatic = !v.u; break;
                case DW_AT_virtual:   f.isVirtual = true; break;
                case DW_AT_declaration: f.isDeclaration = true; break;
                default: break;
                }
            }
        }
        // tag'e özel işleme
        if (f.tag == DW_TAG_subprogram) {
            // isim yoksa abstract_origin'dan çöz (inline/duplicate DIE'ler)
            if (f.name.empty() && f.origin != (u64)-1) {
                auto oit = typeNodes_.find(f.origin);
                if (oit != typeNodes_.end()) f.name = oit->second.name;
            }
        }
        if (f.tag == DW_TAG_inlined_subroutine && f.origin != (u64)-1) {
            auto oit = typeNodes_.find(f.origin);
            if (oit != typeNodes_.end()) f.name = oit->second.name;
        }
        // tip düğümüne ad/boyut yaz (SolveTypeName için)
        if (f.tag == DW_TAG_base_type || f.tag == DW_TAG_pointer_type ||
            f.tag == DW_TAG_structure_type || f.tag == DW_TAG_class_type ||
            f.tag == DW_TAG_union_type || f.tag == DW_TAG_array_type ||
            f.tag == DW_TAG_typedef || f.tag == DW_TAG_const_type ||
            f.tag == DW_TAG_volatile_type || f.tag == DW_TAG_enumeration_type) {
            // array'in eleman tipi: typeRef zaten f.typeRef'ta
        }
        {
            auto& T = typeNodes_[dieOff];
            T.tag = f.tag; T.name = f.name; T.byteSize = f.byteSize;
            T.typeRef = f.typeRef; T.arrayCount = f.arrayCount;
        }

        if (getenv("GODTIER_DW_DEBUG") && dies_ < 40)
            std::printf("[DW] DIE %llu off=%llu tag=%x name=%s\n",
                        (unsigned long long)dies_, (unsigned long long)dieOff,
                        f.tag, f.name.c_str());
        dies_++;
        if (f.hasChildren) {
            stack.push_back(std::move(f));
        } else {
            // yapraksız DIE: hemen derle
            // (struct üyesi / parametre / subrange çocuksuzdur)
            if (!stack.empty()) {
                Frame& parent = stack.back();
                if (f.tag == DW_TAG_member && !f.name.empty()) {
                    DwarfMember m;
                    m.name = f.name;
                    m.offset = f.memberOff == (u64)-1 ? 0 : f.memberOff;
                    // v6: tip çözümü ERTELENİR — -O2 DWARF'ında struct, taban
                    // tiplerden ÖNCE gelir (notlar -> <0x8d7> ileri referans);
                    // parse anında çözülürse "int"e düşer. typeRef saklanır,
                    // CU'lar bittikten sonra çözülür (parametrelerdeki muadili).
                    m.typeRef = f.typeRef;
                    m.typeName = f.typeRef == (u64)-1 ? "int" : SolveTypeName(f.typeRef, 0);
                    if (m.typeRef == (u64)-1 && m.typeName.empty()) m.typeName = "int";
                    if (!m.typeName.empty() && m.typeName.back() == ']') {
                        m.isArray = true;
                        // "int [8]" -> uzunluk
                        size_t ob = m.typeName.rfind('[');
                        if (ob != std::string::npos)
                            m.arrayLen = strtoull(m.typeName.c_str() + ob + 1, 0, 10);
                    }
                    // boyut tahmini: pointer 8, taban tipler byteSize
                    if (f.typeRef != (u64)-1) {
                        auto tt = typeNodes_.find(f.typeRef);
                        if (tt != typeNodes_.end()) m.byteSize = (u32)tt->second.byteSize;
                    }
                    parent.pendingStruct.members.push_back(std::move(m));
                }
                if (f.tag == DW_TAG_inheritance && parent.tag != DW_TAG_subprogram) {
                    // kalıtım: taban sınıfın üyelerini başa kopyala (aynı offset'lerle)
                    if (f.typeRef != (u64)-1) {
                        std::string bn = SolveTypeName(f.typeRef, 0);
                        if (!bn.empty() && bn.back() == '*') bn.pop_back();
                        while (!bn.empty() && bn.back() == ' ') bn.pop_back();
                        // v5: taban tip DIE referansı ERTELENMİŞ çözüm için kaydedilir
                        // (ileri referans: Kopek DIE'si Hayvan'dan ÖNCE gelebilir)
                        parent.pendingStruct.baseRefs.push_back(f.typeRef);
                        bool known = false;
                        for (auto& b : parent.pendingStruct.bases)
                            if (b == bn) known = true;
                        if (!bn.empty() && !known)
                            parent.pendingStruct.bases.push_back(bn);
                        for (auto& s : structs_) {
                            if (s.size && s.name.empty()) continue;
                            // taban tipinin adını çöz
                            if (!bn.empty() && s.name == bn) {
                                for (auto& m : s.members)
                                    parent.pendingStruct.members.push_back(m);
                                break;
                            }
                        }
                    }
                }
                if (f.tag == DW_TAG_formal_parameter && parent.tag == DW_TAG_subprogram) {
                    DwarfFunc::Param prm;
                    prm.name = f.name.empty() ? ("a" + std::to_string(parent.paramPos + 1)) : f.name;
                    prm.typeRef = f.typeRef;   // tip ÇÖZÜMÜ ertelenir (ileri ref.)
                    parent.pendingParams.push_back(prm);
                    parent.paramPos++;
                }
                if (f.tag == DW_TAG_subrange_type && parent.tag == DW_TAG_array_type) {
                    if (f.arrayCount != (u64)-1) parent.arrayCount = f.arrayCount;
                }
                if (f.tag == DW_TAG_subprogram && f.hasLow && !f.name.empty()) {
                    // static çocuksuz subprogram (nadir)
                    DwarfFunc df;
                    df.name = f.name; df.linkageName = f.linkName;
                    df.lowPc = f.low; df.highPc = f.high; df.hasRange = true;
                    funcs_.push_back(df);
                }
            } else if (f.tag == DW_TAG_subprogram && f.hasLow && !f.name.empty()) {
                DwarfFunc df;
                df.name = f.name; df.lowPc = f.low; df.highPc = f.high; df.hasRange = true;
                df.retTypeRef = f.typeRef;   // ertelenmiş çözüm
                funcs_.push_back(df);
            }
        }
    }
    return true;
}

// ----------------------------------------------------------------------------
// Binary'den yükleme
// ----------------------------------------------------------------------------
bool DwarfInfo::LoadFromBinary(const Binary& bin) {
    // .debug_* section verilerini topla
    struct SecView { const u8* p = nullptr; size_t n = 0; };
    SecView info, abbrev, str, strOff, lineStr;
    const std::vector<u8>& raw = bin.Raw();
    const u8* rawPtr = raw.data();
    size_t rawSize = raw.size();
    if (!rawPtr) { err_ = "binary ham veri sunmuyor"; return false; }
    for (auto& s : bin.Sections()) {
        if (s.name == ".debug_info" && s.rawSize) info = {rawPtr + s.rawOffset, (size_t)s.rawSize};
        else if (s.name == ".debug_abbrev" && s.rawSize) abbrev = {rawPtr + s.rawOffset, (size_t)s.rawSize};
        else if (s.name == ".debug_str" && s.rawSize) str = {rawPtr + s.rawOffset, (size_t)s.rawSize};
        else if (s.name == ".debug_str_offsets" && s.rawSize) strOff = {rawPtr + s.rawOffset, (size_t)s.rawSize};
        else if (s.name == ".debug_line_str" && s.rawSize) lineStr = {rawPtr + s.rawOffset, (size_t)s.rawSize};
    }
    if (!info.p || !abbrev.p) { err_ = ".debug_info/.debug_abbrev yok (strip'li veya -g'siz)"; return false; }
    info_ = info.p; infoSize_ = info.n;
    str_ = str.p; strSize_ = str.n;
    strOffsets_ = strOff.p; strOffsetsSize_ = strOff.n;
    lineStr_ = lineStr.p; lineStrSize_ = lineStr.n;

    if (!ParseAbbrevs(abbrev.p, abbrev.n)) { err_ = ".debug_abbrev bos/bozuk"; return false; }

    // CU döngüsü (abbrev offset tek tablo — GCC/Clang ortak kullanır)
    size_t off = 0;
    while (off + 8 <= infoSize_) {
        u32 ulen; memcpy(&ulen, info_ + off, 4);
        if (ulen == 0 || ulen == 0xFFFFFFFF) break;
        size_t cuLen = 4 + ulen;
        if (off + cuLen > infoSize_) break;
        ParseOneCu(info_ + off, cuLen);
        cus_++;
        off += cuLen;
    }
    // high_pc offset ise low'a ekle (DWARF4+)
    for (auto& f : funcs_) {
        if (f.hasRange && f.highPc && f.highPc <= f.lowPc) f.highPc += f.lowPc;
        // ertelenmiş tip çözümleri (ileri referanslar artık çözülebilir)
        if (f.retTypeRef != (u64)-1) f.retType = SolveTypeName(f.retTypeRef, 0);
        for (auto& p : f.params)
            if (p.typeRef != (u64)-1) p.typeName = SolveTypeName(p.typeRef, 0);
    }
    // v6: struct ÜYE tiplerinin ertelenmiş çözümü — -O2'de struct tiplerden
    // önce gelir; parse anında çözülemeyenler ("int" kalanlar) burada gerçek
    // tip adlarını alır (int [8], float, char [24] ...)
    for (auto& s : structs_) {
        for (auto& m : s.members) {
            if (m.typeRef == (u64)-1) continue;
            std::string tn = SolveTypeName(m.typeRef, 0);
            if (tn.empty()) continue;
            // yalnız KAZANÇ varsa güncelle: parse anında çözülmüş gerçek adı
            // bozma ("int" kalıntısı -> çöz; "float" gibi doğru ad -> dokunma)
            if (m.typeName == "int" || m.typeName.empty() ||
                (m.isArray && m.typeName.back() == ']' && tn.find('[') == std::string::npos)) {
                m.typeName = tn;
                m.isArray = false;
                m.arrayLen = 0;
                if (!tn.empty() && tn.back() == ']') {
                    m.isArray = true;
                    size_t ob = tn.rfind('[');
                    if (ob != std::string::npos)
                        m.arrayLen = strtoull(tn.c_str() + ob + 1, 0, 10);
                }
            }
        }
    }
    // inline aralıkları: origin adları (ileri ref.) + high offset düzeltmesi
    for (auto& di : inlines_) {
        if (di.originRef != (u64)-1) {
            auto oit = typeNodes_.find(di.originRef);
            if (oit != typeNodes_.end()) di.funcName = oit->second.name;
        }
        if (di.high && di.high <= di.low) di.high += di.low;
    }
    LogInfo("DWARF: %zu CU, %zu DIE, %zu fonksiyon, %zu struct, %zu inline, %zu global",
            cus_, dies_, funcs_.size(), structs_.size(), inlines_.size(), globals_.size());
    ResolvePendingBases();   // v5: ileri referanslı kalıtım adlarını çöz (CHA)
    return Valid();
}

// v5: DW_TAG_inheritance tip referanslarını (DIE ofseti) sınıf adlarına çöz.
// Kopek DIE'si Hayvan'dan ÖNCE geldiğinde eagerly çözülemeyen adlar burada
// tamamlanır — devirtualizasyonun CHA grafiği buna bağlı.
void DwarfInfo::ResolvePendingBases() {
    for (auto& s : structs_) {
        if (s.baseRefs.empty()) continue;
        for (u64 ref : s.baseRefs) {
            auto it = typeNodes_.find(ref);
            if (it == typeNodes_.end()) continue;
            std::string bn = it->second.name;
            if (bn.empty()) bn = SolveTypeName(ref, 0);
            if (!bn.empty() && bn.back() == '*') bn.pop_back();
            while (!bn.empty() && bn.back() == ' ') bn.pop_back();
            if (bn.empty()) continue;
            bool known = false;
            for (auto& b : s.bases)
                if (b == bn) known = true;
            if (!known) s.bases.push_back(bn);
        }
        s.baseRefs.clear();
    }
}

const DwarfFunc* DwarfInfo::FuncCovering(u64 va) const {
    const DwarfFunc* best = nullptr;
    for (auto& f : funcs_) {
        if (!f.hasRange) continue;
        if (va >= f.lowPc && va < f.highPc) {
            // en dar aralık kazanır (inline edilenler hariç tutulur: aynı aralık)
            if (!best || (f.highPc - f.lowPc) < (best->highPc - best->lowPc)) best = &f;
        }
    }
    return best;
}

const DwarfStruct* DwarfInfo::StructByName(const std::string& n) const {
    const DwarfStruct* best = nullptr;
    for (auto& s : structs_)
        if (s.name == n && (!best || s.members.size() > best->members.size())) best = &s;
    return best;
}

const DwarfInline* DwarfInfo::InlineAt(u64 va) const {
    for (auto& i : inlines_)
        if (va >= i.low && va < i.high) return &i;
    return nullptr;
}

} // namespace gt
