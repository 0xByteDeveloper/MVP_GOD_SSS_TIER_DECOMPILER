// ============================================================================
//  i4M GodTier Engine — format/pdb.h
//  Microsoft PDB (MSF 7.00) okuyucu — PDBX v3 çekirdeğinden uyarlandı
//  (0xByteDeveloper/PDBX: metin2client.pdb üzerinde savaşla kanıtlanmış,
//   sıfır harici bağımlılık MSF/TPI/DBI ayrıştırma).
//
//  Ne çıkarır:
//   - TPI tip kayıtları: struct/class/union ÜYELERİ (offset + tip + AD),
//     enum değerleri, fonksiyon prototipleri (arglist + calling convention)
//   - Modül sembol akışları: S_GPROC32 fonksiyonları + BP-göreli yerel
//     değişkenler/parametreler (gerçek adlarla!)
//   - PUB32/global semboller: isim <-> adres eşlemesi
//  Entegrasyon: TypeInferer DWARF gibi PDB kanıtıyla giydirme yapar
//  (ImportDebug: struct adları, imzalar, parametre adları).
// ============================================================================
#pragma once
#include "format/binary.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace gt {

// ---------------- MSF 7.00 konteyner ----------------
struct MsfStream { u32 size = 0; std::vector<u32> blocks; };
struct Msf {
    std::vector<u8> data;
    u32 blockSize = 0, numBlocks = 0;
    std::vector<MsfStream> streams;
    bool Load(const std::vector<u8>& raw, std::string& err);
    bool StreamBytes(size_t idx, std::vector<u8>& out) const;
};

// ---------------- tip kayıtları (TPI) ----------------
struct PdbMember { std::string name; i64 off = 0; u32 tidx = 0; u32 attr = 0; };
struct PdbEnumVal { std::string name; i64 val = 0; };
struct PdbTypeRec {
    u16 leaf = 0;
    std::string name;
    u64 size = 0; bool sizeKnown = false;
    u32 fieldlist = 0;
    std::vector<PdbMember> members;      // attr 0xFFFF/0xFFFE/0xFFFD = yapısal özel
    std::vector<PdbEnumVal> evals;
    u32 a = 0, b = 0;                    // pointer: hedef; array: eleman
    u32 clsType = 0, thisType = 0, arglist = 0;
    u32 rvType = 0, baseType = 0;
    u16 callconv = 0, attr16 = 0;
    u32 nparams = 0;
    u32 bitLen = 0, bitPos = 0;
    std::vector<u32> args;
    bool valid = false;
};

struct PdbLocal {
    std::string name;
    i32 off = 0x7FFFFFFF;    // ebp-göreli (arg: >= 8, local: < 8)
    u32 tidx = 0;
    bool isArg = false;
};

struct PdbFunc {
    std::string name;         // PROC kaydından (decorated olabilir)
    std::string shortName;    // Class::Metod (dekor zincirinden)
    std::string mangled;      // pub32
    u32 seg = 0, off = 0, size = 0;
    u32 tidx = 0;
    bool hasType = false;
    std::vector<PdbLocal> locals;
    // çözümlenmiş:
    u64 va = 0;
    std::string proto;        // prototip satırı
    bool isThiscall = false;
    u32 thisClassIdx = 0;
    std::vector<std::string> argNames;
};

struct PdbGlobal { std::string name; std::string mangled;
                   u32 tidx = 0; u32 seg = 0, off = 0; u64 va = 0; };

class PdbInfo {
public:
    // Dosyadan yükle (MSF konteyner + TPI + modüller + globals)
    bool Load(const std::string& path);
    bool Parse(const std::vector<u8>& raw, std::string& err);

    // PE görüntüsüne göre VA çözümü (segment no -> RVA)
    void ResolveVAs(u64 imageBase, const std::vector<SectionInfo>& secs);

    // erişim
    const std::vector<PdbFunc>& Funcs() const { return funcs_; }
    const std::vector<PdbGlobal>& Globals() const { return globals_; }
    const PdbFunc* FuncAt(u64 va) const;
    const PdbGlobal* GlobalAt(u64 va) const;
    size_t TypeCount() const { return types_.size(); }
    const PdbTypeRec* PdbTypeAt(u32 idx) const { return Type(idx); }
    std::string TypeName(u32 idx, int depth = 0) const;
    // struct tipleri: üyeleriyle birlikte (DwarfStruct formatına çevrilir)
    struct StructOut { std::string name; u64 size = 0;
                       struct M { std::string name; u64 offset = 0; u32 size = 0;
                                  std::string typeName; bool isArray = false;
                                  u64 arrayLen = 0; };
                       std::vector<M> members; };
    std::vector<StructOut> Structs() const;

    const std::string& Guid() const { return guidStr_; }
    const std::string& Error() const { return err_; }

private:
    const PdbTypeRec* Type(u32 idx) const;
    const PdbTypeRec* CompleteType(u32 idx) const;   // fwdref çözümü
    std::string FullProto(const PdbFunc& f) const;
    bool ParseTpi(const std::vector<u8>& tpi);
    void ScanModuleStream(const std::vector<u8>& buf);
    void ScanGlobalRecords(const std::vector<u8>& buf);

    Msf msf_;
    std::string guidStr_, pdbPath_, err_;
    u32 age_ = 0;
    std::map<u32, PdbTypeRec> types_;
    std::map<std::string, u32> completeByName_;
    u32 tpiBegin_ = 0x1000;
    std::vector<PdbFunc> funcs_;
    std::map<u64, size_t> funcByVa_;
    std::vector<PdbGlobal> globals_;
    std::map<u64, std::string> pubByVa_;
};

} // namespace gt
