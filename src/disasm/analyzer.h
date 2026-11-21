// ============================================================================
//  i4M GodTier Engine — disasm/analyzer.h
//  Statik analiz kalbi:
//   - Recursive traversal disassembly (rizin/angr dersi)
//   - Fonksiyon keşfi (entry + semboller + çağrı hedefleri + prolog)
//   - Xref veritabanı (call/jmp/jcc/data)
//   - String çıkarma (ASCII + UTF-16LE) — FLOSS ruhunda emülatör destekli
//     stack-string kurtarma emulate modülüyle işbirliği içinde raporlanır.
// ============================================================================
#pragma once
#include "disasm/engine.h"
#include "format/binary.h"
#include "format/image.h"
#include <map>
#include <set>
#include <unordered_map>

namespace gt {

enum class RefType : u8 { Call, Jmp, Jcc, Data };

struct Xref {
    u64 src = 0;         // referans veren adres (komut adresi)
    u64 dst = 0;         // referans edilen adres
    RefType type = RefType::Call;
};

struct FuncInfo {
    u64 start = 0;
    u64 end = 0;                  // son komutun sonu
    std::string name;             // sembol ya da sub_XXXXXXXX
    std::vector<u64> chunks;      // (şimdilik tek blok; tail-jump'lar ayrı tutulur)
    bool fromSymbol = false;
    size_t insCount = 0;
};

struct FoundString {
    u64 va = 0;
    std::string text;
    bool wide = false;
    size_t sectionIdx = (size_t)-1;
};

class Analyzer {
public:
    Analyzer(DisasmEngine& eng, const Binary& bin, MappedImage& img)
        : eng_(eng), bin_(bin), img_(img) {}

    // Tüm analiz hattını koşar (fonksiyon bul -> disassemble -> xref -> string)
    void RunFull(bool verbose = true);

    // --- fonksiyonlar ---
    const std::map<u64, FuncInfo>& Functions() const { return funcs_; }
    const FuncInfo* FunctionAt(u64 va) const;          // içine düşülen fonksiyon
    const FuncInfo* FunctionStart(u64 va) const;       // tam başlangıç
    std::string NameFor(u64 va) const;                 // sembol/sub_/jts etiketi

    // fonksiyonu garanti et: varsa yeniden adlandır, yoksa yarat+çözümle
    // (PDB/DWARF import isimleri için)
    void EnsureFunction(u64 va, const std::string& name);

    // --- komutlar (fonksiyon bazlı saklanır) ---
    const std::vector<Ins>* InstructionsOf(u64 funcStart) const;
    std::vector<Ins> DisassembleFunction(u64 start, size_t maxIns = 20000);
    // [start, endExclusive) doğrusal çözümleme (jump-table case blokları için)
    std::vector<Ins> DisassembleLinear(u64 start, u64 endExclusive, size_t maxIns = 64);

    // --- xref ---
    const std::vector<Xref>& Xrefs() const { return xrefs_; }
    std::vector<Xref> XrefsTo(u64 dst) const;
    std::vector<Xref> XrefsFrom(u64 src) const;

    // --- string ---
    const std::vector<FoundString>& Strings() const { return strings_; }
    void ExtractStrings(size_t minLen = 5);

    // --- yardımcılar ---
    const MappedImage& Image() const { return img_; }
    const Binary& Bin() const { return bin_; }
    DisasmEngine& Engine() { return eng_; }

    std::string SymbolOrLabel(u64 va) const;           // api adı / sembol / loc_
    bool IsStringAt(u64 va, std::string* out = nullptr) const;
    size_t TotalInsCount() const { return totalIns_; }

private:
    void DiscoverFunctions();
    void AnalyzeFunction(u64 start);
    void AddXref(u64 src, u64 dst, RefType t);

    DisasmEngine& eng_;
    const Binary& bin_;
    MappedImage& img_;

    std::map<u64, FuncInfo> funcs_;
    std::unordered_map<u64, std::vector<Ins>> funcIns_;
    std::vector<Xref> xrefs_;
    std::multimap<u64, Xref> xrefsByDst_;
    std::vector<FoundString> strings_;
    std::set<u64> visited_;
    std::map<u64, std::string> importsByVa_;   // IAT yuvası -> "dll.api"
    size_t totalIns_ = 0;
    int sameRun_ = 0, padRun_ = 0;             // padding tespiti sayaçları
};

} // namespace gt
