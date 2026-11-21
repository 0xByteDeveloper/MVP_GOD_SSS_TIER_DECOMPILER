// ============================================================================
//  i4M GodTier Engine — analysis/sigs.h
//  FLIRT-tarzı imza motoru (IDA FLIRT / Ghidra FID / rizin sigdb esintisi):
//   1) Desen kuralları — rep movs/stos (memcpy/memset), strlen döngüsü,
//      bswap (htons/ntohl), rdtsc/cpuid/syscall sarmalayıcıları...
//   2) .gsig veritabanı — sembollü binary'den masked-pattern imzaları üret
//      (call rel32 + [rip+disp] baytları jokerlenir, FLIRT mantığı),
//      stripped binary'de eşleştir ve isimleri geri kazan.
//   Fark: Ghidra FID hazır veritabanı ister; burada `sig export` ile
//   KULLANICI kendi imza havuzunu tek komutla üretir.
// ============================================================================
#pragma once
#include "disasm/analyzer.h"
#include <string>
#include <vector>

namespace gt {

struct SigMatch {
    u64 funcVa = 0;
    std::string funcName;      // mevcut (sub_...) isim
    std::string libraryName;   // tanınan işlev: memcpy, memset, ...
    std::string rule;          // kanıt
    int confidence = 0;
};

class SigEngine {
public:
    explicit SigEngine(Analyzer& az) : az_(az) {}

    // Desen kuralı taraması (tüm fonksiyonlar)
    std::vector<SigMatch> RuleScan();

    // .gsig üret/eşleştir
    bool ExportGsig(const std::string& path, size_t patternBytes = 48);
    struct ImportResult {
        size_t compared = 0, matched = 0, renamed = 0;
        std::vector<std::pair<u64, std::string>> renames;
    };
    ImportResult ImportGsig(const std::string& path);

    // maskelemeli imza üretimi (test + iç kullanım)
    std::string MaskedPattern(u64 va, size_t n) const;

    // ---- v6 ----
    // lumina push: isimli fonksiyonları BİRİKİMLİ havuza ekle (isim bazlı
    // dedupe — aynı adın yeni kanıtı eskisini günceller). IDA Lumina'nın
    // yerel muadili: bilgelik dosyayla büyür, başka binary'lerde pull edilir.
    size_t PushToPool(const std::string& path, size_t patternBytes = 48);

private:
    std::string MaskInsns(u64 va, size_t n) const;
    Analyzer& az_;
};

// v6: hazır havuz altyapısı (FLIRT'in "kutudan çıktığı gibi DB" deneyimi)
struct SigPoolResult {
    std::string path;
    size_t matched = 0, renamed = 0;
};
// dizindeki tüm .gsig dosyalarını sırayla uygular (sigs/ klasörü)
std::vector<SigPoolResult> ApplySigPools(Analyzer& az, const std::string& dir);
// .gsig havuzundaki imza sayısı (sadece parse — test/istatistik)
size_t CountGsigEntries(const std::string& path);

} // namespace gt
