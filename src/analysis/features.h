// ============================================================================
//  i4M GodTier Engine — analysis/features.h
//  Yetenek tespiti paketi (capa/FLOSS/YARA/PE-bear/findcrypt dersleri):
//   - imphash (Mandiant algoritması, pefile ile birebir aynı sonuç)
//   - bölüm entropisi + genel packer sezgileri (DIE tarzı)
//   - findcrypt: AES S-box, RC4 S-box başlangıcı, MD5/SHA sabitleri, CRC32
//   - davranış ipuçları: import tablosundan yetenek çıkarımı (capa-lite)
// ============================================================================
#pragma once
#include "format/binary.h"
#include "format/image.h"
#include "disasm/analyzer.h"
#include <vector>
#include <string>

namespace gt {

struct EntropyRow {
    std::string section;
    double entropy = 0;
    double percent = 0;
    std::string verdict; // "düşük/normal/şüpheli/çok şüpheli"
};

struct PackerHint {
    std::string reason;
    int weight = 0;       // toplam ağırlık => risk skoru
};

struct CryptoHit {
    u64 va = 0;
    std::string algo;     // "AES S-box", "MD5 init", "SHA-256 K[0..3]"...
    std::string section;
};

struct Capability {
    std::string name;         // "dosya sistemi erişimi"
    std::string evidence;     // "kernel32.CreateFileA, kernel32.WriteFile"
    int weight = 0;
};

class FeatureAnalyzer {
public:
    FeatureAnalyzer(const Binary& bin, const MappedImage& img) : bin_(bin), img_(img) {}

    std::string Imphash() const;

    std::vector<EntropyRow> SectionEntropies() const;
    double OverallEntropy() const;

    std::vector<PackerHint> PackerHeuristics() const;
    int PackerRisk() const;         // toplam ağırlık

    std::vector<CryptoHit> FindCryptoConstants() const;

    std::vector<Capability> Capabilities() const;

private:
    const Binary& bin_;
    const MappedImage& img_;
};

} // namespace gt
