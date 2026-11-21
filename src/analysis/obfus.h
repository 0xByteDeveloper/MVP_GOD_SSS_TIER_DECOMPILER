// ============================================================================
//  i4M GodTier Engine — analysis/obfus.h
//  Obfuscation / packer / anti-analiz raporu (DIE + ABD dersi esintisi):
//   - Shannon entropisi + packer bölüm imzaları (features.cpp ile ortak)
//   - OPAQUE PREDICATE taraması: xor R,R / mov R,imm + test/cmp + jcc
//     (decompiler bu koşulları sabite katlayıp ölü kodu budar — pseudocode v4)
//   - Anti-analiz: IsDebuggerPresent vb. importlar, rdtsc/cpuid
//   - Junk/sled yoğunluğu
//  Çıktı: ağırlıklı risk skoru + insan-okur gerekçeli karar.
// ============================================================================
#pragma once
#include "analysis/features.h"
#include "disasm/analyzer.h"
#include <string>
#include <vector>

namespace gt {

struct OpaqueHit {
    u64 funcVa = 0;
    std::string funcName;
    u64 insAddr = 0;
    std::string pattern;    // "xor r12d,r12d; test r12d,r12d" gibi
    std::string note;       // "daima 0 -> dallanma sabit" gibi
};

struct ObfusReport {
    // bölüm entropisi
    std::vector<EntropyRow> entropies;
    std::vector<PackerHint> packerHints;
    // opaque predicate'ler
    std::vector<OpaqueHit> opaque;
    // anti-analiz kanıtları
    std::vector<std::string> antiAnalysis;
    // junk yoğunluğu
    size_t junkRuns = 0;
    // karar
    int risk = 0;
    std::string verdict;    // TEMIZ / SUPHELI / YUKSEK RISK / KRITIK
};

class ObfusAnalyzer {
public:
    ObfusAnalyzer(const Binary& bin, MappedImage& img, const Analyzer* az = nullptr)
        : feats_(bin, img), bin_(bin), az_(az) {}

    ObfusReport Run();

private:
    void ScanOpaquePredicates(ObfusReport& rep);
    void ScanAntiAnalysis(ObfusReport& rep);
    void ScanJunk(ObfusReport& rep);

    FeatureAnalyzer feats_;
    const Binary& bin_;
    const Analyzer* az_;
};

} // namespace gt
