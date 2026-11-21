// ============================================================================
//  i4M GodTier Engine — analysis/deepscan.h
//  Derin fonksiyon keşfi (Ghidra "aggressive instruction finder" üstü):
//   Strateji 1 — PROLOG taraması: endbr64 / push rbp;mov rbp,rsp / push r15..
//                kalıplarını tüm çalıştırılabilir bölgede tara, adayı doğrula
//                (geçerli çözümleme + ret/jmp bitişi + içine xref yok).
//   Strateji 2 — VERİ REFERANSI: .data/.rodata/.data.rel.ro içindeki fptr
//                qword'ları + PIE R_X86_64_RELATIVE reloc addend'leri
//                (vtable / fonksiyon tablosu) -> kod işaret eden girişler.
//   Strateji 3 — TAIL-CALL: bilinen fonksiyonlardan dışarı atlayan jmp'ler
//                prolog doğrulamasıyla.
//  Her aday güven skoru (0-100) + kanıt zinciri ile döner.
// ============================================================================
#pragma once
#include "disasm/analyzer.h"
#include <string>
#include <vector>

namespace gt {

struct DeepCandidate {
    u64 va = 0;
    int confidence = 0;          // 0-100
    std::string strategy;        // "prolog" / "veri-referansi" / "tail-call"
    std::string evidence;        // insan-okur kanıt
};

class DeepScanner {
public:
    explicit DeepScanner(Analyzer& az) : az_(az) {}

    // Tüm stratejileri koş. includeWeak=false -> yalnız güvenilir (>=40) adaylar.
    std::vector<DeepCandidate> Scan(bool includeWeak = false);

    // Adayları analiz veritabanına ekle (FUN_XXXXXXXX isimlendirme — Ghidra
    // geleneği). Yeni eklenen sayısını döndürür.
    size_t Apply(const std::vector<DeepCandidate>& cands, int minConfidence = 50);

private:
    bool LooksLikePrologue(u64 va, std::string* why);
    bool ValidateBody(u64 va, std::string* why, size_t* insCount);
    bool InsideKnownFunction(u64 va);
    bool IsExecRange(u64 va);
    void ScanPrologues(std::vector<DeepCandidate>& out);
    void ScanDataRefs(std::vector<DeepCandidate>& out);
    void ScanTailCalls(std::vector<DeepCandidate>& out);

    Analyzer& az_;
};

} // namespace gt
