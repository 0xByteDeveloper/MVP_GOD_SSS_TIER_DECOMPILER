// ============================================================================
//  i4M GodTier Engine — analysis/deepscan.cpp
// ============================================================================
#include "analysis/deepscan.h"
#include "core/log.h"
#include "core/util.h"
#include <algorithm>
#include <set>
#include <map>

namespace gt {

// ----------------------------------------------------------------------------
// Yardımcılar
// ----------------------------------------------------------------------------
bool DeepScanner::IsExecRange(u64 va) {
    for (auto& s : az_.Bin().Sections())
        if (s.executable && va >= s.va && va < s.va + s.vsize) return true;
    return false;
}

bool DeepScanner::InsideKnownFunction(u64 va) {
    // tam başlangıç ayrı değerlendirilir (FunctionStart), içeride olma kötü
    if (az_.FunctionStart(va)) return false;
    if (az_.FunctionAt(va)) return true;
    return false;
}

// Adresteki ilk komut(lar) fonksiyon prologu benziyor mu?
bool DeepScanner::LooksLikePrologue(u64 va, std::string* why) {
    auto& eng = az_.Engine();
    auto& img = az_.Image();
    u8 buf[32];
    if (!img.ReadBytes(va, buf, 32)) return false;
    Ins x;
    if (!eng.DisasmOne(buf, 32, va, x)) return false;

    // Kalıp A: endbr64 + push rbp [+ mov rbp,rsp]
    if (x.mnemonic == "endbr64") {
        Ins y;
        if (img.ReadBytes(va + x.len, buf, 32) &&
            eng.DisasmOne(buf, 32, va + x.len, y) &&
            (y.mnemonic == "push" || y.mnemonic == "sub" || y.mnemonic == "mov")) {
            if (why) *why = "endbr64 + " + y.mnemonic;
            return true;
        }
        return false;
    }
    // Kalıp B: push rbp; mov rbp, rsp
    if (x.mnemonic == "push" && x.opStr == "rbp") {
        Ins y;
        if (img.ReadBytes(va + x.len, buf, 32) &&
            eng.DisasmOne(buf, 32, va + x.len, y) &&
            y.mnemonic == "mov" && y.opStr == "rbp, rsp") {
            if (why) *why = "push rbp; mov rbp, rsp";
            return true;
        }
        return false;
    }
    // Kalıp C: push r15..r12 serisi (glibc/O2 tarzı) — en az 2 ardışık push
    static const char* big[] = {"r15", "r14", "r13", "r12", "rbx"};
    bool first = false;
    for (auto* r : big) if (x.mnemonic == "push" && x.opStr == r) first = true;
    if (first) {
        Ins y;
        if (img.ReadBytes(va + x.len, buf, 32) &&
            eng.DisasmOne(buf, 32, va + x.len, y) &&
            ((y.mnemonic == "push") ||
             (y.mnemonic == "sub" && y.opStr.rfind("rsp, ", 0) == 0))) {
            if (why) *why = x.mnemonic + " " + x.opStr + "; " + y.mnemonic;
            return true;
        }
    }
    return false;
}

// Aday gövdesi gerçekten kod mu? (geçerli çözümleme + ret/jmp bitişi + sınır)
bool DeepScanner::ValidateBody(u64 va, std::string* why, size_t* insCount) {
    auto& eng = az_.Engine();
    auto& img = az_.Image();
    u64 cur = va;
    size_t n = 0;
    bool sawRet = false, sawControl = false;
    std::string lastMn;
    for (int i = 0; i < 48 && n < 48; i++) {
        u8 buf[32];
        if (!img.ReadBytes(cur, buf, 32)) return false;
        Ins x;
        if (!eng.DisasmOne(buf, 32, cur, x) || x.len == 0) return false;
        // int3 / ud2 aniden bitirir: kod bitti say
        if (x.mnemonic == "int3" || x.mnemonic == "ud2") break;
        // içine başka fonksiyonun başına denk geldik (bilinen başlangıç)
        if (n > 0 && az_.FunctionStart(cur)) break;
        n++;
        lastMn = x.mnemonic;
        if (x.isRet) { sawRet = true; break; }
        if ((x.isJmp || x.isJcc || x.isCall) && !x.isIndirect) sawControl = true;
        cur += x.len;
    }
    if (insCount) *insCount = n;
    if (n < 3) return false;                        // çok kısa: şüpheli
    if (sawRet) {
        if (why) *why = "gecerli govde (" + std::to_string(n) + " komut, ret ile biter)";
        return true;
    }
    // ret yok ama sağlıklı kontrol akışı + sonraki adresten devam edememe:
    // sınır olarak kabul et (tail jmp / başka fonksiyona bitişik)
    if (sawControl && (lastMn == "jmp" || lastMn == "jcc" || lastMn == "call")) {
        // son komut başka bir BİLİNEN fonksiyon başına jmp ise tail-call gövdesi
        if (why) *why = "gecerli govde (" + std::to_string(n) + " komut, jmp ile biter)";
        return true;
    }
    return false;
}

// ----------------------------------------------------------------------------
// Strateji 1: prolog taraması (aggressive instruction finder muadili)
// ----------------------------------------------------------------------------
void DeepScanner::ScanPrologues(std::vector<DeepCandidate>& out) {
    auto& img = az_.Image();
    auto& eng = az_.Engine();
    // v6: prolog kalıpları x86'a özgüdür (push rbp / endbr64) — ARM'da
    // yanlış aday üretmesin; veri-referansı ve tail-call stratejileri
    // mimariden bağımsız çalışmaya devam eder.
    Arch arch = eng.GetArch();
    if (arch != Arch::X86_64 && arch != Arch::X86_32) return;
    const u64 base = az_.Image().Base();
    const u64 bd = base - az_.Bin().ImageBase();

    for (auto& sec : az_.Bin().Sections()) {
        if (!sec.executable || sec.rawSize < 16) continue;
        // PLT/GOT bölümlerini atla
        if (sec.name.find("plt") != std::string::npos ||
            sec.name.find("got") != std::string::npos)
            continue;
        u64 va = sec.va + bd;
        u64 end = va + std::min<u64>(sec.vsize, sec.rawSize);
        u8 buf[32];
        u64 cur = va;
        while (cur + 4 < end) {
            if (!img.ReadBytes(cur, buf, 32)) break;
            Ins x;
            if (!eng.DisasmOne(buf, 32, cur, x)) { cur++; continue; }
            std::string why;
            if (LooksLikePrologue(cur, &why) && !InsideKnownFunction(cur)) {
                std::string bodyWhy;
                size_t n = 0;
                if (ValidateBody(cur, &bodyWhy, &n)) {
                    DeepCandidate c;
                    c.va = cur;
                    c.strategy = "prolog";
                    c.confidence = (cur % 16 == 0) ? 75 : 55;
                    c.evidence = why + " + " + bodyWhy +
                                 (cur % 16 == 0 ? " [16-bayt hizali]" : "");
                    out.push_back(c);
                    cur += 1;   // üst üste binmeyi önle: 1'er ilerle
                    continue;
                }
            }
            cur += x.len ? x.len : 1;
        }
    }
}

// ----------------------------------------------------------------------------
// Strateji 2: veri referansları (fptr tablosu / vtable)
//   - ham dosyada qword olarak duran kod adresleri (no-pie)
//   - PIE: .rela.dyn R_X86_64_RELATIVE addend'leri
// ----------------------------------------------------------------------------
void DeepScanner::ScanDataRefs(std::vector<DeepCandidate>& out) {
    auto& img = az_.Image();
    const auto& bin = az_.Bin();
    const auto& raw = bin.Raw();
    const u64 bd = img.Base() - bin.ImageBase();

    std::map<u64, int> hits;      // va -> ekstra güven bonusu
    std::map<u64, std::string> src;

    // 2a) veri bölümlerindeki mutlak qword'lar
    for (auto& sec : bin.Sections()) {
        if (sec.executable || sec.rawSize < 8) continue;
        if (sec.name.find("got") != std::string::npos ||
            sec.name.find("plt") != std::string::npos ||
            sec.name.find("rela") != std::string::npos ||
            sec.name.find("dyn") != std::string::npos)
            continue;
        for (u64 off = sec.rawOffset; off + 8 <= sec.rawOffset + sec.rawSize; off += 8) {
            u64 v;
            memcpy(&v, &raw[(size_t)off], 8);
            if (v < bin.ImageBase() || v >= bin.ImageBase() + bin.ImageSize()) continue;
            u64 target = v + bd;
            if (IsExecRange(target) && !az_.FunctionStart(target)) {
                hits[target]++;
                src[target] = sec.name;
            }
        }
    }
    // 2b) PIE reloc addend'leri (.rela.dyn, R_X86_64_RELATIVE = 8)
    for (auto& sec : bin.Sections()) {
        if (sec.name != ".rela.dyn" || sec.rawSize < 24) continue;
        for (u64 off = sec.rawOffset; off + 24 <= sec.rawOffset + sec.rawSize; off += 24) {
            u64 rOffset, rInfo, rAddend;
            memcpy(&rOffset, &raw[(size_t)off], 8);
            memcpy(&rInfo, &raw[(size_t)off + 8], 8);
            memcpy(&rAddend, &raw[(size_t)off + 16], 8);
            u32 type = (u32)(rInfo & 0xFFFFFFFFull);
            if (type != 8 /*R_X86_64_RELATIVE*/) continue;
            u64 target = rAddend + bd;
            if (IsExecRange(target) && !az_.FunctionStart(target)) {
                hits[target] += 2;    // reloc kanıtı daha güçlü
                src[target] = ".rela.dyn (R_X86_64_RELATIVE)";
            }
        }
    }
    // değerlendir
    for (auto& [va, bonus] : hits) {
        if (InsideKnownFunction(va)) continue;
        std::string why;
        bool prologue = LooksLikePrologue(va, &why);
        std::string bodyWhy;
        size_t n = 0;
        bool valid = ValidateBody(va, &bodyWhy, &n);
        // veri referansı + prolog + geçerli gövde = çok güçlü sinyal
        if (!prologue && !valid) continue;
        DeepCandidate c;
        c.va = va;
        c.strategy = "veri-referansi";
        c.confidence = 40 + bonus * 10 + (prologue ? 20 : 0) + (valid ? 10 : 0);
        if (c.confidence > 95) c.confidence = 95;
        c.evidence = "kod adresi veri bolgesinde (" + src[va] + "), " +
                     std::to_string(hits[va]) + " referans" +
                     (prologue ? ", prolog: " + why : "") +
                     (valid ? ", " + bodyWhy : "");
        out.push_back(c);
    }
}

// ----------------------------------------------------------------------------
// Strateji 3: tail-call hedefleri
// ----------------------------------------------------------------------------
void DeepScanner::ScanTailCalls(std::vector<DeepCandidate>& out) {
    for (auto& [fva, f] : az_.Functions()) {
        auto* ins = az_.InstructionsOf(fva);
        if (!ins) continue;
        for (auto& x : *ins) {
            if (!x.isJmp || x.isIndirect) continue;
            u64 t = x.target;
            if (az_.FunctionStart(t)) continue;
            if (InsideKnownFunction(t)) continue;
            if (!IsExecRange(t)) continue;
            std::string why;
            if (!LooksLikePrologue(t, &why)) continue;
            std::string bodyWhy;
            if (!ValidateBody(t, &bodyWhy, nullptr)) continue;
            DeepCandidate c;
            c.va = t;
            c.strategy = "tail-call";
            c.confidence = 60;
            c.evidence = "jmp hedefi 0x" + ToHex(t) + " (0x" + ToHex(x.addr) +
                         " @ " + f.name + "), prolog: " + why + ", " + bodyWhy;
            out.push_back(c);
        }
    }
}

// ----------------------------------------------------------------------------
// Tarama + uygulama
// ----------------------------------------------------------------------------
std::vector<DeepCandidate> DeepScanner::Scan(bool includeWeak) {
    std::vector<DeepCandidate> out;
    ScanDataRefs(out);       // en güçlü sinyal önce (bonus'lar netleşsin)
    ScanPrologues(out);
    ScanTailCalls(out);

    // aynı VA'da en iyi skoru tut
    std::map<u64, DeepCandidate> best;
    for (auto& c : out) {
        auto it = best.find(c.va);
        if (it == best.end() || c.confidence > it->second.confidence) best[c.va] = c;
    }
    out.clear();
    for (auto& [va, c] : best) out.push_back(c);

    std::sort(out.begin(), out.end(), [](const DeepCandidate& a, const DeepCandidate& b) {
        return a.confidence > b.confidence;
    });
    if (!includeWeak) {
        std::vector<DeepCandidate> strong;
        for (auto& c : out) if (c.confidence >= 40) strong.push_back(c);
        return strong;
    }
    return out;
}

size_t DeepScanner::Apply(const std::vector<DeepCandidate>& cands, int minConfidence) {
    size_t added = 0;
    for (auto& c : cands) {
        if (c.confidence < minConfidence) continue;
        if (az_.FunctionStart(c.va) || InsideKnownFunction(c.va)) continue;
        az_.EnsureFunction(c.va, "FUN_" + ToHex(c.va, 8));
        added++;
    }
    return added;
}

} // namespace gt
