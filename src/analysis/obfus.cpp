// ============================================================================
//  i4M GodTier Engine — analysis/obfus.cpp
// ============================================================================
#include "analysis/obfus.h"
#include "core/log.h"
#include "core/util.h"
#include <algorithm>
#include <cctype>

namespace gt {

// yerel yardımcılar (pseudocode.cpp'deki SplitOps/IsRegTok ile aynı kural)
static std::vector<std::string> SplitOpsSimple(const std::string& s) {
    std::vector<std::string> out;
    std::string cur; int depth = 0;
    for (char c : s) {
        if (c == '[') depth++;
        if (c == ']') depth--;
        if (c == ',' && depth == 0) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    for (auto& x : out) {
        // kırp
        size_t a = x.find_first_not_of(" \t");
        size_t b = x.find_last_not_of(" \t");
        x = (a == std::string::npos) ? "" : x.substr(a, b - a + 1);
    }
    return out;
}
static bool IsRegName(const std::string& s) {
    if (s.empty() || s.find(' ') != std::string::npos || s.find('[') != std::string::npos)
        return false;
    if (s.size() > 5) return false;
    for (char c : s)
        if (!islower((unsigned char)c) && !isdigit((unsigned char)c)) return false;
    return s[0] >= 'a' && s[0] <= 'z';
}
static bool IsNum(const std::string& s) {
    if (s.empty()) return false;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0)
        return s.size() > 2 && s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
    return s.find_first_not_of("0123456789") == std::string::npos;
}

void ObfusAnalyzer::ScanOpaquePredicates(ObfusReport& rep) {
    if (!az_) return;
    for (auto& [fva, f] : az_->Functions()) {
        auto* ins = az_->InstructionsOf(fva);
        if (!ins || ins->empty()) continue;
        for (size_t i = 0; i < ins->size(); i++) {
            const Ins& x = (*ins)[i];
            auto ops = SplitOpsSimple(x.opStr);
            // P1 (sıkı): xor R,R; test R,R; jcc  — klasik opak öncül zinciri
            if (x.mnemonic == "xor" && ops.size() == 2 && ops[0] == ops[1] &&
                i + 2 < ins->size()) {
                const Ins& t = (*ins)[i + 1];
                const Ins& j = (*ins)[i + 2];
                auto tops = SplitOpsSimple(t.opStr);
                if (t.mnemonic == "test" && tops.size() == 2 && tops[0] == ops[0] &&
                    tops[1] == ops[0] && j.isJcc) {
                    OpaqueHit h;
                    h.funcVa = fva;
                    h.funcName = f.name;
                    h.insAddr = x.addr;
                    h.pattern = "xor " + x.opStr + "; test " + t.opStr + "; " + j.mnemonic;
                    h.note = "register daima 0 — dallanma sonucu sabit (olum kod)";
                    rep.opaque.push_back(h);
                }
            }
            // P2 (sıkı): mov R,K1; cmp R,K2 (K1!=K2); jcc — sabit karşılaştırma
            if (x.mnemonic == "mov" && ops.size() == 2 && IsRegName(ops[0]) &&
                IsNum(ops[1])) {
                for (size_t j = i + 1; j < ins->size() && j <= i + 2; j++) {
                    const Ins& y = (*ins)[j];
                    auto ops2 = SplitOpsSimple(y.opStr);
                    if (y.mnemonic == "cmp" && ops2.size() == 2 && ops2[0] == ops[0] &&
                        IsNum(ops2[1]) && ops2[1] != ops[1] &&
                        j + 1 < ins->size() && (*ins)[j + 1].isJcc) {
                        OpaqueHit h;
                        h.funcVa = fva;
                        h.funcName = f.name;
                        h.insAddr = y.addr;
                        h.pattern = "mov " + ops[0] + "," + ops[1] + "; cmp " + y.opStr;
                        h.note = "iki sabitin karsilastirmasi — dallanma sonucu sabit";
                        rep.opaque.push_back(h);
                        break;
                    }
                    if (y.mnemonic == "mov" || y.mnemonic == "lea" ||
                        y.mnemonic == "xor") break;  // R değişti
                }
            }
            // P3 (sıkı): and R,0; test R,R; jcc
            if (x.mnemonic == "and" && ops.size() == 2 && ops[1] == "0" &&
                IsRegName(ops[0]) && i + 2 < ins->size()) {
                const Ins& t = (*ins)[i + 1];
                const Ins& j = (*ins)[i + 2];
                auto tops = SplitOpsSimple(t.opStr);
                if (t.mnemonic == "test" && tops.size() == 2 && tops[0] == ops[0] &&
                    tops[1] == ops[0] && j.isJcc) {
                    OpaqueHit h;
                    h.funcVa = fva;
                    h.funcName = f.name;
                    h.insAddr = x.addr;
                    h.pattern = "and " + x.opStr + "; test " + t.opStr + "; " + j.mnemonic;
                    h.note = "register daima 0 — dallanma sonucu sabit";
                    rep.opaque.push_back(h);
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Anti-analiz: import isimleri + komutlar
// ----------------------------------------------------------------------------
void ObfusAnalyzer::ScanAntiAnalysis(ObfusReport& rep) {
    static const char* antiImports[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "NtSetInformationThread", "DbgUiRemoteBreakin",
        "DbgBreakPoint", "NtQuerySystemInformation",
    };
    for (auto& d : bin_.Imports())
        for (auto& fn : d.funcs) {
            std::string n = fn.name;
            if (n.empty()) continue;
            for (auto* a : antiImports)
                if (n.find(a) != std::string::npos)
                    rep.antiAnalysis.push_back("import: " + d.name + "." + n);
        }
    // sanal makine tespiti: cpuid + VM üretici string'i
    if (az_) {
        for (auto& s : az_->Strings()) {
            std::string t = s.text;
            if (t.find("VMware") != std::string::npos || t.find("VBox") != std::string::npos ||
                t.find("Xen") == 0 || t.find("QEMU") != std::string::npos || t.find("Hyper-V") != std::string::npos)
                rep.antiAnalysis.push_back("VM imzasi string: \"" + t.substr(0, 40) + "\"");
        }
    }
    // rdtsc komutu
    if (az_) {
        for (auto& [fva, f] : az_->Functions()) {
            auto* ins = az_->InstructionsOf(fva);
            if (!ins) continue;
            for (auto& x : *ins)
                if (x.mnemonic == "rdtsc")
                    rep.antiAnalysis.push_back("rdtsc @ " + f.name +
                                               " (zaman damgasi — anti-debug olcumu olabilir)");
        }
    }
}

// ----------------------------------------------------------------------------
// Junk / sled yoğunluğu
// ----------------------------------------------------------------------------
void ObfusAnalyzer::ScanJunk(ObfusReport& rep) {
    if (!az_) return;
    for (auto& [fva, f] : az_->Functions()) {
        auto* ins = az_->InstructionsOf(fva);
        if (!ins) continue;
        int run = 1;
        for (size_t i = 1; i < ins->size(); i++) {
            const Ins& a = (*ins)[i - 1];
            const Ins& b = (*ins)[i];
            if (a.mnemonic == b.mnemonic && a.opStr == b.opStr) run++;
            else {
                if (run >= 4) rep.junkRuns++;
                run = 1;
            }
        }
        if (run >= 4) rep.junkRuns++;
    }
}

// ----------------------------------------------------------------------------
// Ana rapor
// ----------------------------------------------------------------------------
ObfusReport ObfusAnalyzer::Run() {
    ObfusReport rep;
    rep.entropies = feats_.SectionEntropies();
    rep.packerHints = feats_.PackerHeuristics();
    ScanOpaquePredicates(rep);
    ScanAntiAnalysis(rep);
    ScanJunk(rep);

    // risk ağırlıkları
    int risk = 0;
    for (auto& h : rep.packerHints) risk += h.weight;
    risk += (int)std::min<size_t>(rep.opaque.size(), 10) * 2;
    risk += (int)std::min<size_t>(rep.antiAnalysis.size(), 10) * 3;
    risk += (int)std::min<size_t>(rep.junkRuns, 10);
    // kritik entropi
    for (auto& e : rep.entropies)
        if (e.entropy >= 7.2) risk += 3;

    rep.risk = risk;
    if (risk < 3) rep.verdict = "TEMIZ";
    else if (risk < 7) rep.verdict = "SUPHELI";
    else if (risk < 14) rep.verdict = "YUKSEK RISK";
    else rep.verdict = "KRITIK";
    return rep;
}

} // namespace gt
