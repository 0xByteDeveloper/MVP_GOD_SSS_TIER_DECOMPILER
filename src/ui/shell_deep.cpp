// ============================================================================
//  i4M GodTier Engine — ui/shell_deep.cpp
//  v4 komutları:
//   deep [apply]   — derin fonksiyon keşfi (prolog + veri-referans + tail-call)
//   sig [export <f>|import <f>] — FLIRT-tarzı imza motoru (.gsig)
//   obfus          — obfuscation/packer/anti-analiz risk raporu
//   find hex|imm|str|asm <..> — bayt/sabit/string/komut arama
// ============================================================================
#include "ui/shell.h"
#include "core/log.h"
#include "core/util.h"
#include "analysis/deepscan.h"
#include "analysis/sigs.h"
#include "analysis/obfus.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace gt {

// ----------------------------------------------------------------------------
// deep — derin keşif
// ----------------------------------------------------------------------------
void Shell::CmdDeep(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    DeepScanner ds(*az_);
    bool apply = !a.empty() && a[0] == "apply";
    auto cands = ds.Scan(false);
    if (cands.empty()) {
        LogOk("Derin keşif: yeni aday yok (bilinen %zu fonksiyon zaten kapsanmis)",
              az_->Functions().size());
        return;
    }
    LogLine(LogColor::Cyan, "== DERIN FONKSIYON KESFI ===============================");
    LogLine(LogColor::Gray, "  %zu aday (strateji: prolog / veri-referansi / tail-call)", cands.size());
    for (auto& c : cands) {
        LogColor col = c.confidence >= 70 ? LogColor::Green
                       : c.confidence >= 50 ? LogColor::Yellow : LogColor::Gray;
        LogLine(col, "  0x%-12llx [%3d%%] %-14s %s",
                (unsigned long long)c.va, c.confidence, c.strategy.c_str(),
                c.evidence.c_str());
    }
    if (apply) {
        size_t n = ds.Apply(cands);
        LogOk("Uygulandi: %zu yeni fonksiyon (FUN_XXXXXXXX) — toplam %zu",
              n, az_->Functions().size());
    } else {
        LogInfo("Uygulamak icin: deep apply");
    }
}

// ----------------------------------------------------------------------------
// sig — imza motoru
// ----------------------------------------------------------------------------
void Shell::CmdSig(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    SigEngine se(*az_);

    if (!a.empty() && a[0] == "export" && a.size() > 1) {
        if (se.ExportGsig(a[1]))
            LogOk("Imza veritabani yazildi: %s (sembollü fonksiyonlardan)", a[1].c_str());
        else
            LogErr("Imza uretilemedi (sembollü fonksiyon yok veya dosya acilamadi)");
        return;
    }
    if (!a.empty() && a[0] == "import" && a.size() > 1) {
        auto r = se.ImportGsig(a[1]);
        if (r.matched == 0) { LogInfo("Eslesme yok (%zu fonksiyon karsilastirildi)", r.compared); return; }
        LogOk("Imza eslesmesi: %zu / %zu fonksiyon yeniden adlandirildi",
              r.matched, r.renamed);
        for (auto& [va, name] : r.renames)
            LogLine(LogColor::Green, "  0x%-12llx -> %s", (unsigned long long)va, name.c_str());
        return;
    }
    // v6: sig auto — sigs/ dizinindeki tüm havuzları uygula (load'ta otomatik da koşar)
    if (!a.empty() && a[0] == "auto") {
        auto pools = ApplySigPools(*az_, "sigs");
        if (pools.empty()) { LogInfo("sigs/ dizininde .gsig havuzu yok — "
                                     "uretmek icin: sig export sigs/benim.gsig"); return; }
        size_t total = 0;
        for (auto& p : pools) {
            LogLine(p.renamed ? LogColor::Green : LogColor::Gray,
                    "  %-32s %zu eslesme / %zu yeniden adlandirma",
                    p.path.c_str(), p.matched, p.renamed);
            total += p.renamed;
        }
        LogOk("Hazir havuz uygulandi: toplam %zu isim geri kazanildi", total);
        return;
    }
    // v6: havuz istatistiği
    if (!a.empty() && a[0] == "stats") {
        size_t n = CountGsigEntries("sigs/libc_x64.gsig");
        LogInfo("sigs/libc_x64.gsig: %zu imza (uretim: load libc.so.6 + sig export)", n);
        return;
    }
    // desen kuralı taraması
    auto matches = se.RuleScan();
    LogLine(LogColor::Cyan, "== IMZA MOTORU (desen kurallari) ========================");
    if (matches.empty()) { LogInfo("Bilinen kalip eslesmedi. " "Kullanim: sig | sig export <f> | sig import <f>"); return; }
    for (auto& m : matches)
        LogLine(m.confidence >= 80 ? LogColor::Green : LogColor::Yellow,
                "  0x%-12llx %-28s %-22s %s",
                (unsigned long long)m.funcVa, m.funcName.c_str(),
                m.libraryName.c_str(), m.rule.c_str());
    LogLine(LogColor::Gray, "  ipucu: sig export <dosya.gsig> ile imza havuzu uret, "
                            "sig import ile stripped binary'de isim geri kazan");
}

// ----------------------------------------------------------------------------
// lumina — v6: birikimli yerel isim havuzu (IDA Lumina muadili; bulut YOK)
// ----------------------------------------------------------------------------
void Shell::CmdLumina(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    std::string pool = (a.size() > 1 && a[1][0] != '-') ? a[1] : "lumina.gsig";
    SigEngine se(*az_);

    if (!a.empty() && a[0] == "push") {
        size_t added = se.PushToPool(pool);
        size_t total = CountGsigEntries(pool);
        LogOk("lumina push: %zu yeni isim havuza eklendi (toplam %zu) — %s",
              added, total, pool.c_str());
        return;
    }
    if (!a.empty() && a[0] == "pull") {
        auto r = se.ImportGsig(pool);
        if (r.matched == 0) { LogInfo("Eslesme yok (havuz: %s, %zu fonksiyon karsilastirildi)",
                                      pool.c_str(), r.compared); return; }
        LogOk("lumina pull: %zu fonksiyon yeniden adlandirildi (havuz: %s)",
              r.renamed, pool.c_str());
        for (auto& [va, name] : r.renames)
            LogLine(LogColor::Green, "  0x%-12llx -> %s", (unsigned long long)va, name.c_str());
        return;
    }
    LogInfo("Kullanim: lumina push [havuz.gsig]  — isimli fonksiyonlari havuza ekle\n"
            "        lumina pull [havuz.gsig]  — havuzu bu binary'ye uygula\n"
            "  (varsayilan havuz: lumina.gsig — bilgelik dosyayla birikir)");
}

// ----------------------------------------------------------------------------
// obfus — obfuscation risk raporu
// ----------------------------------------------------------------------------
void Shell::CmdObfus(const std::vector<std::string>&) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    ObfusAnalyzer oa(*bin_, *img_, az_.get());
    auto rep = oa.Run();

    LogLine(LogColor::Cyan, "== OBFUSCATION / PACKER RAPORU ==========================");
    LogLine(LogColor::Gray, "  Bolum entropisi:");
    for (auto& e : rep.entropies)
        Log("    %-10s %.2f  %s\n", e.section.c_str(), e.entropy, e.verdict.c_str());
    if (!rep.packerHints.empty()) {
        LogLine(LogColor::Gray, "  Packer izleri:");
        for (auto& h : rep.packerHints)
            Log("    [%d] %s\n", h.weight, h.reason.c_str());
    }
    if (!rep.opaque.empty()) {
        LogLine(LogColor::Gray, "  Opaque predicate'ler (%zu):", rep.opaque.size());
        for (auto& o : rep.opaque)
            Log("    0x%-12llx %-20s %s  // %s\n", (unsigned long long)o.insAddr,
                o.funcName.c_str(), o.pattern.c_str(), o.note.c_str());
    }
    if (!rep.antiAnalysis.empty()) {
        LogLine(LogColor::Gray, "  Anti-analiz kanitlari (%zu):", rep.antiAnalysis.size());
        for (auto& s : rep.antiAnalysis) Log("    %s\n", s.c_str());
    }
    if (rep.junkRuns)
        LogLine(LogColor::Gray, "  Junk/dolgu bloklari: %zu", rep.junkRuns);

    LogColor vc = rep.risk >= 14 ? LogColor::Red
                 : rep.risk >= 7 ? LogColor::Yellow : LogColor::Green;
    LogLine(vc, "  KARAR: %s (risk puani %d)", rep.verdict.c_str(), rep.risk);
    if (!rep.opaque.empty())
        LogInfo("Not: decompiler bu opaque predicate'leri sabite katlar "
                "(decomp ciktisinde 'kosul sabit' notu) ve olu dallari budar");
}

// ----------------------------------------------------------------------------
// find — bayt / sabit / string / komut arama
// ----------------------------------------------------------------------------
void Shell::CmdFind(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    if (a.size() < 2) {
        LogInfo("Kullanim:\n"
                "  find hex 55 48 89 e5      bayt dizisi ara (hex baytlar)\n"
                "  find imm 0x51eb851f       komutlardaki sabiti ara\n"
                "  find str <metin>          string'lerde ara\n"
                "  find asm <mnemonic>       komut adina gore ara (xor, imul...)");
        return;
    }
    const std::string& mode = a[0];
    const u64 base = img_->Base();
    const u64 bd = base - bin_->ImageBase();

    if (mode == "hex") {
        std::vector<u8> pat;
        for (size_t i = 1; i < a.size(); i++) pat.push_back((u8)strtoul(a[i].c_str(), 0, 16));
        if (pat.empty() || pat.size() < 2) { LogErr("En az 2 bayt verin"); return; }
        LogLine(LogColor::Cyan, "== BAYT ARAMA (%zu bayt) ===============================", pat.size());
        size_t hits = 0;
        auto& raw = bin_->Raw();
        for (auto& s : bin_->Sections()) {
            if (!s.rawSize) continue;
            for (u64 off = s.rawOffset; off + pat.size() <= s.rawOffset + s.rawSize; off++) {
                if (memcmp(&raw[(size_t)off], pat.data(), pat.size()) != 0) continue;
                u64 va = s.va + bd + (off - s.rawOffset);
                const FuncInfo* f = az_->FunctionAt(va);
                Log("  0x%-12llx %-10s %s\n", (unsigned long long)va, s.name.c_str(),
                    f ? f->name.c_str() : "");
                if (++hits >= 50) { LogLine(LogColor::Gray, "  ... (ilk 50)"); off = (u64)-1; break; }
            }
            if (hits >= 50) break;
        }
        if (!hits) LogInfo("Bulunamadi");
        return;
    }
    if (mode == "imm") {
        std::string tok = a[1];
        if (tok.rfind("0x", 0) != 0 && tok.rfind("0X", 0) != 0) tok = "0x" + tok;
        LogLine(LogColor::Cyan, "== SABIT ARAMA (%s) ===================================", tok.c_str());
        size_t hits = 0;
        for (auto& [fva, f] : az_->Functions()) {
            auto* ins = az_->InstructionsOf(fva);
            if (!ins) continue;
            for (auto& x : *ins) {
                if (x.opStr.find(tok) == std::string::npos) continue;
                Log("  0x%-12llx %-8s %-24s  [%s]\n", (unsigned long long)x.addr,
                    x.mnemonic.c_str(), x.opStr.c_str(), f.name.c_str());
                if (++hits >= 50) break;
            }
            if (hits >= 50) break;
        }
        if (!hits) LogInfo("Bulunamadi");
        return;
    }
    if (mode == "str") {
        std::string needle = a[1];
        for (size_t i = 2; i < a.size(); i++) needle += " " + a[i];
        LogLine(LogColor::Cyan, "== STRING ARAMA \"%s\" =============================", needle.c_str());
        size_t hits = 0;
        for (auto& s : az_->Strings())
            if (s.text.find(needle) != std::string::npos) {
                Log("  0x%-12llx %s %s\n", (unsigned long long)s.va,
                    s.wide ? "[W]" : "   ", s.text.c_str());
                if (++hits >= 50) break;
            }
        if (!hits) LogInfo("Bulunamadi");
        return;
    }
    if (mode == "asm") {
        std::string mn = a[1];
        LogLine(LogColor::Cyan, "== KOMUT ARAMA (%s) ===================================", mn.c_str());
        size_t hits = 0;
        for (auto& [fva, f] : az_->Functions()) {
            auto* ins = az_->InstructionsOf(fva);
            if (!ins) continue;
            for (auto& x : *ins)
                if (x.mnemonic == mn) {
                    Log("  0x%-12llx %-8s %-28s  [%s]\n", (unsigned long long)x.addr,
                        x.mnemonic.c_str(), x.opStr.c_str(), f.name.c_str());
                    if (++hits >= 50) break;
                }
            if (hits >= 50) break;
        }
        if (!hits) LogInfo("Bulunamadi");
        return;
    }
    LogErr("Bilinmeyen mod: %s (hex|imm|str|asm)", mode.c_str());
}

} // namespace gt
