// ============================================================================
//  i4M GodTier Engine — ui/shell.cpp  (1/2: kurulum + dosya komutları)
// ============================================================================
#include "ui/shell.h"
#include "core/log.h"
#include "core/util.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>

namespace gt {

std::vector<std::string> Shell::SplitArgs(const std::string& line) {
    // tırnaklı argümanları da destekle
    std::vector<std::string> out;
    std::string cur; bool inQ = false;
    for (size_t i = 0; i <= line.size(); i++) {
        char c = (i < line.size()) ? line[i] : ' ';
        if (c == '"') { inQ = !inQ; continue; }
        if ((c == ' ' || c == '\t') && !inQ) {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

Shell::Shell() {
    LogInit();
}

void Shell::PrintBanner() {
    LogLine(LogColor::Magenta, "  ____        ______                    _____            _        _    ");
    LogLine(LogColor::Magenta, " |_  /  ___  |_   _|_ __ _   _ ___    |_   _|_ __  ___| |_ __ _| |__ | | ___");
    LogLine(LogColor::Magenta, "  / /  / _ \\   | |/ _| '_ \\ / | '_ \\____| || '_ \\/ _ \\ __/ _` | '_ \\| |/ _ \\");
    LogLine(LogColor::Magenta, " / /__| (_) |  | | (_| | | | \\ | | |_____| || | |\\  __/ || (_| | |_) | |  __/");
    LogLine(LogColor::Magenta, "/____|\\___/   |_|\\__,_| |_| |_|_|_|    |_||_| |_|\\___|\\__\\__,_|_.__/|_|\\___|");
    LogLine(LogColor::Cyan, "        MEGA GOD SSS TIER Binary Analiz Motoru  |  Capstone + Keystone + Unicorn");
    LogLine(LogColor::Gray,  "        i4M ekosisteminin yeni nesli — PE/ELF | mapper | emulasyon | pseudocode");
    Log("");
}

// ----------------------------------------------------------------------------
// Gereksinim kontrolleri
// ----------------------------------------------------------------------------
bool Shell::RequireBinary() {
    if (!bin_) { LogErr("Once bir dosya acin:  load <dosya.exe/dosya.elf>"); return false; }
    return true;
}

bool Shell::RequireMapped() {
    if (!img_) { LogErr("Once map edin:  map"); return false; }
    return true;
}

bool Shell::RequireEmu() {
    if (!emu_ || !emu_->Ok()) { LogErr("Once emulator kurun:  emu setup <giris-adresi>"); return false; }
    return true;
}

void Shell::EnsureAnalyzed() {
    if (analyzed_ || !bin_ || !img_) return;
    eng_ = std::make_unique<DisasmEngine>();
    eng_->SetMemoryReader([this](u64 va, u8* o, size_t n) { return img_->ReadBytes(va, o, n); });
    if (!eng_->Init(bin_->GetArch())) return;
    az_ = std::make_unique<Analyzer>(*eng_, *bin_, *img_);
    az_->RunFull(true);
    // v6: HAZIR İMZA HAVUZU — sigs/ dizinindeki .gsig dosyaları otomatik
    // uygulanır (IDA FLIRT / Ghidra FID'in "kutudan çıktığı gibi" deneyimi;
    // bizimki sembollü binary'den TEK KOMUTLA üretilir: sig export)
    {
        auto pools = ApplySigPools(*az_, "sigs");
        size_t totalRenamed = 0;
        for (auto& p : pools) totalRenamed += p.renamed;
        if (totalRenamed > 0) {
            LogOk("Hazir imza havuzu uygulandi: %zu isim geri kazanildi "
                  "(%zu havuz: sigs/*.gsig)", totalRenamed, pools.size());
        } else if (!pools.empty()) {
            LogInfo("Imza havuzlari tarandi (%zu dosya) — eslesme yok", pools.size());
        }
    }
    ps_ = std::make_unique<Pseudocoder>(*az_);
    analyzed_ = true;
}

u64 Shell::ParseAddr(const std::string& s) {
    if (s.empty()) return 0;
    if ((s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ||
        (s.find_first_of("abcdefABCDEF") != std::string::npos && s.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos))
        return std::strtoull(s.c_str(), nullptr, 16);
    // sembol dene
    if (az_) {
        for (auto& [va, f] : az_->Functions())
            if (f.name == s) return va;
    }
    return std::strtoull(s.c_str(), nullptr, 0);
}

// ----------------------------------------------------------------------------
// Yükleme
// ----------------------------------------------------------------------------
void Shell::CmdLoad(const std::vector<std::string>& a) {
    if (a.empty()) { LogInfo("Kullanim: load <dosya>  (PE .exe/.dll veya ELF)"); return; }
    std::string path = a[0];
    // görüntüyü sıfırla (aliaslar da temizlenir — sahiplik yalnız bin_'de)
    bin_.reset(); pe_ = nullptr; elf_ = nullptr; img_.reset();
    az_.reset(); ps_.reset(); emu_.reset();
    analyzed_ = false; patches_.Clear();

    Binary* b = Binary::Open(path);
    if (!b) { LogErr("Dosya acilamadi / desteklenmiyor: %s", path.c_str()); return; }
    bin_.reset(b);
    pe_ = dynamic_cast<PE*>(b);
    elf_ = dynamic_cast<ELF*>(b);
    loadedPath_ = path;

    // görüntüyü kur (statik görünüm)
    img_ = std::make_unique<MappedImage>();
    img_->LoadFromBinary(*bin_);

    LogOk("Yuklendi: %s", path.c_str());
    CmdInfo({});
}

void Shell::CmdInfo(const std::vector<std::string>&) {
    if (!RequireBinary()) return;
    LogLine(LogColor::Cyan, "== DOSYA BILGISI =========================================");
    Log("  Format        : %s\n", bin_->FormatName().c_str());
    Log("  Mimari        : %s\n", ArchName(bin_->GetArch()));
    Log("  Boyut         : %s bayt\n", std::to_string(bin_->RawSize()).c_str());
    Log("  ImageBase     : 0x%llx\n", (unsigned long long)bin_->ImageBase());
    Log("  ImageSize     : 0x%llx\n", (unsigned long long)bin_->ImageSize());
    Log("  Entry Point   : 0x%llx\n", (unsigned long long)bin_->EntryPoint());
    Log("  Section       : %zu\n", bin_->Sections().size());
    size_t impN = 0;
    for (auto& d : bin_->Imports()) impN += d.funcs.size();
    Log("  Import        : %zu dll / %zu fonksiyon\n", bin_->Imports().size(), impN);
    Log("  Export        : %zu\n", bin_->Exports().size());
    Log("  Sembol        : %zu\n", bin_->Symbols().size());
    Log("  Relocation    : %zu\n", bin_->Relocs().size());
    auto dbg = bin_->GetDebugInfo();
    if (dbg.hasPdb) {
        LogLine(LogColor::Yellow, "  PDB           : %s", dbg.pdbPath.c_str());
        Log("                GUID: %s\n", dbg.pdbGuid.c_str());
    }
    if (pe_) {
        static const char* subsys[] = {"?", "native", "windows gui", "windows console", "os2", "ce", "?", "?"};
        u16 ss = pe_->Subsystem();
        Log("  Subsystem     : %u (%s)\n", ss, subsys[std::min<u16>(ss, 7)]);
        Log("  DLL mi        : %s\n", pe_->IsDll() ? "EVET" : "hayir");
        Log("  Timestamp     : %llu", (unsigned long long)pe_->Timestamp());
        if (!pe_->DelayDlls().empty()) {
            Log(" (delay-load: ");
            for (size_t i = 0; i < pe_->DelayDlls().size(); i++)
                Log("%s%s", pe_->DelayDlls()[i].c_str(), i + 1 < pe_->DelayDlls().size() ? ", " : ")");
        }
        Log("\n");
        if (!pe_->RichHeader().empty()) {
            LogLine(LogColor::Gray, "  Rich header   : %zu derleyici kaydi (MSVC)", pe_->RichHeader().size());
            for (auto& r : pe_->RichHeader())
                LogLine(LogColor::Gray, "      prodid=%u build=%u x%u", r.id, r.build, r.count);
        }
    }
    if (elf_) {
        Log("  Interpreter   : %s\n", elf_->Interpreter().empty() ? "(statik)" : elf_->Interpreter().c_str());
    }
}

void Shell::CmdSections(const std::vector<std::string>&) {
    if (!RequireBinary()) return;
    LogLine(LogColor::Cyan, "== SECTION'LAR ===========================================");
    Log("  %-10s %-14s %-12s %-12s %-6s %s\n", "AD", "VA", "VSIZE", "RAWSIZE", "ERW", "ENTROPI");
    auto feats = std::make_unique<FeatureAnalyzer>(*bin_, *img_);
    auto ent = feats->SectionEntropies();
    size_t ei = 0;
    for (auto& s : bin_->Sections()) {
        std::string erws;
        erws += s.executable ? 'E' : '-';
        erws += s.readable ? 'R' : '-';
        erws += s.writable ? 'W' : '-';
        double e = (ei < ent.size()) ? ent[ei].entropy : 0.0; ei++;
        Log("  %-10s 0x%-12llx 0x%-10llx 0x%-10llx %s   %.2f\n",
            s.name.c_str(), (unsigned long long)s.va, (unsigned long long)s.vsize,
            (unsigned long long)s.rawSize, erws.c_str(), e);
    }
}

void Shell::CmdImports(const std::vector<std::string>& a) {
    if (!RequireBinary()) return;
    std::string flt = a.empty() ? "" : ToLower(a[0]);
    LogLine(LogColor::Cyan, "== IMPORT'LAR ============================================");
    for (auto& d : bin_->Imports()) {
        if (!flt.empty() && ToLower(d.name).find(flt) == std::string::npos) continue;
        LogLine(LogColor::White, "  %s (%zu fonksiyon)", d.name.c_str(), d.funcs.size());
        for (auto& f : d.funcs) {
            if (!flt.empty() && (f.name.empty() || ToLower(f.name).find(flt) == std::string::npos)) continue;
            Log("      iat: 0x%-10llx  %s\n", (unsigned long long)f.iatVa,
                f.name.empty() ? ("ord#" + std::to_string(f.ordinal)).c_str() : f.name.c_str());
        }
    }
}

void Shell::CmdExports(const std::vector<std::string>&) {
    if (!RequireBinary()) return;
    if (bin_->Exports().empty()) { LogInfo("Export yok"); return; }
    LogLine(LogColor::Cyan, "== EXPORT'LAR ============================================");
    for (auto& e : bin_->Exports())
        Log("  0x%llx  ord=%-5u  %s\n", (unsigned long long)e.va, e.ordinal, e.name.c_str());
}

void Shell::CmdStrings(const std::vector<std::string>& a) {
    if (!RequireBinary()) return;
    EnsureAnalyzed();
    std::string flt = a.empty() ? "" : ToLower(a[0]);
    size_t maxShow = a.size() > 1 ? std::strtoul(a[1].c_str(), 0, 10) : 60;
    auto& strs = az_->Strings();
    size_t shown = 0;
    for (auto& s : strs) {
        if (!flt.empty() && ToLower(s.text).find(flt) == std::string::npos) continue;
        if (shown++ >= maxShow) { LogLine(LogColor::Gray, "  ... (%zu toplam, filtre kullanin)", strs.size()); break; }
        Log("  0x%-12llx %s %s\n", (unsigned long long)s.va, s.wide ? "[W]" : "   ", s.text.c_str());
    }
    if (!shown) LogInfo("Kosula uyan string yok (toplam %zu)", strs.size());
}

void Shell::CmdFuncs(const std::vector<std::string>&) {
    if (!RequireBinary()) return;
    EnsureAnalyzed();
    LogLine(LogColor::Cyan, "== FONKSIYONLAR ==========================================");
    size_t n = 0;
    for (auto& [va, f] : az_->Functions()) {
        if (n++ >= 200) { LogLine(LogColor::Gray, "  ... (daha fazla icin xref/dis kullanin)"); break; }
        Log("  0x%-12llx %-40s %5zu komut%s\n", (unsigned long long)va,
            f.name.c_str(), f.insCount, f.fromSymbol ? "  [sembol]" : "");
    }
    LogLine(LogColor::Gray, "  toplam: %zu fonksiyon", az_->Functions().size());
}

} // namespace gt
