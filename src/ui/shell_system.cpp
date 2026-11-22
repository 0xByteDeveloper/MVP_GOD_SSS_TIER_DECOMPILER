// ============================================================================
//  i4M GodTier Engine — ui/shell.cpp  (3/3: analysis/proc/komut döngüsü)
// ============================================================================
#include "ui/shell.h"
#include "format/pdb.h"
#include "core/log.h"
#include "core/util.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>

namespace gt {

// ----------------------------------------------------------------------------
// Analysis paketi
// ----------------------------------------------------------------------------
void Shell::CmdAnalysis(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    std::string what = a.empty() ? "all" : ToLower(a[0]);
    auto feats = std::make_unique<FeatureAnalyzer>(*bin_, *img_);

    if (what == "imphash" || what == "all") {
        LogLine(LogColor::Cyan, "== IMPHASH (Mandiant algoritmasi) ========================");
        Log("  %s\n", feats->Imphash().c_str());
        if (what == "imphash") return;
    }
    if (what == "entropy" || what == "all") {
        LogLine(LogColor::Cyan, "== ENTROPI ==============================================");
        for (auto& r : feats->SectionEntropies())
            Log("  %-10s %5.2f/8.00 (%5.1f%%)  %s\n", r.section.c_str(),
                r.entropy, r.percent, r.verdict.c_str());
        Log("  genel dosya: %.2f/8.00\n", feats->OverallEntropy());
        if (what == "entropy") return;
    }
    if (what == "packer" || what == "all") {
        LogLine(LogColor::Cyan, "== PACKER SEZGILERI (DIE tarzi) =========================");
        auto hints = feats->PackerHeuristics();
        if (hints.empty()) { LogLine(LogColor::Green, "  paketlenmemis gorunuyor"); }
        else for (auto& h : hints) Log("  [%d] %s\n", h.weight, h.reason.c_str());
        int risk = feats->PackerRisk();
        Log("  toplam risk: %d %s\n", risk,
            risk >= 6 ? "(PACKED!)" : risk >= 3 ? "(supheli)" : "(dusuk)");
        if (what == "packer") return;
    }
    if (what == "crypto" || what == "all") {
        LogLine(LogColor::Cyan, "== FINDCRYPT (kripto sabitleri) =========================");
        auto hits = feats->FindCryptoConstants();
        if (hits.empty()) LogLine(LogColor::Gray, "  bilinen sabit bulunamadi");
        else for (auto& h : hits)
            Log("  0x%-12llx %-20s (%s)\n", (unsigned long long)h.va,
                h.algo.c_str(), h.section.c_str());
        if (what == "crypto") return;
    }
    if (what == "capa" || what == "all") {
        LogLine(LogColor::Cyan, "== YETENEKLER (capa-lite) ===============================");
        auto caps = feats->Capabilities();
        if (caps.empty()) LogLine(LogColor::Gray, "  yetenek cikarilamadi");
        else for (auto& c : caps) {
            LogLine(LogColor::Yellow, "  [%d] %s", c.weight, c.name.c_str());
            LogLine(LogColor::Gray, "       kanit: %s", c.evidence.c_str());
        }
    }
}

// ----------------------------------------------------------------------------
// Dump / Save
// ----------------------------------------------------------------------------
void Shell::CmdDump(const std::vector<std::string>& a) {
    if (!RequireMapped()) return;
    std::string path = a.empty() ? "godtier_dump.bin" : a[0];
    if (WriteFileBytes(path, img_->Data()))
        LogOk("Mapped goruntu (%zu bayt, base 0x%llx) -> %s",
              img_->Size(), (unsigned long long)img_->Base(), path.c_str());
    else LogErr("Yazilamadi: %s", path.c_str());
}

void Shell::CmdSave(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    // patch'leri DISKE geri uygula: VA -> dosya offset
    std::string path = a.empty() ? (loadedPath_ + ".patched") : a[0];
    std::vector<u8> out = bin_->Raw();   // kopya
    size_t applied = 0;
    for (auto& p : patches_.Done()) {
        u64 off = bin_->VaToRaw(p.va);
        if (off == (u64)-1 || off + p.after.size() > out.size()) {
            LogWarn("Patch 0x%llx diske uygulanamadi (VA ofset disi)",
                    (unsigned long long)p.va);
            continue;
        }
        std::memcpy(&out[(size_t)off], p.after.data(), p.after.size());
        applied++;
    }
    if (WriteFileBytes(path, out))
        LogOk("Kaydedildi -> %s (%zu patch uygulandi)", path.c_str(), applied);
    else LogErr("Yazilamadi");
}

// ----------------------------------------------------------------------------
// PDB bilgisi
// ----------------------------------------------------------------------------
void Shell::CmdPdb(const std::vector<std::string>& a) {
    if (!RequireBinary()) return;
    // pdb <dosya.pdb>: MSF 7.00 PDB yükle + isim/tip veritabanına uygula
    if (!a.empty()) {
        if (!RequireMapped()) return;
        EnsureAnalyzed();      // görüntü + temel analiz hazır olsun (map edilmiş)
        auto pdb = std::make_unique<PdbInfo>();
        if (!pdb->Load(a[0])) {
            LogErr("PDB yuklenemedi: %s", pdb->Error().c_str());
            return;
        }
        pdb->ResolveVAs(bin_->ImageBase(), bin_->Sections());
        LogOk("PDB yuklendi: %zu tip, %zu fonksiyon, %zu global (GUID %s)",
              pdb->TypeCount(), pdb->Funcs().size(), pdb->Globals().size(),
              pdb->Guid().c_str());
        // 1) fonksiyon isimlerini uygula (strip'li PE'lerde bile!)
        size_t renamed = 0;
        for (auto& f : pdb->Funcs()) {
            std::string nm = !f.shortName.empty() ? f.shortName : f.name;
            size_t had = az_->Functions().size();
            az_->EnsureFunction(f.va, nm);
            if (az_->Functions().size() > had || renamed < (size_t)-1) renamed++;
        }
        LogOk("Fonksiyon isimleri uygulandi: %zu", renamed);
        // 2) tip veritabanına PDB kanalı aç (struct'lar + imzalar)
        ps_->SetPdb(std::move(pdb));       // kanal (pending: Run'da beslenir)
        ps_->InvalidateTI();                // yeniden kurulsun
        LogInfo("Tip veritabani PDB kanaliyla yeniden kurulacak (types/decomp komutlari)");
        return;
    }
    auto dbg = bin_->GetDebugInfo();
    LogLine(LogColor::Cyan, "== PDB BILGISI (debug dizini) ===========================");
    if (dbg.hasPdb) {
        Log("  Yol  : %s\n", dbg.pdbPath.c_str());
        Log("  GUID : %s\n", dbg.pdbGuid.c_str());
    } else {
        LogLine(LogColor::Gray, "  PDB bilgisi yok (debug dizini bos)");
    }
    LogInfo("Kullanim: pdb <dosya.pdb>   — MSF 7.00 PDB yukle + uygula");
    LogLine(LogColor::Gray, "  Fonksiyon isimleri, parametre adlari, struct uyeleri");
    LogLine(LogColor::Gray, "  ve imzalar PDB kanalindan giydirilir (IDA + PDB modu)");
}

// ----------------------------------------------------------------------------
// Köprüler
// ----------------------------------------------------------------------------
void Shell::CmdBridge(const std::vector<std::string>& a) {
    if (!RequireBinary()) return;
    if (a.empty()) {
        LogInfo("Kullanim: bridge retdec | bridge ghidra");
        LogInfo("  Harici decompiler'lari cagirir (PATH'te kurulu olmali)");
        return;
    }
    if (a[0] == "retdec") {
        std::string out = Pseudocoder::BridgeRetDec(loadedPath_, loadedPath_ + ".retdec.c");
        LogLine(LogColor::Cyan, "%s", out.c_str());
    } else if (a[0] == "ghidra") {
        std::string out = Pseudocoder::BridgeGhidra(loadedPath_, loadedPath_ + ".ghidra.json");
        LogLine(LogColor::Cyan, "%s", out.c_str());
    }
}

// ----------------------------------------------------------------------------
// Process modu
// ----------------------------------------------------------------------------
void Shell::CmdProc(const std::vector<std::string>& a) {
    if (a.empty()) {
        LogInfo("Kullanim:");
        LogInfo("  proc list [filtre]     process listesi");
        LogInfo("  proc attach <pid>      baglan");
        LogInfo("  proc modules           modul listesi");
        LogInfo("  proc read <adres> [n]  bellek oku");
        LogInfo("  proc write <adres> b:.. bellek yaz");
        LogInfo("  proc detach            ayir");
        return;
    }
    if (a[0] == "list") {
        auto list = ProcessAccess::ListProcesses(a.size() > 1 ? a[1] : "");
        size_t i = 0;
        for (auto& p : list) {
            if (i++ >= 50) { LogLine(LogColor::Gray, "  ... %zu toplam", list.size()); break; }
            Log("  %-8u %s\n", p.pid, p.name.c_str());
        }
        return;
    }
    if (a[0] == "attach") {
        if (a.size() < 2) { LogErr("pid ver: proc attach 1234"); return; }
        u32 pid = (u32)std::strtoul(a[1].c_str(), 0, 0);
        if (!proc_.Attach(pid)) LogErr("Baglanamadi");
        return;
    }
    if (a[0] == "detach") { proc_.Detach(); LogOk("Ayirildi"); return; }
    if (a[0] == "modules") {
        if (!proc_.Ok()) { LogErr("Once proc attach"); return; }
        for (auto& m : proc_.Modules())
            Log("  0x%-12llx +%-10llx %s\n", (unsigned long long)m.base,
                (unsigned long long)m.size, m.name.c_str());
        return;
    }
    if (a[0] == "read") {
        if (!proc_.Ok()) { LogErr("Once proc attach"); return; }
        if (a.size() < 2) { LogErr("adres ver"); return; }
        u64 va = std::strtoull(a[1].c_str(), 0, 16);
        size_t n = a.size() > 2 ? (size_t)std::strtoul(a[2].c_str(), 0, 0) : 32;
        std::vector<u8> buf(n);
        if (!proc_.Read(va, buf.data(), n)) { LogErr("Okunamadi 0x%llx", (unsigned long long)va); return; }
        for (size_t r = 0; r * 16 < n; r++) {
            Log("  %012llx  %s\n", (unsigned long long)(va + r * 16),
                ToHexBytes(&buf[r * 16], std::min<size_t>(16, n - r * 16)).c_str());
        }
        return;
    }
    if (a[0] == "write") {
        if (!proc_.Ok()) { LogErr("Once proc attach"); return; }
        if (a.size() < 3) { LogErr("proc write <adres> b:DEADBEEF"); return; }
        u64 va = std::strtoull(a[1].c_str(), 0, 16);
        std::vector<u8> bytes;
        std::string hex = a[2].rfind("b:", 0) == 0 ? a[2].substr(2) : a[2];
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
            bytes.push_back((u8)std::strtoul(hex.substr(i, 2).c_str(), 0, 16));
        if (proc_.Write(va, bytes.data(), bytes.size()))
            LogOk("%zu bayt yazildi", bytes.size());
        else LogErr("Yazilamadi (izin?)");
        return;
    }
}

// ----------------------------------------------------------------------------
// Script + menü + help
// ----------------------------------------------------------------------------
void Shell::CmdScript(const std::vector<std::string>& a) {
    if (a.empty()) { LogInfo("Kullanim: script <dosya.gt>  (her satir bir komut)"); return; }
    std::ifstream f(a[0]);
    if (!f) { LogErr("Script acilamadi: %s", a[0].c_str()); return; }
    std::string line;
    int ln = 0;
    scriptVars_.clear();   // v6: her çalıştırma temiz başlar
    while (std::getline(f, line)) {
        ln++;
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        LogLine(LogColor::Magenta, ">> %s", line.c_str());
        if (!ScriptLine(line)) break;
    }
    LogOk("Script bitti (%d satir)", ln);
}

// ----------------------------------------------------------------------------
// v6: script satırı ön-işlemesi — $değişken / set / eval / echo / if
//   set $a = 0x10 * 3        -> $a = 48
//   echo "toplam: $a"        -> toplam: 48
//   eval (0xff + 1) << 4     -> 4096
//   if $a == 48 : load x.elf -> koşul doğruysa komut çalışır (iç içe olabilir)
// ----------------------------------------------------------------------------
bool Shell::ScriptLine(const std::string& raw) {
    std::string line = Trim(raw);
    if (line.empty() || line[0] == '#') return true;

    // $değişken ikamesi (set hedefi hariç)
    auto subst = [&](const std::string& in) {
        std::string out;
        for (size_t i = 0; i < in.size(); i++) {
            if (in[i] == '$' && i + 1 < in.size() &&
                (isalpha((unsigned char)in[i+1]) || in[i+1] == '_')) {
                size_t j = i + 1;
                while (j < in.size() &&
                       (isalnum((unsigned char)in[j]) || in[j] == '_')) j++;
                std::string name = in.substr(i, j - i);
                auto it = scriptVars_.find(name);
                if (it != scriptVars_.end()) out += it->second;
                else out += name;      // tanımsız: olduğu gibi (honest)
                i = j - 1;
            } else out += in[i];
        }
        return out;
    };

    if (line.rfind("set ", 0) == 0) {
        std::string rest = Trim(line.substr(4));
        size_t eq = rest.find('=');
        if (eq == std::string::npos || eq == 0) {
            LogWarn("set kullanimi: set $ad = <aritmetik ifade>");
            return true;
        }
        std::string name = Trim(rest.substr(0, eq));
        std::string expr = subst(Trim(rest.substr(eq + 1)));
        bool ok = false;
        i64 v = EvalArith(expr, &ok);
        if (!ok) { LogWarn("ifade cozulemedi: %s", expr.c_str()); return true; }
        if (name[0] != '$') name = "$" + name;
        scriptVars_[name] = std::to_string(v);
        return true;
    }
    line = subst(line);
    if (line.rfind("echo ", 0) == 0) {
        std::string t = line.substr(5);
        if (!t.empty() && t.front() == '"') t = t.substr(1);
        if (!t.empty() && t.back() == '"') t.pop_back();
        LogLine(LogColor::White, "%s", t.c_str());
        return true;
    }
    if (line.rfind("eval ", 0) == 0) {
        bool ok = false;
        i64 v = EvalArith(line.substr(5), &ok);
        if (ok) LogLine(LogColor::White, "%lld  (0x%llx)", (long long)v,
                        (unsigned long long)(u64)v);
        else LogWarn("ifade cozulemedi: %s", line.substr(5).c_str());
        return true;
    }
    if (line.rfind("if ", 0) == 0) {
        std::string rest = Trim(line.substr(3));
        static const char* ops[] = {"==", "!=", "<=", ">=", "<", ">"};
        size_t opPos = std::string::npos; size_t opLen = 0;
        for (auto* op : ops) {
            size_t p = rest.find(op);
            if (p != std::string::npos && (opPos == std::string::npos || p < opPos)) {
                opPos = p; opLen = strlen(op);
            }
        }
        size_t colon = rest.find(':');
        if (opPos == std::string::npos || colon == std::string::npos || colon < opPos) {
            LogWarn("if kullanimi: if $a == 42 : <komut>");
            return true;
        }
        std::string lhs = Trim(rest.substr(0, opPos));
        std::string rhs = Trim(rest.substr(opPos + opLen, colon - opPos - opLen));
        std::string cmd = Trim(rest.substr(colon + 1));
        bool ok1 = false, ok2 = false;
        i64 a = EvalArith(lhs, &ok1), b = EvalArith(rhs, &ok2);
        if (!ok1 || !ok2) { LogWarn("if kosulu cozulemedi"); return true; }
        std::string op = rest.substr(opPos, opLen);
        bool cond = op == "==" ? a == b : op == "!=" ? a != b :
                    op == "<"  ? a <  b : op == ">"  ? a >  b :
                    op == "<=" ? a <= b : a >= b;
        if (cond && !cmd.empty()) return ScriptLine(cmd);
        return true;
    }
    return ExecuteCommand(line);
}

void Shell::CmdHelp(const std::vector<std::string>&) {
    LogLine(LogColor::Cyan, "== KOMUTLAR ==============================================");
    LogLine(LogColor::White, " DOSYA");
    Log("  load <dosya>            PE/ELF yukle          info       ozet bilgi\n");
    Log("  sections                bolumler + entropi    imports [f] import tablosu\n");
    Log("  exports                 export tablosu        strings [f][n] string ara\n");
    Log("  pdb                     PDB GUID/yol raporu   save [cikti] patch'li kaydet\n");
    LogLine(LogColor::White, " ANALIZ");
    Log("  funcs                   fonksiyon listesi     dis [adres] [n]  disassembly\n");
    Log("  xref <adres>            cross-referanslar     decomp [adres|all] pseudocode (v2)\n");
    Log("  types                   imza + struct veritabani (global tip analizi)\n");
    Log("  deep [apply]            derin fonksiyon kesfi (v4)  sig [export|import|auto] imza+havuz (v4/v6)\n");
    Log("  lumina [push|pull]      birikimli isim havuzu (v6)  obfus   obfuscation risk raporu\n");
    Log("  find hex|imm|str|asm     arama (v4)     analysis [all|imphash|entropy|...] ozellik analizi\n");
    LogLine(LogColor::White, " DUZENLEME");
    Log("  asm <adres> \"kod\"       assemble (Keystone)   hex [adres] [satir] hexdump\n");
    Log("  patch <adres> b:..|a:\"..\" yama               undo|redo        geri al\n");
    LogLine(LogColor::White, " LOADER EMULASYONU (Windows gibi, kod calismaz)");
    Log("  map                     bellege map et        maplog     loader gunlugu\n");
    Log("  dump [dosya]            mapped goruntuyu yaz\n");
    LogLine(LogColor::White, " EMULATOR (Unicorn - kod calisir!)");
    Log("  emu [setup [adres]|step [n]|stop|mem <a>]    regs       register durumu\n");
    Log("  apitrace                API cagri gunlugu     trace [n]  komut izi\n");
    LogLine(LogColor::White, " PROCESS");
    Log("  proc list|attach|modules|read|write|detach   (Win: RPM, Linux: /proc)\n");
    LogLine(LogColor::White, " HARICI KO PRULER");
    Log("  bridge retdec|ghidra    harici decompiler cagrisi\n");
    Log("  rtti [sinif]            v7: MSVC RTTI atlasi (siniflar + vftable)\n");
    Log("  devirt [cagri-adresi]   v7: sanal cagriyi statik coz (kanit zinciri)\n");
    Log("  devirt stats            v8.1: mekanizma kirilimi (nasil cozuldu/neden cozulemedi)\n");
    LogLine(LogColor::White, " DIGER");
    Log("  script <dosya.gt>       toplu komut (v6: $degisken/set/eval/if)  menu  klasik i4M menusu\n");
    Log("  help                    bu ekran              quit / q   cikis\n");
}

void Shell::CmdMenu(const std::vector<std::string>&) {
    LogLine(LogColor::Cyan, "== i4M KLASIK MENU (eski dost, yeni motorla) ============");
    Log(" [1] PE Yukle        [2] Bilgi        [3] Strings      [4] Disassembly\n");
    Log(" [5] Hexdump         [6] Map (loader) [7] Emulate      [8] ApiTrace\n");
    Log(" [9] Analiz (tumu)   [10] Pseudocode  [0] Shell'a don\n");
    LogInfo("Secim (numara yazin, detay icin shell komutlari daha guclu):");
    std::string line;
    std::getline(std::cin, line);
    line = Trim(line);
    if (line == "1") { LogInfo("Dosya yolu:"); std::getline(std::cin, line); CmdLoad({Trim(line)}); }
    else if (line == "2") CmdInfo({});
    else if (line == "3") CmdStrings({});
    else if (line == "4") CmdDis({});
    else if (line == "5") CmdHex({});
    else if (line == "6") CmdMap({});
    else if (line == "7") CmdEmu({"setup"});
    else if (line == "8") CmdApiTrace({});
    else if (line == "9") CmdAnalysis({"all"});
    else if (line == "10") CmdDecomp({});
}

// ----------------------------------------------------------------------------
// Ana döngü
// ----------------------------------------------------------------------------
bool Shell::ExecuteCommand(const std::string& line) {
    auto args = SplitArgs(line);
    if (args.empty()) return true;
    std::string cmd = ToLower(args[0]);
    std::vector<std::string> rest(args.begin() + 1, args.end());

    if (cmd == "help" || cmd == "h" || cmd == "?") CmdHelp(rest);
    else if (cmd == "load" || cmd == "open") CmdLoad(rest);
    else if (cmd == "info" || cmd == "i") CmdInfo(rest);
    else if (cmd == "sections" || cmd == "sec") CmdSections(rest);
    else if (cmd == "imports") CmdImports(rest);
    else if (cmd == "exports" || cmd == "exp") CmdExports(rest);
    else if (cmd == "strings" || cmd == "iz") CmdStrings(rest);
    else if (cmd == "funcs" || cmd == "fl") CmdFuncs(rest);
    else if (cmd == "dis" || cmd == "pd") CmdDis(rest);
    else if (cmd == "xref" || cmd == "xt") CmdXref(rest);
    else if (cmd == "decomp" || cmd == "dec") CmdDecomp(rest);
    else if (cmd == "types" || cmd == "ty") CmdTypes(rest);
    else if (cmd == "asm" || cmd == "a") CmdAsm(rest);
    else if (cmd == "patch") CmdPatch(rest);
    else if (cmd == "undo" || cmd == "redo") CmdUndoRedo(rest);
    else if (cmd == "hex" || cmd == "px") CmdHex(rest);
    else if (cmd == "map") CmdMap(rest);
    else if (cmd == "maplog") CmdMapLog(rest);
    else if (cmd == "emu") CmdEmu(rest);
    else if (cmd == "regs") CmdRegs(rest);
    else if (cmd == "apitrace" || cmd == "ait") CmdApiTrace(rest);
    else if (cmd == "trace" || cmd == "it") CmdTrace(rest);
    else if (cmd == "analysis" || cmd == "ax") CmdAnalysis(rest);
    else if (cmd == "dump") CmdDump(rest);
    else if (cmd == "save") CmdSave(rest);
    else if (cmd == "pdb") CmdPdb(rest);
    else if (cmd == "rtti") CmdRtti(rest);
    else if (cmd == "devirt") CmdDevirt(rest);
    else if (cmd == "deep") CmdDeep(rest);
    else if (cmd == "sig") CmdSig(rest);
    else if (cmd == "lumina") CmdLumina(rest);
    else if (cmd == "obfus") CmdObfus(rest);
    else if (cmd == "find") CmdFind(rest);
    else if (cmd == "bridge") CmdBridge(rest);
    else if (cmd == "proc") CmdProc(rest);
    else if (cmd == "script") CmdScript(rest);
    else if (cmd == "menu") CmdMenu(rest);
    else if (cmd == "quit" || cmd == "q" || cmd == "exit") return false;
    else LogWarn("Bilinmeyen komut: %s  (help yazin)", cmd.c_str());
    return true;
}

void Shell::Run(const std::string& preloadPath) {
    PrintBanner();
    if (!preloadPath.empty()) {
        CmdLoad({preloadPath});
    }
    LogInfo("Komutlar icin 'help', klasik menu icin 'menu' yazin. Cikis: quit");
    std::string line;
    while (true) {
        LogSetColor(LogColor::Magenta);
        std::fputs("gt> ", stdout);
        LogSetColor(LogColor::Default);
        if (!std::getline(std::cin, line)) break;
        line = Trim(line);
        if (line.empty()) continue;
        if (!ExecuteCommand(line)) break;
    }
    LogLine(LogColor::Magenta, "GOD TIER kapaniyor. Yine bekleriz!");
}

} // namespace gt
