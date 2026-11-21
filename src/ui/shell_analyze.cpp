// ============================================================================
//  i4M GodTier Engine — ui/shell.cpp  (2/2: disasm/decomp/emu/komut döngüsü)
// ============================================================================
#include "ui/shell.h"
#include "core/log.h"
#include "core/util.h"
#include "decomp/cfg.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>

namespace gt {

// ----------------------------------------------------------------------------
// Disassembly
// ----------------------------------------------------------------------------
void Shell::CmdDis(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    u64 va;
    size_t count = 20;
    if (a.empty()) {
        va = bin_->EntryPoint();
    } else {
        va = ParseAddr(a[0]);
        if (a.size() > 1) count = std::strtoul(a[1].c_str(), 0, 0);
    }
    if (!img_->InRange(va)) { LogErr("Adres goruntude degil: 0x%llx", (unsigned long long)va); return; }

    // fonksiyon mu? fonksiyon içindeyse fonksiyon adını göster
    const FuncInfo* f = az_->FunctionAt(va);
    if (f) LogLine(LogColor::White, "[%s]", f->name.c_str());

    u64 cur = va;
    for (size_t i = 0; i < count; i++) {
        u8 buf[32];
        if (!img_->ReadBytes(cur, buf, 32)) break;
        Ins x;
        if (!eng_->DisasmOne(buf, 32, cur, x)) {
            LogLine(LogColor::Red, "  0x%llx  (db 0x%02x)", (unsigned long long)cur, buf[0]);
            cur++;
            continue;
        }
        // sembol/ipucu
        std::string hint = az_->SymbolOrLabel(x.isIndirect ? x.memRef : x.target);
        if (hint.empty() && x.memRef) {
            std::string s;
            if (az_->IsStringAt(x.memRef, &s)) hint = "\"" + s.substr(0, 48) + "\"";
        }
        // xref sayısı
        auto xr = az_->XrefsTo(cur);
        std::string xrefNote = xr.empty() ? "" :
            ("  <" + std::to_string(xr.size()) + " xref>");
        Log("  0x%012llx  %-22s %-8s %-32s%s%s\n",
            (unsigned long long)cur,
            ToHexBytes(x.bytes, x.len).c_str(),
            x.mnemonic.c_str(), x.opStr.c_str(),
            hint.empty() ? "" : (" ; " + hint).c_str(),
            xrefNote.c_str());
        cur += x.len;
    }
}

void Shell::CmdXref(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    if (a.empty()) { LogInfo("Kullanim: xref <adres>  (adrese gelen referanslar)"); return; }
    u64 va = ParseAddr(a[0]);
    auto refs = az_->XrefsTo(va);
    if (refs.empty()) { LogInfo("0x%llx adresine xref yok", (unsigned long long)va); return; }
    static const char* tname[] = {"call", "jmp", "jcc", "data"};
    for (auto& r : refs)
        Log("  %s  0x%llx -> 0x%llx\n", tname[(int)r.type],
            (unsigned long long)r.src, (unsigned long long)r.dst);
}

// ----------------------------------------------------------------------------
// Decompiler
// ----------------------------------------------------------------------------
void Shell::CmdTypes(const std::vector<std::string>&) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    TypeInferer& ti = ps_->TI();
    LogLine(LogColor::Cyan, "== TIP VERITABANI (global iki fazli analiz) =============");
    LogInfo("Imzalar (cagiran/cagrilan tip yayilimi + govde kaniti):");
    for (auto& [va, f] : az_->Functions()) {
        const FuncSig* s = ti.SigOf(va);
        if (!s) continue;
        // isimsiz/onemsiz fonksiyonlari da goster (kisa tutmak icin PLT'leri atla)
        std::string line = "  " + s->SignatureLine();
        if (s->noreturn) line += "   [noreturn]";
        LogLine(LogColor::Gray, "%s", line.c_str());
    }
    auto& st = ti.Structs();
    if (st.empty()) { LogInfo("Geri kazanilan struct yok."); return; }
    LogOk("Geri kazanilan struct'lar: %zu", st.size());
    for (auto& s : st) {
        LogLine(LogColor::Yellow, "%s", s.Decl().c_str());
        // hangi fonksiyonlar kullaniyor?
        for (auto& [va, f] : az_->Functions()) {
            const FuncSig* fs = ti.SigOf(va);
            if (!fs) continue;
            for (int i = 0; i < fs->nArgs; i++)
                if (fs->argStruct[i] == s.id)
                    Log("    kullanir: %s (arg %d)\n", f.name.c_str(), i + 1);
        }
    }
}

void Shell::CmdDecomp(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    EnsureAnalyzed();
    if (a.empty()) {
        // tüm fonksiyonlar
        std::string out = ps_->DecompileAll(0);
        std::string path = "godtier_decomp.c";
        WriteFileBytes(path, std::vector<u8>(out.begin(), out.end()));
        LogOk("Tum fonksiyonlar decompile edildi -> %s (%zu bayt)", path.c_str(), out.size());
        return;
    }
    if (a[0] == "all") { CmdDecomp({}); return; }
    u64 va = ParseAddr(a[0]);
    if (!az_->FunctionStart(va)) {
        // fonksiyon değilse disassemble temelli deneme
        az_->DisassembleFunction(va);
    }
    std::string code = ps_->DecompileFunction(va);
    std::fputs(code.c_str(), stdout);
}

// ----------------------------------------------------------------------------
// Assembler + patch
// ----------------------------------------------------------------------------
void Shell::CmdAsm(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    if (a.empty()) { LogInfo("Kullanim: asm <adres> \"mov rax, 1; ret\"   — cikti: baytlar"); return; }
    u64 va = ParseAddr(a[0]);
    std::string code = a.size() > 1 ? a[1] : "";
    if (!asmEng_) {
        asmEng_ = std::make_unique<Assembler>();
        asmEng_->Init(bin_->GetArch());
        asmEng_->SetSymbolResolver([this](const std::string& sym) -> u64 {
            EnsureAnalyzed();
            for (auto& [v, f] : az_->Functions()) if (f.name == sym) return v;
            // dll.api icin IAT slotunun adresini dondur
            for (auto& d : bin_->Imports()) {
                std::string pfx = ToLower(d.name);
                size_t dot = pfx.find('.');
                if (dot != std::string::npos) pfx = pfx.substr(0, dot); // "kernel32"
                if (ToLower(sym).rfind(pfx + ".", 0) == 0) {
                    std::string fn = ToLower(sym).substr(pfx.size() + 1);
                    for (auto& f : d.funcs) if (ToLower(f.name) == fn) return f.iatVa;
                }
            }
            return 0;
        });
    }
    std::vector<u8> bytes;
    if (!asmEng_->Assemble(code, va, bytes)) return;
    LogOk("Assemble: %zu bayt: %s", bytes.size(), ToHexBytes(bytes.data(), bytes.size()).c_str());
    // round-trip dogrulama (Capstone ile geri coz)
    Ins chk;
    if (eng_ && eng_->DisasmOne(bytes.data(), bytes.size(), va, chk))
        LogLine(LogColor::Gray, "  round-trip: %s %s", chk.mnemonic.c_str(), chk.opStr.c_str());
    LogInfo("Uygulamak icin: patch 0x%llx %s", (unsigned long long)va,
            ToHexBytes(bytes.data(), std::min<size_t>(bytes.size(), 8)).c_str());
}

void Shell::CmdPatch(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    if (a.size() < 2) {
        LogInfo("Kullanim:");
        LogInfo("  patch <adres> b:DE AD BE EF   (hex baytlar)");
        LogInfo("  patch <adres> a:\"xor rax, rax\" (asm)  -> asm komutuyla da calisir");
        return;
    }
    u64 va = ParseAddr(a[0]);
    std::string mode = a[1];
    std::vector<u8> bytes;
    if (mode == "b" || mode == "-b") {
        std::string hex;
        for (size_t i = 2; i < a.size(); i++) hex += a[i];
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
            bytes.push_back((u8)std::strtoul(hex.substr(i, 2).c_str(), 0, 16));
    } else if (mode == "a" || mode == "-a" || (!mode.empty() && mode[0] != 'b')) {
        // asm modu
        std::string code;
        for (size_t i = (mode == "a" || mode == "-a") ? 2 : 1; i < a.size(); i++)
            code += (code.empty() ? "" : " ") + a[i];
        if (!asmEng_) CmdAsm({ToHex(va), code});
        else if (!asmEng_->Assemble(code, va, bytes)) return;
        if (bytes.empty()) { LogErr("Assemble basarisiz"); return; }
    }
    if (bytes.empty()) { LogErr("Bayt yok"); return; }
    patches_.Apply(*img_, va, bytes);
}

void Shell::CmdUndoRedo(const std::vector<std::string>& a) {
    if (!RequireMapped()) return;
    if (a.empty() || a[0] == "u" || a[0] == "undo") patches_.Undo(*img_);
    else patches_.Redo(*img_);
    LogLine(LogColor::Gray, "  defter: %zu undo / %zu redo hazir",
            patches_.UndoCount(), patches_.RedoCount());
}

// ----------------------------------------------------------------------------
// Hexdump
// ----------------------------------------------------------------------------
void Shell::CmdHex(const std::vector<std::string>& a) {
    if (!RequireMapped()) return;
    u64 va = a.empty() ? img_->Base() : ParseAddr(a[0]);
    size_t rows = a.size() > 1 ? (size_t)std::strtoul(a[1].c_str(), 0, 0) : 16;
    LogLine(LogColor::Cyan, "== HEXDUMP (mapped) ======================================");
    for (size_t r = 0; r < rows; r++) {
        u64 line = va + (u64)r * 16;
        u8 buf[16];
        if (!img_->ReadBytes(line, buf, 16)) break;
        Log("  %012llx  ", (unsigned long long)line);
        for (int i = 0; i < 16; i++) Log("%02x ", buf[i]);
        Log(" |");
        for (int i = 0; i < 16; i++)
            Log("%c", (buf[i] >= 0x20 && buf[i] < 0x7F) ? buf[i] : '.');
        Log("|\n");
    }
}

// ----------------------------------------------------------------------------
// Mapper (Windows loader emülasyonu)
// ----------------------------------------------------------------------------
void Shell::CmdMap(const std::vector<std::string>&) {
    if (!RequireBinary()) return;
    if (pe_) {
        LogInfo("Windows PE Loader emulasyonu (kod CALISTIRILMAZ):");
        mapRep_ = mapper_.MapPE(*pe_, *img_, MapOptions{});
    } else if (elf_) {
        mapRep_ = mapper_.MapELF(*elf_, *img_, MapOptions{});
    }
    analyzed_ = false; // görüntü değişti (reloc/IAT) → yeniden analiz gerekir
}

void Shell::CmdMapLog(const std::vector<std::string>&) {
    if (!mapRep_.success && mapRep_.log.empty()) { LogInfo("Once 'map' calistirin"); return; }
    LogLine(LogColor::Cyan, "== LOADER LOG ============================================");
    for (auto& l : mapRep_.log) LogLine(LogColor::Gray, "  %s", l.c_str());
    if (!mapRep_.tlsCallbacks.empty()) {
        LogLine(LogColor::Yellow, "  TLS callback'ler (calistirilmaz):");
        for (u64 cb : mapRep_.tlsCallbacks)
            Log("    0x%llx\n", (unsigned long long)cb);
    }
}

// ----------------------------------------------------------------------------
// Emülasyon
// ----------------------------------------------------------------------------
void Shell::CmdEmu(const std::vector<std::string>& a) {
    if (!RequireBinary() || !RequireMapped()) return;
    if (a.empty() || a[0] == "setup") {
        if (!mapRep_.success) {
            LogInfo("Once loader emulasyonu calisiyor (map)...");
            CmdMap({});
        }
        u64 start = (a.size() > 1) ? ParseAddr(a[1]) : bin_->EntryPoint();
        emu_ = std::make_unique<Emulator>();
        EmuConfig cfg;
        if (!emu_->Setup(*bin_, *img_, mapRep_, bin_->GetArch(), cfg)) {
            LogErr("Emulator kurulamadi: %s", emu_->LastError().c_str());
            emu_.reset();
            return;
        }
        LogInfo("Emulasyon basliyor: 0x%llx (Ctrl-C ile durdurulabilir 'emu stop')",
                (unsigned long long)start);
        emu_->Run(start);
        if (emu_->Finished()) LogOk("Emulasyon normal bitti");
        auto regs = emu_->DumpRegs();
        LogLine(LogColor::Cyan, "== SON REGISTER DURUMU ==================================");
        Emulator::PrintRegs(regs);
        Log("  iz: %zu komut | API cagrisi: %zu | hata: %zu\n",
            emu_->Trace().size(), emu_->ApiCalls().size(), emu_->Faults().size());
        return;
    }
    if (a[0] == "step") {
        if (!RequireEmu()) return;
        size_t n = a.size() > 1 ? (size_t)std::strtoul(a[1].c_str(), 0, 0) : 1;
        if (emu_->Step(n)) {
            auto r = emu_->DumpRegs();
            Log("  rip=0x%llx rsp=0x%llx rax=0x%llx\n",
                r.rip, r.rsp, r.rax);
        } else LogWarn("Adim atilamadi: %s", emu_->LastError().c_str());
        return;
    }
    if (a[0] == "stop") { if (RequireEmu()) emu_->Stop(); return; }
    if (a[0] == "mem") {
        if (!RequireEmu()) return;
        u64 va = a.size() > 1 ? ParseAddr(a[1]) : emu_->HeapBase();
        u8 buf[16];
        if (emu_->ReadMem(va, buf, 16)) {
            Log("  0x%llx: %s\n", (unsigned long long)va, ToHexBytes(buf, 16).c_str());
        } else LogErr("Okunamadi");
        return;
    }
    LogInfo("Kullanim: emu [setup <adres>] | emu step [n] | emu stop | emu mem <adres>");
}

void Shell::CmdRegs(const std::vector<std::string>&) {
    if (!RequireEmu()) return;
    auto r = emu_->DumpRegs();
    Emulator::PrintRegs(r);
}

void Shell::CmdApiTrace(const std::vector<std::string>&) {
    if (!RequireEmu()) return;
    auto& calls = emu_->ApiCalls();
    if (calls.empty()) { LogInfo("API cagrisi yakalanmadi (emu setup sonrasi buraya bakin)"); return; }
    LogLine(LogColor::Cyan, "== API TRACE (shadow IAT yakalamalari) ==================");
    size_t i = 0;
    for (auto& c : calls) {
        if (i++ >= 100) { LogLine(LogColor::Gray, "  ... %zu toplam", calls.size()); break; }
        Log("  %-12s %-28s (0x%llx, 0x%llx, 0x%llx, 0x%llx) -> 0x%llx  %s\n",
            c.dll.c_str(), c.func.c_str(),
            (unsigned long long)c.args[0], (unsigned long long)c.args[1],
            (unsigned long long)c.args[2], (unsigned long long)c.args[3],
            (unsigned long long)c.ret, c.note.c_str());
    }
}

void Shell::CmdTrace(const std::vector<std::string>& a) {
    if (!RequireEmu()) return;
    size_t n = a.empty() ? 40 : (size_t)std::strtoul(a[0].c_str(), 0, 0);
    auto& t = emu_->Trace();
    size_t start = t.size() > n ? t.size() - n : 0;
    LogLine(LogColor::Cyan, "== INSTRUCTION TRACE (son %zu / %zu) =====================",
            std::min(n, t.size()), t.size());
    for (size_t i = start; i < t.size(); i++)
        Log("  0x%012llx  %s\n", (unsigned long long)t[i].addr, t[i].text.c_str());
}

} // namespace gt
