// ============================================================================
//  i4M GodTier Engine — ui/shell.h
//  Etkileşimli komut kabuğu. i4M konsol menüsünün + rizin komut dilinin
//  birleşimi. Tüm motor modülleri buradan yönetilir.
// ============================================================================
#pragma once
#include "format/binary.h"
#include "format/image.h"
#include "format/pe.h"
#include "format/elf.h"
#include "disasm/engine.h"
#include "disasm/analyzer.h"
#include "asm/assembler.h"
#include "mapper/mapper.h"
#include "emulate/emulator.h"
#include "decomp/pseudocode.h"
#include "analysis/features.h"
#include "analysis/deepscan.h"
#include "analysis/sigs.h"
#include "analysis/obfus.h"
#include "proc/process.h"
#include <memory>
#include <string>

namespace gt {

class Shell {
public:
    Shell();
    ~Shell() = default;

    void Run(const std::string& preloadPath = "");
    bool ExecuteCommand(const std::string& line);   // tek komut (script modu için de)
    // v6: script satırı — $değişken/set/eval/echo/if ön-işlemesi + komut
    // (test edilebilirlik için ayrı metod; CmdScript bunu çağırır)
    bool ScriptLine(const std::string& line);
    const std::map<std::string, std::string>& ScriptVars() const { return scriptVars_; }

private:
    // durum
    std::unique_ptr<Binary> bin_;     // sahiplik burada
    PE* pe_ = nullptr;                // bin_'e alias (sahiplik YOK — tip erişimi)
    ELF* elf_ = nullptr;              // bin_'e alias (sahiplik YOK)
    std::unique_ptr<MappedImage> img_;
    std::unique_ptr<DisasmEngine> eng_;
    std::unique_ptr<Analyzer> az_;
    std::unique_ptr<Pseudocoder> ps_;
    std::unique_ptr<Assembler> asmEng_;
    Mapper mapper_;
    std::unique_ptr<Emulator> emu_;
    MapReport mapRep_;
    PatchBook patches_;
    ProcessAccess proc_;
    std::string loadedPath_;
    bool analyzed_ = false;
    std::map<std::string, std::string> scriptVars_;   // v6: $değişkenler

    // komut işleyicileri
    void CmdHelp(const std::vector<std::string>& a);
    void CmdLoad(const std::vector<std::string>& a);
    void CmdInfo(const std::vector<std::string>& a);
    void CmdSections(const std::vector<std::string>& a);
    void CmdImports(const std::vector<std::string>& a);
    void CmdExports(const std::vector<std::string>& a);
    void CmdStrings(const std::vector<std::string>& a);
    void CmdFuncs(const std::vector<std::string>& a);
    void CmdDis(const std::vector<std::string>& a);
    void CmdXref(const std::vector<std::string>& a);
    void CmdDecomp(const std::vector<std::string>& a);
    void CmdTypes(const std::vector<std::string>& a);
    void CmdAsm(const std::vector<std::string>& a);
    void CmdHex(const std::vector<std::string>& a);
    void CmdPatch(const std::vector<std::string>& a);
    void CmdUndoRedo(const std::vector<std::string>& a);
    void CmdMap(const std::vector<std::string>& a);
    void CmdMapLog(const std::vector<std::string>& a);
    void CmdEmu(const std::vector<std::string>& a);
    void CmdRegs(const std::vector<std::string>& a);
    void CmdApiTrace(const std::vector<std::string>& a);
    void CmdTrace(const std::vector<std::string>& a);
    void CmdAnalysis(const std::vector<std::string>& a);
    void CmdDump(const std::vector<std::string>& a);
    void CmdSave(const std::vector<std::string>& a);
    void CmdProc(const std::vector<std::string>& a);
    void CmdPdb(const std::vector<std::string>& a);
    void CmdRtti(const std::vector<std::string>& a);      // v7: RTTI atlası
    void CmdDevirt(const std::vector<std::string>& a);    // v7: devirt-pro
    void CmdDeep(const std::vector<std::string>& a);      // v4: derin keşif
    void CmdSig(const std::vector<std::string>& a);       // v4: imza motoru
    void CmdLumina(const std::vector<std::string>& a);    // v6: isim havuzu
    void CmdObfus(const std::vector<std::string>& a);     // v4: obfuscation raporu
    void CmdFind(const std::vector<std::string>& a);      // v4: arama
    void CmdBridge(const std::vector<std::string>& a);
    void CmdScript(const std::vector<std::string>& a);
    void CmdMenu(const std::vector<std::string>& a);   // klasik i4M numaralı menü

    // yardımcılar
    bool RequireBinary();
    bool RequireMapped();
    bool RequireEmu();
    void EnsureAnalyzed();
    u64 ParseAddr(const std::string& s);               // hex/dec/sembol
    void PrintBanner();
    std::vector<std::string> SplitArgs(const std::string& line);
};

} // namespace gt
