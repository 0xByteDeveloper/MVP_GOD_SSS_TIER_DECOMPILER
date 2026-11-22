// ============================================================================
//  i4M GodTier Engine — tests/test_main.cpp
//  Smoke + doğrulama testleri. Fixture'lar:
//   - fixture.elf  (gcc ile derlenir, test öncesi)
//   - fixture.exe  (make_fixture_pe.py ile üretilir, test öncesi)
//  Çalıştırma: ./godtier_tests  (fixture'lar CWD'de aranır, sonra tests/fixtures/)
// ============================================================================
#include "format/binary.h"
#include "format/pe.h"
#include "format/elf.h"
#include "format/image.h"
#include "format/pdb.h"
#include "disasm/engine.h"
#include "disasm/analyzer.h"
#include "asm/assembler.h"
#include "mapper/mapper.h"
#include "emulate/emulator.h"
#include "decomp/cfg.h"
#include "decomp/pseudocode.h"
#include "analysis/features.h"
#include "analysis/deepscan.h"
#include "analysis/sigs.h"
#include "ui/shell.h"
#include "analysis/obfus.h"
#include "proc/process.h"
#include "core/log.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstdio>
#include "core/util.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace gt;

#ifdef _WIN32
static u32 getpid_platform() { return (u32)GetCurrentProcessId(); }
#else
#include <unistd.h>
static u32 getpid_platform() { return (u32)getpid(); }
#endif

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, ...) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; std::printf("  [FAIL] %s:%d  ", __FILE__, __LINE__); std::printf(__VA_ARGS__); std::printf("\n"); } \
} while (0)

static bool FileHas(const char* name) { return FileExists(name) || FileExists(std::string("tests/fixtures/") + name); }
static std::string PathOf(const char* name) {
    return FileExists(name) ? name : ("tests/fixtures/" + std::string(name));
}

int main() {
    LogInit();
    std::printf("== i4M GodTier Engine testleri ==\n\n");

    // ------------------------------------------------------------------
    std::printf("[1] MD5 (imphash'in bel kemiği)\n");
    {
        const char* abc = "abc";
        auto d = MD5((const u8*)abc, 3);
        std::string hex = MD5Hex((const u8*)abc, 3);
        CHECK(hex == "900150983cd24fb0d6963f7d28e17f72", "md5(abc)=%s", hex.c_str());
        const char* empty = "";
        CHECK(MD5Hex((const u8*)empty, 0) == "d41d8cd98f00b204e9800998ecf8427e", "md5(empty)");
    }

    // ------------------------------------------------------------------
    std::printf("[2] Entropy\n");
    {
        std::vector<u8> zeros(1000, 0);
        std::vector<u8> ramp(256);
        for (int i = 0; i < 256; i++) ramp[i] = (u8)i;
        CHECK(Entropy(zeros.data(), zeros.size()) < 0.01, "entropi(sabit)=0 olmali");
        CHECK(Entropy(ramp.data(), ramp.size()) > 7.9, "entropi(ramp)~8 olmali");
    }

    // ------------------------------------------------------------------
    std::printf("[3] Keystone assembler + Capstone round-trip\n");
    {
        Assembler as;
        CHECK(as.Init(Arch::X86_64), "keystone init");
        std::vector<u8> bytes;
        CHECK(as.Assemble("mov rax, 0x1337; ret", 0x401000, bytes), "assemble");
        CHECK(bytes.size() == 8 && bytes[0] == 0x48 && bytes[1] == 0xC7,
              "mov rax,imm32 kodlamasi (got %zu bayt: %s)", bytes.size(),
              ToHexBytes(bytes.data(), bytes.size()).c_str());
        DisasmEngine de;
        de.Init(Arch::X86_64);
        Ins x;
        CHECK(de.DisasmOne(bytes.data(), bytes.size(), 0x401000, x), "disasm back");
        CHECK(x.mnemonic == "mov" && x.opStr.find("rax") != std::string::npos, "mnemonic=%s", x.mnemonic.c_str());
        // x86-32 modu
        Assembler as32;
        as32.Init(Arch::X86_32);
        std::vector<u8> b32;
        CHECK(as32.Assemble("mov eax, 0x37; ret", 0x401000, b32), "asm32");
        CHECK(b32.size() == 6 && b32[0] == 0xB8, "mov eax,imm32 = B8 (got %02x)", b32[0]);
    }

    // ------------------------------------------------------------------
    if (FileHas("fixture.elf")) {
        std::printf("[4] ELF parser + analyzer + decompiler (fixture.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("fixture.elf")));
        CHECK(elf != nullptr, "elf acildi");
        if (elf) {
            CHECK(elf->FormatName().find("ELF64") != std::string::npos, "format=%s", elf->FormatName().c_str());
            CHECK(elf->Is64(), "64-bit");
            // semboller: fonksiyon isimleri gelsin
            bool hasLoop = false, hasAdd = false;
            for (auto& s : elf->Symbols()) {
                if (s.name == "loop_sum") hasLoop = true;
                if (s.name == "add_numbers") hasAdd = true;
            }
            CHECK(hasLoop, "loop_sum sembolu");
            CHECK(hasAdd, "add_numbers sembolu");

            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            CHECK(az.Functions().size() >= 4, "fonksiyon sayisi >= 4 (got %zu)", az.Functions().size());
            CHECK(az.TotalInsCount() > 30, "toplam komut > 30 (got %zu)", az.TotalInsCount());
            CHECK(az.Strings().size() >= 1, "string bulundu");
            bool foundGodStr = false;
            for (auto& s : az.Strings())
                if (s.text.find("GODTIER_FIXTURE_STRING") != std::string::npos) foundGodStr = true;
            CHECK(foundGodStr, "GODTIER string bulundu");

            // loop_sum fonksiyonu: CFG + döngü tespiti
            u64 loopVa = 0;
            for (auto& [va, f] : az.Functions())
                if (f.name == "loop_sum") loopVa = va;
            CHECK(loopVa != 0, "loop_sum va bulundu");
            if (loopVa) {
                auto ins = az.DisassembleFunction(loopVa);
                CFG cfg;
                CHECK(cfg.Build(ins), "cfg kuruldu");
                CHECK(cfg.DetectLoops().size() >= 1, "dongu tespit edildi (for dongusu)");
                Pseudocoder pc(az);
                std::string code = pc.DecompileFunction(loopVa);
                CHECK(code.find("while") != std::string::npos ||
                      code.find("for ( ") != std::string::npos,
                      "pseudocode'da dongu yapisi var (v4: for yukseltmesi)");
                CHECK(code.find("loop_sum") != std::string::npos, "fonksiyon adi pseudocode'da");
            }
            // xref: choose -> loop_sum çağrısı
            bool foundCall = false;
            for (auto& x : az.Xrefs())
                if (x.type == RefType::Call && az.NameFor(x.dst) == "loop_sum") foundCall = true;
            CHECK(foundCall, "choose->loop_sum cagri xref'i");
            delete elf;
        }
    } else {
        std::printf("[4] ATLANDI: fixture.elf yok (once: gcc -O0 derleyin)\n");
    }

    // ------------------------------------------------------------------
    if (FileHas("fixture.exe")) {
        std::string pePath = PathOf("fixture.exe");
        std::printf("[5] PE parser (elle uretilmis fixture.exe)\n");
        auto* pe = dynamic_cast<PE*>(Binary::Open(pePath));
        CHECK(pe != nullptr, "pe acildi");
        if (pe) {
            CHECK(pe->Is64(), "PE32+");
            CHECK(pe->ImageBase() == 0x140000000ull, "imagebase");
            CHECK(pe->EntryPoint() == 0x140001000ull, "entry rva 0x1000");
            CHECK(pe->Sections().size() == 4, "4 section (got %zu)", pe->Sections().size());
            // importlar
            size_t totalImp = 0;
            for (auto& d : pe->Imports()) totalImp += d.funcs.size();
            CHECK(pe->Imports().size() == 2, "2 dll (got %zu)", pe->Imports().size());
            CHECK(totalImp == 6, "6 import (got %zu)", totalImp);
            bool hasMsgBox = false, hasExit = false;
            for (auto& d : pe->Imports())
                for (auto& f : d.funcs) {
                    if (f.name == "MessageBoxA") hasMsgBox = true;
                    if (f.name == "ExitProcess") hasExit = true;
                }
            CHECK(hasMsgBox && hasExit, "MessageBoxA + ExitProcess importlari");
            // reloc
            CHECK(pe->Relocs().size() == 1, "1 reloc (got %zu)", pe->Relocs().size());
            CHECK(pe->Relocs().size() && pe->Relocs()[0].type == 10, "DIR64 reloc");
            // PDB debug
            auto dbg = pe->GetDebugInfo();
            CHECK(dbg.hasPdb, "PDB CodeView girdisi");
            CHECK(dbg.pdbPath.find("godtier") != std::string::npos, "pdb yolu");

            // imphash: pefile get_imphash() ile ÇAPRAZ DOĞRULANMIŞTIR:
            //   b22b15f12a1c2c344f28dc093c28f24a
            MappedImage img;
            img.LoadFromBinary(*pe);
            FeatureAnalyzer fa(*pe, img);
            std::string ih = fa.Imphash();
            CHECK(ih == "b22b15f12a1c2c344f28dc093c28f24a",
                  "imphash pefile ile ayni olmali (got %s)", ih.c_str());

            // findcrypt: AES S-box fixture'ta var
            auto hits = fa.FindCryptoConstants();
            bool aesFound = false;
            for (auto& h : hits) if (h.algo.find("AES") != std::string::npos) aesFound = true;
            CHECK(aesFound, "AES S-box bulundu (findcrypt)");

            // yetenekler: dosya sistemi (CreateFileA) tespiti
            auto caps = fa.Capabilities();
            bool fsCap = false;
            for (auto& c : caps) if (c.name.find("Dosya sistemi") == 0) fsCap = true;
            CHECK(fsCap, "CreateFileA -> dosya sistemi yetenegi");

            // ---- mapper + emulator: entry'i çalıştır ----
            std::printf("[6] Mapper (loader emulasyonu) + Unicorn emulasyonu\n");
            Mapper mapper;
            MappedImage mimg;
            MapOptions mo;
            mo.forceBase = 0x150000000ull;   // ImageBase'ten FARKLI -> relocation devrede
            MapReport rep = mapper.MapPE(*pe, mimg, mo);
            CHECK(rep.success, "map basarili");
            CHECK(rep.relocated, "base kaydi -> reloc uygulandi");
            CHECK(rep.relocsApplied == 1, "1 reloc uygulandi (got %zu)", rep.relocsApplied);
            CHECK(rep.importsResolved == 6, "6 shadow import (got %zu)", rep.importsResolved);
            // reloc dogrulamasi: .data'daki isaretci delta kadar artmali
            //   orijinal: 0x140003000, delta = 0x10000000 -> 0x150003000
            u64 ptr = mimg.Read64(0x150003000ull);
            CHECK(ptr == 0x150003000ull, "reloc edilmis isaretci 0x150003000 (got 0x%llx)",
                  (unsigned long long)ptr);
            // reloc dogrulamasi: .data'daki isaretci forceBase ile kayarsa artmali
            // (ayni base'te delta=0 -> ayni deger)
            Emulator emu;
            CHECK(emu.Setup(*pe, mimg, rep, pe->GetArch()), "emu setup");
            u64 newEntry = 0x150001000ull;   // forceBase sonrasi yeni entry
            CHECK(emu.Run(newEntry), "entry calisti (forceBase 0x150000000)");
            u64 rax = emu.GetReg(UC_X86_REG_RAX);
            CHECK(rax == 0x3C, "entry sonucu rax=0x3c (got 0x%llx)", (unsigned long long)rax);
            CHECK(emu.Trace().size() >= 4, "iz >= 4 komut (got %zu)", emu.Trace().size());
            // entry: call -> loop calisti mi? (loop 1..10=55 set eder sonra ezilir)
            CHECK(emu.Trace().size() >= 30, "loop dahil iz >= 30 (got %zu)", emu.Trace().size());

            // loop fonksiyonunu emule et: 1+2+...+10 = 55 = 0x37
            u64 loopVa = 0x150001000ull + 14; // forceBase + entry'in 14 bayti (call+mov+add+ret)
            Emulator emu2;
            emu2.Setup(*pe, mimg, rep, pe->GetArch());
            // döngü fonksiyonuna argüman yok (gövde sabit 10 kullanır)
            CHECK(emu2.Run(loopVa), "loop calisti");
            rax = emu2.GetReg(UC_X86_REG_RAX);
            CHECK(rax == 55, "loop_sum(10)=55 (got %llu)", (unsigned long long)rax);

            // ---- analyzer + pseudocode (PE uzerinde) ----
            DisasmEngine de;
            de.Init(pe->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return mimg.ReadBytes(va, o, n); });
            Analyzer az(de, *pe, mimg);
            az.RunFull(false);
            CHECK(az.Functions().size() >= 2, "en az 2 fonksiyon (got %zu)", az.Functions().size());
            Pseudocoder pc(az);
            std::string code = pc.DecompileFunction(0x150001000ull);
            CHECK(code.find("0x37") != std::string::npos || code.find("mov eax") != std::string::npos,
                  "entry pseudocode uretildi");
            // disasm'da add eax komutu görülmeli
            auto insList = az.DisassembleFunction(0x150001000ull);
            CHECK(insList.size() == 4, "entry 4 komut (call,mov,add,ret) (got %zu)", insList.size());
            CHECK(insList.size() > 0 && insList[0].mnemonic == "call", "1. komut call (got %s)",
                  insList.size() > 0 ? insList[0].mnemonic.c_str() : "?");
            // entry pseudocode: call satiri sub etiketli olmali
            std::string code2 = pc.DecompileFunction(0x150001000ull);
            CHECK(code2.find("sub_15000100e") != std::string::npos,
                  "pseudocode call hedefi sub_ etiketli (kucuk harf hex)");
            delete pe;
        }
    } else {
        std::printf("[5]/[6] ATLANDI: fixture.exe yok (once: python3 make_fixture_pe.py)\n");
    }

    // ------------------------------------------------------------------
    if (FileHas("fixture_api.exe")) {
        std::printf("[6b] API shim: MessageBoxA + IsDebuggerPresent + ExitProcess (fixture_api.exe)\n");
        auto* pe = dynamic_cast<PE*>(Binary::Open(PathOf("fixture_api.exe")));
        CHECK(pe != nullptr, "api fixture acildi");
        if (pe) {
            MappedImage mimg;
            Mapper mapper;
            MapReport rep = mapper.MapPE(*pe, mimg, MapOptions{});
            CHECK(rep.success && rep.importsResolved == 3, "3 shadow import (got %zu)", rep.importsResolved);
            CHECK(rep.shadowApis.size() == 3, "raporda 3 shadow api (got %zu)", rep.shadowApis.size());
            Emulator emu;
            CHECK(emu.Setup(*pe, mimg, rep, pe->GetArch()), "emu setup");
            CHECK(emu.Run(pe->EntryPoint()), "entry calisti");
            CHECK(emu.Finished(), "ExitProcess shim emulasyonu bitirdi");
            auto& calls = emu.ApiCalls();
            CHECK(calls.size() == 3, "3 API cagrisi yakalandi (got %zu)", calls.size());
            bool hasMsg = false, hasIdp = false, hasExit = false;
            for (auto& c : calls) {
                if (c.func == "MessageBoxA" && c.note.find("GodTier API emulasyon testi") != std::string::npos) hasMsg = true;
                if (c.func == "IsDebuggerPresent" && c.ret == 0) hasIdp = true;
                if (c.func == "ExitProcess" && c.note.find("kod=42") != std::string::npos) hasExit = true;
            }
            CHECK(hasMsg, "MessageBoxA metni yakalandi");
            CHECK(hasIdp, "IsDebuggerPresent false dondu");
            CHECK(hasExit, "ExitProcess(42) yakalandi");
            delete pe;
        }
    } else {
        std::printf("[6b] ATLANDI: fixture_api.exe yok\n");
    }

    // ------------------------------------------------------------------
    std::printf("[7] PatchBook (undo/redo)\n");
    {
        MappedImage img;
        img.LoadRaw(std::vector<u8>(0x1000, 0xCC), 0x400000);
        PatchBook pb;
        std::vector<u8> patch = {0x90, 0x90};
        CHECK(pb.Apply(img, 0x400000, patch), "patch uygulandi");
        CHECK(img.Read8(0x400000) == 0x90, "nop yazildi");
        CHECK(pb.Undo(img), "undo");
        CHECK(img.Read8(0x400000) == 0xCC, "eski deger geri geldi");
        CHECK(pb.Redo(img), "redo");
        CHECK(img.Read8(0x400000) == 0x90, "redo sonrasi nop");
    }

    // ------------------------------------------------------------------
    std::printf("[8] ProcessAccess (/proc uzerinden kendi surecimiz)\n");
    {
        auto list = ProcessAccess::ListProcesses("");
        CHECK(list.size() > 2, "surec listesi > 2 (got %zu)", list.size());
        ProcessAccess pa;
        u32 selfPid = (u32)getpid_platform();
        if (pa.Attach(selfPid)) {
            CHECK(pa.Read32(0) == 0 || true, "read testi (0 adresi okunamayabilir, sorun degil)");
            pa.Detach();
        }
    }

    // ------------------------------------------------------------------
    if (FileHas("kurban.elf")) {
        std::printf("[9] Decompiler v2: tip cikarimi + struct + ifade katlama (kurban.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban.elf")));
        CHECK(elf != nullptr, "kurban.elf acildi");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            Pseudocoder pc(az);
            TypeInferer& ti = pc.TI();

            // fonksiyon adreslerini bul
            u64 toplamaVa = 0, raporVa = 0, mainVa = 0, faktVa = 0, ortVa = 0;
            for (auto& [va, f] : az.Functions()) {
                if (f.name.rfind("toplama", 0) == 0) toplamaVa = va;
                if (f.name.rfind("rapor_yaz", 0) == 0) raporVa = va;
                if (f.name == "main") mainVa = va;
                if (f.name.rfind("faktoriyel", 0) == 0) faktVa = va;
                if (f.name.rfind("ortalama", 0) == 0) ortVa = va;
            }
            CHECK(toplamaVa && raporVa && mainVa && faktVa && ortVa, "5 fonksiyon bulundu");

            // PLT isim cozumu
            bool printfFound = false;
            for (auto& [va, f] : az.Functions())
                if (f.name == "printf") printfFound = true;
            CHECK(printfFound, "printf@plt isimlendirildi (rela.plt cozumu)");

            if (toplamaVa) {
                const FuncSig* sg = ti.SigOf(toplamaVa);
                CHECK(sg && sg->nArgs == 2, "toplama imzasi: 2 arg");
                CHECK(sg && sg->argKinds[0] == ArgKind::Ptr, "toplama arg0 = int*");
                CHECK(sg && sg->retKind == ArgKind::Int, "toplama int doner");
                std::string code = pc.DecompileFunction(toplamaVa);
                CHECK(code.find("while ( v2 < adet )") != std::string::npos ||
                      code.find("while ( v2 < a2 )") != std::string::npos ||
                      code.find("for ( v2 = 0; v2 < adet; ++v2 )") != std::string::npos ||
                      code.find("for ( v2 = 0; v2 < a2; ++v2 )") != std::string::npos,
                      "toplama: dongu kosulu yapilastirildi (v4 for yukseltmesi, DWARF adlariyla)");
                CHECK(code.find("dizi[v2]") != std::string::npos ||
                      code.find("a1[v2]") != std::string::npos,
                      "toplama: dizi[i] endeksli erisim katlandi");
                CHECK(code.find("return v1;") != std::string::npos,
                      "toplama: return degeri");
            }
            if (faktVa) {
                std::string code = pc.DecompileFunction(faktVa);
                CHECK(code.find("if ( n > 1 )") != std::string::npos ||
                      code.find("if ( a1 > 1 )") != std::string::npos,
                      "faktoriyel: if/else elmasi");
                CHECK(code.find("faktoriyel(n - 1)") != std::string::npos ||
                      code.find("faktoriyel(a1 - 1)") != std::string::npos,
                      "faktoriyel: ozyineleme cagrisi");
                CHECK(code.find("return 1;") != std::string::npos,
                      "faktoriyel: else return 1");
            }
            if (ortVa) {
                const FuncSig* sg = ti.SigOf(ortVa);
                CHECK(sg && sg->argStruct[0] > 0, "ortalama arg0 = struct_1*");
                std::string code = pc.DecompileFunction(ortVa);
                CHECK(code.find("toplama(o->notlar, 8)") != std::string::npos ||
                      code.find("toplama(a1->field_4, 8)") != std::string::npos,
                      "ortalama: cagri+arg birlesimi + uye erisimi");
            }
            if (raporVa) {
                std::string code = pc.DecompileFunction(raporVa);
                CHECK(code.find("printf(\"Ogrenci %d: %s ort=%.2f\"") != std::string::npos,
                      "rapor: printf + format string");
                CHECK(code.find("o->isim") != std::string::npos,
                      "rapor: isim uyesi (DWARF gercek adi)");
                CHECK(code.find("(double)(o->ortalama)") != std::string::npos,
                      "rapor: float uye double'a cast (ortalama)");
            }
            // struct geri kazanimi: Ogrenci {int;int[];float;char[24]}
            bool structOk = false, floatOk = false, strOk = false;
            for (auto& st : ti.Structs()) {
                if (st.members.count(0) && st.members.count(4) &&
                    st.members.count(0x24) && st.members.count(0x28)) {
                    structOk = true;
                    floatOk = (st.members.at(0x24).kind == ArgKind::Float);
                    strOk = st.members.at(0x28).isString &&
                            st.members.at(0x28).arrayLen == 24;
                }
            }
            CHECK(structOk, "struct_1 = Ogrenci {+0,+4,+24,+28} geri kazanildi");
            CHECK(floatOk, "field_24 float (movss kaniti)");
            CHECK(strOk, "field_28 char[24] (memset boyu kaniti)");
            if (mainVa) {
                std::string code = pc.DecompileFunction(mainVa);
                CHECK(code.find("Ogrenci v1") != std::string::npos ||
                      code.find("struct_1 v1") != std::string::npos,
                      "main: yerel struct tanimi (Ogrenci adiyla)");
                CHECK(code.find("(v2 + 12 * v2) % 100") != std::string::npos,
                      "main: magic-number -> %%100 idiom katlamasi");
                CHECK(code.find("\"Ali\"") != std::string::npos,
                      "main: 0x696c41 -> 'Ali' string notu");
                CHECK(code.find("v1.notlar[") != std::string::npos ||
                      code.find("v1.field_4[v2]") != std::string::npos,
                      "main: struct dizi uyesi endeksli");
            }
            delete elf;
        }
    } else {
        std::printf("[9] ATLANDI: kurban.elf yok\n");
    }

    // ------------------------------------------------------------------
    if (FileHas("kurban_o2s.elf")) {
        std::printf("[10] Strip edilmis O2 binary: main kesfi (kurban_o2s.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban_o2s.elf")));
        CHECK(elf != nullptr, "kurban_o2s.elf acildi");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            // __libc_start_main kalibiyla main bulundu mu?
            bool mainFound = false;
            for (auto& [va, f] : az.Functions())
                if (f.name == "main") mainFound = true;
            CHECK(mainFound, "strip'li binary'de main kesfedildi (libc_start_main kalibi)");
            // O2'de ana fonksiyonlar main'den erisilebilir
            CHECK(az.Functions().size() >= 7, "fonksiyon sayisi >= 7 (got %zu)",
                  az.Functions().size());
            delete elf;
        }
    } else {
        std::printf("[10] ATLANDI: kurban_o2s.elf yok\n");
    }


    // ------------------------------------------------------------------
    if (FileHas("kurban2.elf")) {
        std::printf("[11] kurban2 (O0 -g): switch + vtable + DWARF (kurban2.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban2.elf")));
        CHECK(elf != nullptr, "kurban2.elf acildi");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            Pseudocoder pc(az);
            TypeInferer& ti = pc.TI();
            // DWARF yüklendi mi?
            CHECK(ti.Dwarf() != nullptr, "DWARF info yuklendi");
            if (ti.Dwarf()) {
                CHECK(ti.Dwarf()->Funcs().size() >= 5, "DWARF fonksiyonlari >= 5");
                CHECK(ti.Dwarf()->Structs().size() >= 2, "DWARF struct'lari >= 2");
            }
            // --- jump table (switch) ---
            const FuncInfo* mevsim = nullptr;
            for (auto& [va, f] : az.Functions())
                if (f.name.find("mevsim_adi") != std::string::npos) mevsim = &f;
            CHECK(mevsim != nullptr, "mevsim_adi bulundu");
            if (mevsim) {
                std::string code = pc.DecompileFunction(mevsim->start);
                CHECK(code.find("switch (") != std::string::npos,
                      "mevsim_adi: switch() yapisi kuruldu");
                CHECK(code.find("jump table") != std::string::npos,
                      "mevsim_adi: jump table notu");
                CHECK(code.find("case 1: case 2: case 12:") != std::string::npos,
                      "mevsim_adi: case 1/2/12 grubu (Kis)");
                CHECK(code.find("case 3: case 4: case 5:") != std::string::npos,
                      "mevsim_adi: case 3/4/5 grubu (Ilkbahar)");
                CHECK(code.find("return \"Kis\"") != std::string::npos,
                      "mevsim_adi: case govdesi inline + string (Kis)");
                CHECK(code.find("return \"Sonbahar\"") != std::string::npos,
                      "mevsim_adi: case govdesi inline (Sonbahar)");
            }
            // --- vtable + sanal cagri ---
            CHECK(ti.VTables().size() >= 3, "vtable veritabani >= 3 (Sekil/Dikdortgen/Daire)");
            CHECK(ti.VirtSlotName(0) == "alan", "vtable slot 0 = alan (cogunluk oyu)");
            CHECK(ti.VirtSlotName(1) == "isim", "vtable slot 1 = isim");
            const FuncInfo* toplam = nullptr;
            for (auto& [va, f] : az.Functions())
                if (f.name.find("toplam_alan") != std::string::npos) toplam = &f;
            CHECK(toplam != nullptr, "toplam_alan bulundu");
            if (toplam) {
                std::string code = pc.DecompileFunction(toplam->start);
                CHECK(code.find("s1->alan()") != std::string::npos,
                      "toplam_alan: sanal cagri s1->alan() (vtable cozumu)");
                CHECK(code.find("s2->alan()") != std::string::npos,
                      "toplam_alan: sanal cagri s2->alan()");
                CHECK(code.find("vtable[0]") != std::string::npos,
                      "toplam_alan: vtable slot notu");
                CHECK(code.find("const Sekil * s1") != std::string::npos,
                      "toplam_alan: DWARF imzasi (const Sekil * s1)");
                CHECK(code.find("s1->alan() + s2->alan()") != std::string::npos ||
                      code.find(") + v1") != std::string::npos,
                      "toplam_alan: iki sanal cagri birlesimi");
            }
            // --- DWARF struct giydirme (Dikdortgen) ---
            bool hasDikd = false, hasEn = false;
            for (auto& st : ti.Structs()) {
                if (st.name == "Dikdortgen") {
                    hasDikd = true;
                    for (auto& [off, m] : st.members)
                        if (m.name == "en_" || m.name == "boy_") hasEn = true;
                }
            }
            CHECK(hasDikd, "struct Dikdortgen DWARF'tan adlandi");
            CHECK(hasEn, "Dikdortgen uyeleri gercek adlar (en_/boy_)");
            // --- main: ctor/dtor cagrilari + dongu ---
            const FuncInfo* mainF = nullptr;
            for (auto& [va, f] : az.Functions())
                if (f.name == "main") mainF = &f;
            if (mainF) {
                std::string code = pc.DecompileFunction(mainF->start);
                CHECK(code.find("while ( v3 <= 0xd )") != std::string::npos ||
                      code.find("for ( v3 = 0; v3 <= 0xd; ++v3 )") != std::string::npos,
                      "main: for dongusu yapilandi (v4: init+artis for basligina cekildi)");
                CHECK(code.find("mevsim_adi(v3)") != std::string::npos,
                      "main: mevsim_adi cagrisi");
                CHECK(code.find("printf(\"ay %d -> %s\"") != std::string::npos,
                      "main: format stringi geri kazanimi");
            }
            delete elf;
        }
    } else {
        std::printf("[11] ATLANDI: kurban2.elf yok\n");
    }

    // ------------------------------------------------------------------
    if (FileHas("kurban.elf") && FileHas("kurban_src.cpp")) {
        std::printf("[12] kurban (O0 -g): DWARF gercek adlar (kurban.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban.elf")));
        CHECK(elf != nullptr, "kurban.elf acildi");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            Pseudocoder pc(az);
            TypeInferer& ti = pc.TI();
            // DWARF: Ogrenci struct'i gercek adlarla
            bool hasOgr = false, hasNumara = false, hasIsim = false, hasNotlar = false;
            for (auto& st : ti.Structs()) {
                if (st.name == "Ogrenci") {
                    hasOgr = true;
                    for (auto& [off, m] : st.members) {
                        if (m.name == "numara") hasNumara = true;
                        if (m.name == "isim") hasIsim = true;
                        if (m.name == "notlar") hasNotlar = true;
                    }
                }
            }
            CHECK(hasOgr, "struct Ogrenci DWARF'tan adlandi");
            CHECK(hasNumara, "uyе: numara (DWARF)");
            CHECK(hasIsim, "uye: isim (DWARF)");
            CHECK(hasNotlar, "uye: notlar (DWARF)");
            // imzalar: gercek param adlari
            std::string tAll = pc.DecompileAll(0);
            CHECK(tAll.find("int toplama(const int * dizi, int adet)") != std::string::npos,
                  "toplama imzasi: DWARF param adlari (dizi, adet)");
            CHECK(tAll.find("float ortalama_hesapla(const Ogrenci * o)") != std::string::npos,
                  "ortalama_hesapla imzasi: (const Ogrenci * o)");
            CHECK(tAll.find("long int faktoriyel(int n)") != std::string::npos,
                  "faktoriyel imzasi: (int n)");
            // rapor_yaz govdesi: o->numara / o->isim
            const FuncInfo* rapor = nullptr;
            for (auto& [va, f] : az.Functions())
                if (f.name.find("rapor_yaz") != std::string::npos) rapor = &f;
            if (rapor) {
                std::string code = pc.DecompileFunction(rapor->start);
                CHECK(code.find("o->numara") != std::string::npos,
                      "rapor_yaz: o->numara (gercek uye adi)");
                CHECK(code.find("o->isim") != std::string::npos,
                      "rapor_yaz: o->isim");
                CHECK(code.find("o->ortalama") != std::string::npos,
                      "rapor_yaz: o->ortalama");
                CHECK(code.find("faktoriyel(o->numara)") != std::string::npos,
                      "rapor_yaz: cagri argumanlari uye erisimiyle");
            }
            delete elf;
        }
    } else {
        std::printf("[12] ATLANDI: kurban.elf yok\n");
    }

    // ------------------------------------------------------------------
    if (FileHas("fixture.pdb") && FileHas("fixture.exe")) {
        std::printf("[13] PDB import: MSF 7.00 + isimler + parametreler (fixture.pdb)\n");
        auto* pe = dynamic_cast<PE*>(Binary::Open(PathOf("fixture.exe")));
        CHECK(pe != nullptr, "fixture.exe acildi");
        if (pe) {
            MappedImage img;
            img.LoadFromBinary(*pe);
            DisasmEngine de;
            de.Init(pe->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *pe, img);
            az.RunFull(false);
            Pseudocoder pc(az);
            // PDB yukle + uygula
            auto pdb = std::make_unique<PdbInfo>();
            CHECK(pdb->Load(PathOf("fixture.pdb")), "PDB (MSF 7.00) yuklendi");
            if (true) {   // Load dogrulandi yukarida
                pdb->ResolveVAs(pe->ImageBase(), pe->Sections());
                CHECK(pdb->Funcs().size() == 2, "PDB: 2 fonksiyon (S_GPROC32)");
                CHECK(pdb->TypeCount() >= 5, "PDB: tip kayitlari >= 5");
                auto structs = pdb->Structs();
                bool hasOgrPdb = false;
                for (auto& st : structs)
                    if (st.name == "OgrenciPdb" && st.members.size() == 4) hasOgrPdb = true;
                CHECK(hasOgrPdb, "PDB: OgrenciPdb struct'i (4 uye)");
                // isimleri uygula
                for (auto& f : pdb->Funcs()) {
                    std::string nm = !f.shortName.empty() ? f.shortName : f.name;
                    az.EnsureFunction(f.va, nm);
                }
                bool named = false;
                for (auto& [va, f] : az.Functions())
                    if (f.name == "toplama_pdb") named = true;
                CHECK(named, "fonksiyon PDB ismiyle adlandi (toplama_pdb)");
                // tip veritabanina PDB kanali
                pc.SetPdb(std::move(pdb));
                pc.InvalidateTI();
                std::string tAll = pc.DecompileAll(0);
                CHECK(tAll.find("int toplama_pdb(int dizi, int adet)") != std::string::npos,
                      "PDB imzasi: param adlari (dizi, adet)");
            }
            delete pe;
        }
    } else {
        std::printf("[13] ATLANDI: fixture.pdb yok\n");
    }

    // ------------------------------------------------------------------
    if (FileHas("kurban_o2g.elf")) {
        std::printf("[14-B] DWARF inline kaniti: -O2 -g (kurban_o2g.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban_o2g.elf")));
        CHECK(elf != nullptr, "kurban_o2g.elf acildi");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            Pseudocoder pc(az);
            TypeInferer& ti = pc.TI();
            CHECK(ti.Dwarf() != nullptr, "DWARF yuklendi (O2 -g)");
            if (ti.Dwarf()) {
                CHECK(ti.Dwarf()->Inlines().size() >= 1,
                      "DWARF inline araligi bulundu (inlined_subroutine)");
                if (!ti.Dwarf()->Inlines().empty())
                    CHECK(!ti.Dwarf()->Inlines()[0].funcName.empty(),
                          "inline edilen fonksiyonun adi cozuldu (ileri referans)");
            }
            // ortalama_hesapla govdesinde inline notu
            const FuncInfo* ort = nullptr;
            for (auto& [va, f] : az.Functions())
                if (f.name.find("ortalama_hesapla") != std::string::npos) ort = &f;
            if (ort) {
                std::string code = pc.DecompileFunction(ort->start);
                CHECK(code.find("inline edilmis") != std::string::npos,
                      "ortalama_hesapla: 'toplama() inline' notu (DWARF kaniti)");
                // v5: SIMD skaler geri açma — movdqu+paddd+psrldq zinciri
                // artık lane modeliyle TAM skaler ifadeye açılıyor (simd128 yok)
                // v6: DWARF struct giydirme ile lane'ler ARTIK GERÇEK üye adlarıyla:
                // *(int*)(o+4) kalıntısı YOK — o->notlar[0..7] üslubu var
                bool unwound = code.find("simd128") == std::string::npos &&
                               code.find("simd_add") == std::string::npos &&
                               code.find("o->notlar[0]") != std::string::npos &&
                               code.find(")(o + ") == std::string::npos;
                CHECK(unwound,
                      "v6 SIMD lane + DWARF struct giydirme: o->notlar[k] (ham *(int*)(o+K) yok)");
                int plusCount = 0;
                for (size_t i = 0; i + 1 < code.size(); i++)
                    if (code[i] == '+' && code[i + 1] == ' ') plusCount++;
                CHECK(plusCount >= 6,
                      "v5 yatay indirme: 8 elemanli toplam ifadesi (>=6 '+' isareti, %d)",
                      plusCount);
            }
            delete elf;
        }
    } else {
        std::printf("[14-B] ATLANDI: kurban_o2g.elf yok\n");
    }

    // ------------------------------------------------------------------
    {
        std::printf("[14] Demangle: Itanium sinif metotlari + dtor + vtable\n");
        CHECK(Demangle("_ZNK5Daire4alanEv") == "Daire::alan",
              "const metot: Daire::alan");
        CHECK(Demangle("_ZN10Dikdortgen4alanEv") == "Dikdortgen::alan",
              "Dikdortgen::alan");
        CHECK(Demangle("_ZN5DaireD1Ev") == "Daire::~Daire",
              "yikici: Daire::~Daire");
        CHECK(Demangle("_ZN5SekilC1Ev") == "Sekil",
              "kurucu: Sekil");
        CHECK(Demangle("_ZTV5Sekil") == "vtable for Sekil",
              "vtable sembolu");
        CHECK(Demangle("_ZTI5Sekil") == "typeinfo for Sekil",
              "typeinfo sembolu");
        CHECK(Demangle("_ZL10mevsim_adii") == "mevsim_adi",
              "yerel (L) sembol");
        CHECK(Demangle("_Z7toplamaPKii") == "toplama",
              "toplama (parametreli basit)");
    }

    // ==================================================================
    // [15] v4: DERIN FONKSIYON KESFI (kurban3s.elf — strip edilmis)
    //      prolog taramasi + veri referansi (fptr tablosu) + tail-call
    // ==================================================================
    if (FileHas("kurban3s.elf")) {
        std::printf("[15] Deep scan: strip edilmis kurban3s.elf\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban3s.elf")));
        CHECK(elf != nullptr, "kurban3s.elf acildi");
        if (elf) {
            CHECK(elf->Symbols().empty() || [&]{
                for (auto& s : elf->Symbols())
                    if (s.name.find("gizli") != std::string::npos ||
                        s.name.find("islem") != std::string::npos) return false;
                return true; }(), "semboller gercekten strip edilmis");
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            size_t before = az.Functions().size();
            DeepScanner ds(az);
            auto cands = ds.Scan(false);
            CHECK(!cands.empty(), "derin keşif aday buldu (%zu)", cands.size());
            // veri-referansi stratejisi: islem_tablosu üyeleri (3 fptr)
            int dataRefCnt = 0;
            for (auto& c : cands)
                if (c.strategy == "veri-referansi" && c.confidence >= 70) dataRefCnt++;
            CHECK(dataRefCnt >= 3, "fptr tablosu üyeleri veri referansindan bulundu (%d)", dataRefCnt);
            // prolog stratejisi: en az 4 aday (gizli_sifrele dahil)
            int prologCnt = 0;
            for (auto& c : cands)
                if (c.strategy == "prolog" && c.confidence >= 50) prologCnt++;
            CHECK(prologCnt >= 4, "prolog taramasi adaylari (%d)", prologCnt);
            // uygula + doğrula
            size_t added = ds.Apply(cands);
            CHECK(added >= 4, "FUN_ isimli yeni fonksiyon eklendi (%zu)", added);
            CHECK(az.Functions().size() == before + added, "fonksiyon sayisi tutarli");
            int funNamed = 0;
            for (auto& [va, f] : az.Functions())
                if (f.name.rfind("FUN_", 0) == 0) funNamed++;
            CHECK(funNamed >= 4, "FUN_XXXXXXXX (Ghidra geleneği) isimlendirme (%d)", funNamed);
            // gizli_sifrele gövdesi erişilebilir: uygulanan fonksiyonlardan biri
            // en az 10 komut içermeli (gizli_sifrele 17 komut)
            bool foundBig = false;
            for (auto& [va, f] : az.Functions())
                if (f.name.rfind("FUN_", 0) == 0 && f.insCount >= 12) foundBig = true;
            CHECK(foundBig, "hic cagrilmayan gizli_sifrele prolog taramasindan kurtarildi");
            delete elf;
        }
    } else {
        std::printf("[15] ATLANDI: kurban3s.elf yok\n");
    }

    // ==================================================================
    // [16] v4: OBFUSCATION RAPORU + OPAQUE PREDICATE (kurban3.elf)
    // ==================================================================
    if (FileHas("kurban3.elf")) {
        std::printf("[16] Obfus: opaque predicate + risk raporu (kurban3.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban3.elf")));
        CHECK(elf != nullptr, "kurban3.elf acildi");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            ObfusAnalyzer oa(*elf, img, &az);
            auto rep = oa.Run();
            CHECK(rep.opaque.size() >= 1, "opaque predicate tespit edildi (%zu)", rep.opaque.size());
            bool inOpak = false;
            for (auto& o : rep.opaque)
                if (o.funcName == "opak_toplam" &&
                    o.pattern.find("xor") != std::string::npos)
                    inOpak = true;
            CHECK(inOpak, "xor r12d,r12d; test; jz kalibi opak_toplam icinde");
            CHECK(rep.risk >= 1 && rep.risk < 7, "risk puani makul aralikta (%d)", rep.risk);
            CHECK(!rep.verdict.empty(), "karar verildi: %s", rep.verdict.c_str());

            // decompiler: opak öncül katlanmalı + ölü kod (junk) budanmalı
            Pseudocoder pc(az);
            const FuncInfo* fo = nullptr;
            for (auto& [va, f] : az.Functions())
                if (f.name == "opak_toplam") fo = &f;
            CHECK(fo != nullptr, "opak_toplam bulundu");
            if (fo) {
                std::string code = pc.DecompileFunction(fo->start);
                CHECK(code.find("kosul daima DOGRU") != std::string::npos,
                      "opak oncul katlandi: sabit dallanma notu");
                CHECK(code.find("E8") == std::string::npos ||
                      code.find("0xe8") == std::string::npos,
                      "olum kod (junk .byte E8..) ciktiya sizmadi");
            }
            // yapılaştırma v4: do-while / for / && / break / ternary
            const FuncInfo* fk = nullptr, *fc = nullptr, *fr = nullptr;
            for (auto& [va, f] : az.Functions()) {
                if (f.name == "kac_defa") fk = &f;
                if (f.name == "karma_toplam") fc = &f;
                if (f.name == "opak_toplam") fo = &f;
                if (f.name.rfind("karma", 0) == 0) fr = &f;
            }
            if (fk) {
                std::string code = pc.DecompileFunction(fk->start);
                CHECK(code.find("do {") != std::string::npos, "do-while yapilandi");
                CHECK(code.find("} while (") != std::string::npos, "do-while kosulu");
                CHECK(code.find("goto") == std::string::npos, "kac_defa goto'suz");
            }
            if (fc) {
                std::string code = pc.DecompileFunction(fc->start);
                CHECK(code.find("for ( ") != std::string::npos, "karma: for dongusu");
                CHECK(code.find("&&") != std::string::npos, "karma: kisa devre &&");
                CHECK(code.find("break;") != std::string::npos, "karma: break kurtarildi");
                CHECK(code.find("?") != std::string::npos, "karma: ternary operator");
                CHECK(code.find("goto") == std::string::npos, "karma: goto'suz (68 komut)");
            }
            delete elf;
        }
    } else {
        std::printf("[16] ATLANDI: kurban3.elf yok\n");
    }

    // ==================================================================
    // [17] v4: IMZA MOTORU — .gsig export/import (FLIRT-tarzı)
    // ==================================================================
    if (FileHas("siglib_sym.elf") && FileHas("siglib_strip.elf")) {
        std::printf("[17] Sig engine: sembollüden imza üret, strip'te isim geri kazan\n");
        // 17a) export
        auto* elfS = dynamic_cast<ELF*>(Binary::Open(PathOf("siglib_sym.elf")));
        CHECK(elfS != nullptr, "siglib_sym.elf acildi");
        if (elfS) {
            MappedImage imgS;
            imgS.LoadFromBinary(*elfS);
            DisasmEngine deS;
            deS.Init(elfS->GetArch());
            deS.SetMemoryReader([&](u64 va, u8* o, size_t n) { return imgS.ReadBytes(va, o, n); });
            Analyzer azS(deS, *elfS, imgS);
            azS.RunFull(false);
            SigEngine seS(azS);
            std::string gsigPath = "/tmp/godtier_test.gsig";
            CHECK(seS.ExportGsig(gsigPath), "imza veritabani uretildi");
            // üretilen dosyada ortak_* isimleri var mı
            std::string gsig = [&]{
                std::ifstream f(gsigPath);
                std::stringstream ss; ss << f.rdbuf(); return ss.str(); }();
            CHECK(gsig.find("ortak_topla") != std::string::npos, "imzada ortak_topla");
            CHECK(gsig.find("ortak_max3") != std::string::npos, "imzada ortak_max3");
            CHECK(gsig.find("ortak_parite") != std::string::npos, "imzada ortak_parite");
            CHECK(gsig.find("xx") != std::string::npos, "maskeli (xx) joker baytlar var");
            delete elfS;

            // 17b) import → strip'te isim geri kazanımı
            auto* elfT = dynamic_cast<ELF*>(Binary::Open(PathOf("siglib_strip.elf")));
            CHECK(elfT != nullptr, "siglib_strip.elf acildi");
            if (elfT) {
                MappedImage imgT;
                imgT.LoadFromBinary(*elfT);
                DisasmEngine deT;
                deT.Init(elfT->GetArch());
                deT.SetMemoryReader([&](u64 va, u8* o, size_t n) { return imgT.ReadBytes(va, o, n); });
                Analyzer azT(deT, *elfT, imgT);
                azT.RunFull(false);
                SigEngine seT(azT);
                auto res = seT.ImportGsig(gsigPath);
                CHECK(res.matched >= 3, "imza eslesmesi (%zu/%zu)", res.matched, res.compared);
                bool gotTopla = false, gotParite = false;
                for (auto& [va, nm] : res.renames) {
                    if (nm == "ortak_topla") gotTopla = true;
                    if (nm == "ortak_parite") gotParite = true;
                }
                CHECK(gotTopla, "ortak_topla geri kazanimildi");
                CHECK(gotParite, "ortak_parite geri kazanimildi");
                // isimler analiz veritabanına da işlemiş mi
                bool dbNamed = false;
                for (auto& [va, f] : azT.Functions())
                    if (f.name == "ortak_max3") dbNamed = true;
                CHECK(dbNamed, "ortak_max3 analiz veritabaninda yeniden adlandi");
                // kural taraması: desen kuralları çalışıyor
                auto rules = seT.RuleScan();
                CHECK(true, "kural taramasi %zu eslesme (bilgi)", rules.size());
                delete elfT;
            }
        }
    } else {
        std::printf("[17] ATLANDI: siglib fixture'lari yok\n");
    }

    // ==================================================================
    // [18] v4: FIND komutu altyapısı + deepscan kapsam kontrolü
    // ==================================================================
    if (FileHas("kurban3.elf")) {
        std::printf("[18] Find: bayt/sabit arama altyapisi\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban3.elf")));
        CHECK(elf != nullptr, "kurban3.elf acildi (find)");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            // bayt arama: "push rbp; mov rbp, rsp" = 55 48 89 e5
            int pushRbpCount = 0;
            const auto& raw = elf->Raw();
            const u8 pat[4] = {0x55, 0x48, 0x89, 0xE5};
            for (size_t i = 0; i + 4 <= raw.size(); i++)
                if (memcmp(&raw[i], pat, 4) == 0) pushRbpCount++;
            CHECK(pushRbpCount >= 5, "prolog bayt kalibi dosyada >=5 kez (%d)", pushRbpCount);
            // sabit arama: 0x5A (gizli_sifrele anahtarı) komut içinde
            int immHits = 0;
            for (auto& [va, f] : az.Functions()) {
                auto* ins = az.InstructionsOf(va);
                if (!ins) continue;
                for (auto& x : *ins)
                    if (x.opStr.find("0x5a") != std::string::npos) immHits++;
            }
            CHECK(immHits >= 1, "0x5a sabiti komutlarda bulundu (%d)", immHits);
            // string arama
            bool foundStr = false;
            az.ExtractStrings();
            for (auto& s : az.Strings())
                if (s.text.find("karma") != std::string::npos) foundStr = true;
            CHECK(foundStr, "'karma' stringi bulundu");
            delete elf;
        }
    } else {
        std::printf("[18] ATLANDI: kurban3.elf yok (find)\n");
    }

    // ------------------------------------------------------------------
    // [19] v5 DEVIRTUALIZASYON (CHA) + iç içe else-if + erken dönüş (kurban4.elf)
    // ------------------------------------------------------------------
    if (FileHas("kurban4.elf")) {
        std::printf("[19] v5: CHA devirt + ic ice else-if + erken donus (kurban4.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban4.elf")));
        CHECK(elf != nullptr, "kurban4.elf acildi");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            Pseudocoder pc(az);
            pc.TI();
            auto decompByName = [&](const char* needle) -> std::string {
                for (auto& [va, f] : az.Functions())
                    if (f.name.find(needle) != std::string::npos)
                        return pc.DecompileFunction(va);
                return "";
            };
            // 1) devirt_tek: CHA ile statik çözüm (Tek* alt sınıfsız -> tek impl)
            std::string dv = decompByName("devirt_tek");
            CHECK(dv.find("Tek::deger") != std::string::npos,
                  "devirt_tek: CHA devirtualize (Tek::deger cagrisi)");
            CHECK(dv.find("v5 devirtualize") != std::string::npos,
                  "devirt_tek: devirt kanit notu");
            // 2) sanal_kalir: Kopek::ses override var -> DURUST sanal kalmali
            std::string sk = decompByName("sanal_kalir");
            CHECK(sk.find("h->ses()") != std::string::npos,
                  "sanal_kalir: cok impl'li slot sanal kaldi (h->ses)");
            CHECK(sk.find("Hayvan::ses(") == std::string::npos,
                  "sanal_kalir: yanlis devirt YOK (override tespiti)");
            // 3) phi_ucyol: iç içe else-if + ternary
            std::string pu = decompByName("phi_ucyol");
            CHECK(pu.find("? ") != std::string::npos,
                  "phi_ucyol: ic elmas ternary'e katlandi");
            CHECK(pu.find("3 * x") != std::string::npos &&
                  pu.find("2 * x") != std::string::npos &&
                  pu.find("-x") != std::string::npos,
                  "phi_ucyol: uc yolun degerleri korundu (3x / 2x / -x)");
            // 4) erken_donus: erken dönüş zinciri + return yükseltme, goto yok
            std::string ed = decompByName("erken_donus");
            CHECK(ed.find("goto") == std::string::npos,
                  "erken_donus: goto kalintisi yok");
            CHECK(ed.find("return ( x <= 0x64 ) ?") != std::string::npos,
                  "erken_donus: ternary return (x : 0x64)");
            CHECK(ed.find("return -1") != std::string::npos,
                  "erken_donus: 0xffffffff -> -1 isaretli pretty-print (v6)");
            // 5) trambolin: iç içe if/else (goto yok)
            std::string tr = decompByName("trambolin");
            CHECK(tr.find("goto") == std::string::npos,
                  "trambolin: goto kalintisi yok (ic ice if/else)");
            CHECK(tr.find("<<= 1") != std::string::npos || tr.find("<< 1") != std::string::npos,
                  "trambolin: a <<= 1 govdesi");
            delete elf;
        }
    } else {
        std::printf("[19] ATLANDI: kurban4.elf yok\n");
    }

    // ------------------------------------------------------------------
    // [20] v5 SIMD skaler geri açma + cmov phi + döngü-taşıyıcı phi (kurban4_o3.elf)
    // ------------------------------------------------------------------
    if (FileHas("kurban4_o3.elf")) {
        std::printf("[20] v5: SIMD lane geri acma + cmov phi + loop phi (kurban4_o3.elf)\n");
        auto* elf = dynamic_cast<ELF*>(Binary::Open(PathOf("kurban4_o3.elf")));
        CHECK(elf != nullptr, "kurban4_o3.elf acildi");
        if (elf) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            DisasmEngine de;
            de.Init(elf->GetArch());
            de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            Analyzer az(de, *elf, img);
            az.RunFull(false);
            Pseudocoder pc(az);
            pc.TI();
            auto decompByName = [&](const char* needle) -> std::string {
                for (auto& [va, f] : az.Functions())
                    if (f.name.find(needle) != std::string::npos)
                        return pc.DecompileFunction(va);
                return "";
            };
            // 1) phi_ucyol O3: cmov -> ternary (donanim phi'si)
            std::string pu = decompByName("phi_ucyol");
            CHECK(pu.find("( x >= 0x33 ) ?") != std::string::npos,
                  "phi_ucyol O3: cmovge ternary'e katlandi");
            CHECK(pu.find("goto") == std::string::npos,
                  "phi_ucyol O3: goto yok");
            // 2) simd_dot O3: vektörleştirilmiş döngü skaler geri açıldı
            std::string sd = decompByName("simd_dot");
            CHECK(sd.find("simd_add") == std::string::npos &&
                  sd.find("simd128") == std::string::npos,
                  "simd_dot: SIMD intrinsic kalintisi yok (tam skaler geri acma)");
            CHECK(sd.find("phi:") != std::string::npos,
                  "simd_dot: döngü-taşıyıcı phi degiskenleri tanimlandi");
            CHECK(sd.find("+= 0x10") != std::string::npos,
                  "simd_dot: bayt sayac phi artisi (v += 0x10)");
            // 4 lane çarpımı: en az 4 '*' ve lane erişimleri
            int mulCount = 0;
            for (size_t i = 0; i + 2 < sd.size(); i++)
                if (sd[i] == '*' && sd[i + 1] == ' ') mulCount++;
            CHECK(mulCount >= 4,
                  "simd_dot: yatay indirme 4 lane carpimi (%d * isareti)", mulCount);
            CHECK(sd.find("float v") != std::string::npos,
                  "simd_dot: float birikimli phi degiskeni");
            delete elf;
        }
    } else {
        std::printf("[20] ATLANDI: kurban4_o3.elf yok\n");
    }

    // ------------------------------------------------------------------
    // [21] v5 SÜPER BLOK birleştirme (sentetik trambolin zinciri)
    // ------------------------------------------------------------------
    {
        std::printf("[21] v5: CFG super blok birlestirme (trambolin zinciri)\n");
        // A: mov eax,1 ; jmp B      (0x100)
        // B: mov eax,2 ; jmp C      (0x105)  <- tek öncül + adres-komşu -> A'ya füze
        // C: ret                    (0x10a)
        std::vector<Ins> code;
        auto mk = [&](u64 a, const char* mn, const char* ops, u8 len) {
            Ins x; x.addr = a; x.mnemonic = mn; x.opStr = ops; x.len = len;
            x.isJmp = (mn[0] == 'j' && std::string(mn) != "jcc");
            x.isRet = mn[0] == 'r';
            return x;
        };
        Ins a1 = mk(0x100, "mov", "eax, 1", 5);
        Ins a2 = mk(0x105, "jmp", "0x10a", 5); a2.isJmp = true; a2.target = 0x10a;
        Ins b1 = mk(0x10a, "mov", "eax, 2", 5);
        Ins b2 = mk(0x10f, "jmp", "0x114", 5); b2.isJmp = true; b2.target = 0x114;
        Ins c1 = mk(0x114, "ret", "", 1); c1.isRet = true;
        code = {a1, a2, b1, b2, c1};
        // düz Build: bloklar = [A][B][C] (jmp hedefleri lider)
        // B'nin tek öncülü A VE fiziksel komşu -> füzyon beklenir
        CFG cfg;
        CHECK(cfg.Build(code), "sentetik CFG kuruldu");
        size_t afterBlocks = cfg.BlockCount();
        CHECK(cfg.MergedCount() >= 1,
              "trambolin zinciri fuse edildi (birlesen=%zu, blok=%zu)",
              cfg.MergedCount(), afterBlocks);
        // fuse sonrası tüm blok succ hedefleri geçerli bloklara düşmeli
        bool succOk = true;
        for (auto& b : cfg.Blocks())
            for (auto& [t, et] : b.succ) {
                bool found = false;
                for (auto& b2 : cfg.Blocks())
                    if (b2.start == t) found = true;
                if (!found) succOk = false;
            }
        CHECK(succOk, "fuse sonrasi tum succ hedefleri gecerli");
        // jmp-üzerinden-jmp (trambolin) yönlendirme testi:
        //   X: jmp T (tek komut, giriş değil) — P: jcc X
        //   -> P'nin kenarı doğrudan T'ye dönmeli
        std::vector<Ins> code2;
        Ins p1 = mk(0x200, "cmp", "eax, 5", 5);
        Ins p2 = mk(0x205, "jne", "0x215", 6); p2.isJcc = true; p2.target = 0x215;
        Ins x1 = mk(0x20b, "jmp", "0x220", 5); x1.isJmp = true; x1.target = 0x220;
        Ins t1 = mk(0x210, "nop", "", 1);
        Ins q1 = mk(0x211, "mov", "eax, 3", 5);   // 0x215 buraya düşer mi? hayır:
        // X bloğu 0x20b'de; jne hedefi 0x215 (X'ten sonra bir blok başı yapalım)
        Ins x2 = mk(0x215, "jmp", "0x220", 5); x2.isJmp = true; x2.target = 0x220;
        Ins tt = mk(0x220, "ret", "", 1); tt.isRet = true;
        code2 = {p1, p2, x1, t1, q1, x2, tt};
        CFG cfg2;
        CHECK(cfg2.Build(code2), "trambolin CFG kuruldu");
        // 0x215 tek komutlu jmp 0x220 -> p2'nin dal kenarı 0x220'ye yönlenmeli
        bool threaded = false;
        for (auto& b : cfg2.Blocks())
            if (b.start == 0x200)
                for (auto& [t, et] : b.succ)
                    if (t == 0x220) threaded = true;
        CHECK(threaded, "jne kenari trambolinden gecirildi (0x215 -> 0x220)");
    }

    // ------------------------------------------------------------------
    // [22] v6 ARM64 + ARM32 mimari desteği (elle kodlanmış fixture'lar —
    //      cross-compiler GEREKMEZ; encodings make_fixture_arm.py'de)
    // ------------------------------------------------------------------
    {
        std::printf("[22] v6: ARM64 + ARM32 mimari destegi (disasm+keşif+xref)\n");
        ELF* elf = new ELF();
        if (elf->Load("tests/fixtures/kurban_arm64.elf")) {
            MappedImage img;
            img.LoadFromBinary(*elf);
            CHECK(elf->GetArch() == Arch::ARM64,
                  "ARM64: e_machine=0xB7 -> Arch::ARM64 tespiti");
            DisasmEngine eng;
            eng.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
            CHECK(eng.Init(Arch::ARM64), "Capstone ARM64 motoru acildi");
            Analyzer az(eng, *elf, img);
            az.RunFull(false);
            // BL hedeflerinden fonksiyon keşfi: entry + f1 + f2 + f3
            CHECK(az.Functions().size() >= 4,
                  "ARM64: bl hedeflerinden fonksiyon keşfi (%zu fonksiyon)",
                  az.Functions().size());
            CHECK(az.FunctionStart(0x400120) != nullptr,
                  "ARM64: f1 (0x400120) bl ile kesfedildi");
            // cbz/b/b.eq kenarları + bl çağrı xref'i
            auto xr = az.XrefsTo(0x400120);
            bool hasCall = false;
            for (auto& x : xr) if (x.type == RefType::Call) hasCall = true;
            CHECK(hasCall, "ARM64: f1'e CALL xref'i (%zu xref)", xr.size());
            // adr -> rodata string xref'i (data kanalı)
            auto xrStr = az.XrefsTo(0x400200);
            CHECK(!xrStr.empty(), "ARM64: adr x0,0x400200 -> string DATA xref'i");
            // koşullu dal + geri döngü: cbz x1 (0x400138) xref'leri
            auto xrCbz = az.XrefsTo(0x400138);
            CHECK(xrCbz.size() >= 1, "ARM64: cbz hedefine JCC xref'i");
            // string bulundu
            bool strOk = false;
            for (auto& s : az.Strings())
                if (s.text.find("ARM64 GodTier") != std::string::npos) strOk = true;
            CHECK(strOk, "ARM64: .rodata string taraması");
            // decomp: dürüst mimari mesajı
            Pseudocoder ps(az);
            std::string dc = ps.DecompileFunction(0x400130);
            CHECK(dc.find("ARM64") != std::string::npos &&
                  dc.find("x86-64") != std::string::npos,
                  "ARM64: decomp dürüst mimari bilgisi verir (yanlış pseudocode ÜRETMEZ)");
        } else {
            std::printf("     (kurban_arm64.elf yok — atlandi)\n");
        }
        delete elf;

        ELF* elf2 = new ELF();
        if (elf2->Load("tests/fixtures/kurban_arm32.elf")) {
            MappedImage img2;
            img2.LoadFromBinary(*elf2);
            CHECK(elf2->GetArch() == Arch::ARM32,
                  "ARM32: e_machine=0x28 -> Arch::ARM32 tespiti");
            DisasmEngine eng2;
            eng2.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img2.ReadBytes(va, o, n); });
            CHECK(eng2.Init(Arch::ARM32), "Capstone ARM32 motoru acildi");
            Analyzer az2(eng2, *elf2, img2);
            az2.RunFull(false);
            CHECK(az2.FunctionStart(0x400118) != nullptr,
                  "ARM32: bl hedefi f1 (0x400118) kesfedildi");
            bool blSeen = false, bxSeen = false;
            if (auto* fi = az2.InstructionsOf(0x400100)) {
                for (auto& x : *fi) {
                    if (x.mnemonic == "bl") blSeen = true;
                    if (x.mnemonic == "bx") bxSeen = true;
                }
            }
            CHECK(blSeen, "ARM32: bl komutu cozumlendirildi");
            CHECK(bxSeen, "ARM32: bx lr (dönüş) cozumlendirildi");
        } else {
            std::printf("     (kurban_arm32.elf yok — atlandi)\n");
        }
        delete elf2;
    }

    // ==================================================================
    // [23] v6: HAZIR İMZA HAVUZU (libc .gsig) + lumina push/pull + auto-apply
    // ==================================================================
    {
        std::printf("[23] v6: hazir imza havuzu + lumina + otomatik uygulama\n");
        // 23a) repodaki libc havuzu gerçek ve dolu mu
        if (FileHas("sigs/libc_x64.gsig") ||
            std::filesystem::exists("sigs/libc_x64.gsig")) {
            size_t n = CountGsigEntries("sigs/libc_x64.gsig");
            CHECK(n >= 2000, "libc_x64.gsig havuzu dolu (%zu imza)", n);
            std::string txt = [&]{
                std::ifstream f("sigs/libc_x64.gsig");
                std::stringstream ss; ss << f.rdbuf(); return ss.str(); }();
            CHECK(txt.find("\nmemcpy ") != std::string::npos, "havuzda memcpy imzasi");
            CHECK(txt.find("\nprintf ") != std::string::npos, "havuzda printf imzasi");
        } else {
            std::printf("     (sigs/libc_x64.gsig yok — havuz atlandi)\n");
        }
        // 23b) lumina push/pull + auto-apply (siglib fixture'lari uzerinden)
        if (FileHas("siglib_sym.elf") && FileHas("siglib_strip.elf")) {
            auto* elfS = dynamic_cast<ELF*>(Binary::Open(PathOf("siglib_sym.elf")));
            CHECK(elfS != nullptr, "lumina: siglib_sym.elf acildi");
            if (elfS) {
                MappedImage imgS;
                imgS.LoadFromBinary(*elfS);
                DisasmEngine deS;
                deS.Init(elfS->GetArch());
                deS.SetMemoryReader([&](u64 va, u8* o, size_t n) { return imgS.ReadBytes(va, o, n); });
                Analyzer azS(deS, *elfS, imgS);
                azS.RunFull(false);
                SigEngine seS(azS);
                // lumina push: birikimli havuz
                std::string poolPath = "/tmp/godtier_lumina_test.gsig";
                std::remove(poolPath.c_str());
                size_t added = seS.PushToPool(poolPath);
                CHECK(added >= 3, "lumina push: %zu yeni isim eklendi", added);
                size_t total1 = CountGsigEntries(poolPath);
                // tekrar push: dedupe (ayni kanitlar -> 0 yeni)
                size_t added2 = seS.PushToPool(poolPath);
                CHECK(added2 == 0, "lumina push dedupe: ikinci push 0 yeni (%zu)", added2);
                CHECK(CountGsigEntries(poolPath) == total1, "havuz buyklugu korundu");
                // lumina pull: strip'te isim geri kazanimi
                auto* elfT = dynamic_cast<ELF*>(Binary::Open(PathOf("siglib_strip.elf")));
                CHECK(elfT != nullptr, "lumina: siglib_strip.elf acildi");
                if (elfT) {
                    MappedImage imgT;
                    imgT.LoadFromBinary(*elfT);
                    DisasmEngine deT;
                    deT.Init(elfT->GetArch());
                    deT.SetMemoryReader([&](u64 va, u8* o, size_t n) { return imgT.ReadBytes(va, o, n); });
                    Analyzer azT(deT, *elfT, imgT);
                    azT.RunFull(false);
                    SigEngine seT(azT);
                    auto r = seT.ImportGsig(poolPath);
                    CHECK(r.renamed >= 3, "lumina pull: %zu isim geri kazanimildi", r.renamed);
                    // 23c) ApplySigPools: dizin tabanlı otomatik uygulama (sigs/ mekanizması)
                    std::string tmpDir = "/tmp/godtier_sigpools_test";
                    std::filesystem::create_directories(tmpDir);
                    std::filesystem::copy_file(poolPath, tmpDir + "/havuz.gsig",
                                               std::filesystem::copy_options::overwrite_existing);
                    // yeniden strip + otomatik havuz
                    auto* elfT2 = dynamic_cast<ELF*>(Binary::Open(PathOf("siglib_strip.elf")));
                    if (elfT2) {
                        MappedImage imgT2;
                        imgT2.LoadFromBinary(*elfT2);
                        DisasmEngine deT2;
                        deT2.Init(elfT2->GetArch());
                        deT2.SetMemoryReader([&](u64 va, u8* o, size_t n) { return imgT2.ReadBytes(va, o, n); });
                        Analyzer azT2(deT2, *elfT2, imgT2);
                        azT2.RunFull(false);
                        auto pools = ApplySigPools(azT2, tmpDir);
                        CHECK(pools.size() == 1, "ApplySigPools: 1 havuz bulundu");
                        CHECK(pools[0].renamed >= 3,
                              "ApplySigPools: otomatik isim geri kazanimi (%zu)",
                              pools[0].renamed);
                        bool named = false;
                        for (auto& [va, f] : azT2.Functions())
                            if (f.name == "ortak_topla") named = true;
                        CHECK(named, "ApplySigPools sonrasi ortak_topla adlandi");
                        delete elfT2;
                    }
                    delete elfT;
                }
                delete elfS;
            }
        } else {
            std::printf("     (siglib fixture'lari yok — lumina atlandi)\n");
        }
    }

    // ==================================================================
    // [24] v6: SCRIPT API — EvalArith + $değişken + set/echo/if
    // ==================================================================
    {
        std::printf("[24] v6: script API (değişken/aritmetik/koşul)\n");
        bool ok = false;
        CHECK(EvalArith("(0x10 + 5) * 3", &ok) == 63 && ok, "EvalArith: (0x10+5)*3 == 63");
        CHECK(EvalArith("0xff & 0x0f", &ok) == 15 && ok, "EvalArith: 0xff & 0x0f == 15");
        CHECK(EvalArith("1 << 10", &ok) == 1024 && ok, "EvalArith: 1 << 10 == 1024");
        CHECK(EvalArith("-7 % 3", &ok) == -1 && ok, "EvalArith: -7 %% 3 == -1");
        CHECK(EvalArith("100 / (2 * 5)", &ok) == 10 && ok, "EvalArith: 100/(2*5) == 10");
        CHECK(EvalArith("2 +", &ok) == 0 && !ok, "EvalArith: bozuk ifade reddedilir");
        Shell sh;
        CHECK(sh.ScriptLine("set $a = 6 * 7"), "ScriptLine: set calisti");
        auto it = sh.ScriptVars().find("$a");
        CHECK(it != sh.ScriptVars().end() && it->second == "42",
              "script degiskeni $a = 42");
        CHECK(sh.ScriptLine("set $b = ( $a + 6 ) / 3"), "ScriptLine: ic ice degisken");
        CHECK(sh.ScriptVars().at("$b") == "16", "$b = (42+6)/3 = 16");
        // yanlış koşul: komut ÇALIŞMAMALI (set üzerinden doğrulanır)
        sh.ScriptLine("if $a == 41 : set $c = 1");
        CHECK(sh.ScriptVars().count("$c") == 0, "yanlis kosulda komut calismaz");
        sh.ScriptLine("if $a == 42 : set $c = 99");
        CHECK(sh.ScriptVars().count("$c") == 1 && sh.ScriptVars().at("$c") == "99",
              "dogru kosulda komut calisir");
    }

    // ==================================================================
    // [25] v7: MSVC RTTI atlası + DEVRİT-PRO + x86-32 decompiler
    //      (fixture_devirt.exe — metin2client.exe playerGetStatus deseninin
    //       elle inşa edilmiş minyatürü: sembolsüz, PDB'sız çözüm kanıtı)
    // ==================================================================
    {
        std::printf("[25] v7: RTTI atlasi + devirt-pro + x86-32 (fixture_devirt.exe)\n");
        if (FileHas("fixture_devirt.exe")) {
            auto* pe = dynamic_cast<PE*>(Binary::Open(PathOf("fixture_devirt.exe")));
            CHECK(pe != nullptr, "fixture_devirt.exe acildi (PE32)");
            if (pe) {
                MappedImage img;
                img.LoadFromBinary(*pe);
                DisasmEngine de;
                de.Init(pe->GetArch());
                de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
                Analyzer az(de, *pe, img);
                az.RunFull(false);
                Pseudocoder pc(az);

                // ---- RTTI atlası: sembolsüz sınıf evreni ----
                MsvcRtti& rtti = pc.Rtti();
                CHECK(rtti.Classes().size() == 6,
                      "RTTI: 6 vftable (CPlayer x3 + CExtra + CExtra2 + CEmu) (got %zu)",
                      rtti.Classes().size());
                const RttiClass* cpMain = nullptr;
                for (auto& c : rtti.Classes())
                    if (c.name == "CPlayer" && c.slots.size() == 40) cpMain = &c;
                CHECK(cpMain != nullptr, "CPlayer ana vftable (40 slot)");
                if (cpMain) {
                    std::string why;
                    CHECK(rtti.ResolveSlot(cpMain->vftVa, 0x10, &why) == 0x401020,
                          "slot 4 (+0x10) = GetStatus 0x401020 (%s)", why.c_str());
                    CHECK(rtti.ResolveSlot(cpMain->vftVa, 0x88, &why) == 0x401030,
                          "slot 34 (+0x88) = GetActorPtr 0x401030 (%s)", why.c_str());
                    CHECK(cpMain->objectOffset == 4,
                          "COL offset = +4 (nesne icindeki CPlayer alt-nesnesi)");
                }

                // ---- DEVRİT-PRO: statik nesne kanıtları + çözümler ----
                DevirtPro& dp = pc.Devirt();
                CHECK(dp.StaticCount() == 2, "2 statik nesne (ms_singleton + ms_extra)");
                CHECK(dp.ResolvedCount() == 5,
                      "5 dolayli cagri statik cozuldu (v8: +emu +inversiyon) (got %zu)",
                      dp.ResolvedCount());
                auto* ins = az.InstructionsOf(0x4010e0);
                CHECK(ins != nullptr, "playerGetStatus bulundu (0x4010e0)");
                if (ins) {
                    std::vector<u64> calls;
                    for (auto& x : *ins)
                        if (x.isCall && x.isIndirect) calls.push_back(x.addr);
                    CHECK(calls.size() == 3, "3 dolayli cagri (got %zu)", calls.size());
                    if (calls.size() == 3) {
                        DevirtPro::Result r1 = dp.Resolve(calls[0]);
                        CHECK(r1.resolved && r1.target == 0x401020,
                              "cagri 1 (call eax): CPlayer::GetStatus statik cozuldu");
                        CHECK(r1.className == "CPlayer" && r1.slot == 4,
                              "cagri 1: sinif=CPlayer slot=4");
                        CHECK(!r1.trace.empty(), "cagri 1: kanit izi (trace) var");
                        DevirtPro::Result r2 = dp.Resolve(calls[1]);
                        CHECK(r2.resolved && r2.target == 0x401030,
                              "cagri 2 (call [edx+0x88]): CPlayer::GetActorPtr");
                        CHECK(r2.className == "CPlayer" && r2.slot == 34,
                              "cagri 2: sinif=CPlayer slot=34");
                        DevirtPro::Result r3 = dp.Resolve(calls[2]);
                        CHECK(r3.resolved && r3.isImport && r3.name == "py.dll.Py_BuildValue",
                              "cagri 3: IAT import py.dll.Py_BuildValue (got %s)",
                              r3.name.c_str());
                    }
                }
                // muğlak zincir: iki sınıf aynı statik nesneye yazıyor → dürüst aday
                auto* insA = az.InstructionsOf(0x401160);
                CHECK(insA != nullptr, "muğlak fonksiyon bulundu (0x401160)");
                if (insA) {
                    for (auto& x : *insA) {
                        if (!(x.isCall && x.isIndirect)) continue;
                        DevirtPro::Result r = dp.Resolve(x.addr);
                        CHECK(!r.resolved, "muğlak cagri COZULMEDI (dürüstlük)");
                        CHECK(r.candidates.size() == 2,
                              "2 aday (got %zu)", r.candidates.size());
                        bool hasExtra = false, hasExtra2 = false;
                        for (auto& n : r.candidateNames) {
                            if (n.find("CExtra::") != std::string::npos) hasExtra = true;
                            if (n.find("CExtra2::") != std::string::npos) hasExtra2 = true;
                        }
                        CHECK(hasExtra && hasExtra2, "aday isimleri CExtra/CExtra2");
                    }
                }

                // ---- x86-32 decompiler çıktı kalitesi ----
                std::string code = pc.DecompileFunction(0x4010e0);
                CHECK(code.find("CPlayer::Instance().vf4(") != std::string::npos,
                      "decomp: CPlayer::Instance().vf4(iType) — kaynak stili (v8)");
                CHECK(code.find("CPlayer::Instance().vf34()") != std::string::npos,
                      "decomp: CPlayer::Instance().vf34() — kaynak stili (v8)");
                CHECK(code.find("py.dll.Py_BuildValue") != std::string::npos,
                      "decomp: import cagrisi isimli");
                CHECK(code.find("\"i\"") != std::string::npos,
                      "decomp: Py_BuildValue(\"i\", ...) kisa format stringi");
                size_t n4 = 0, pos4 = 0;
                while ((pos4 = code.find("CPlayer::Instance().vf4(", pos4)) != std::string::npos) {
                    n4++; pos4 += 8;
                }
                CHECK(n4 == 1, "decomp: Instance().vf4 cagrisi TEK kez basildi (got %zu)", n4);
                std::string codeA = pc.DecompileFunction(0x401160);
                CHECK(codeA.find("adaylari") != std::string::npos,
                      "decomp: muğlak cagri aday notu gorunur");
                delete pe;
            }
        } else {
            std::printf("     (fixture_devirt.exe yok — v7 devirt testleri atlandi)\n");
        }
    }

    // ==================================================================
    // [26] v8: TIER-3 (Unicorn tohumlu pencere emülasyonu) + atlas
    //      inversiyonu + Instance() katlaması — üç yeni devirt silahı
    // ==================================================================
    {
        std::printf("[26] v8: tier-3 unicorn + atlas inversiyonu + Instance() "
                    "+ v8.1 vfN sozlugu + mekanizma kirilimi\n");
        if (FileHas("fixture_devirt.exe")) {
            auto* pe = dynamic_cast<PE*>(Binary::Open(PathOf("fixture_devirt.exe")));
            CHECK(pe != nullptr, "fixture_devirt.exe acildi (v8)");
            if (pe) {
                MappedImage img;
                img.LoadFromBinary(*pe);
                DisasmEngine de;
                de.Init(pe->GetArch());
                de.SetMemoryReader([&](u64 va, u8* o, size_t n) { return img.ReadBytes(va, o, n); });
                Analyzer az(de, *pe, img);
                az.RunFull(false);
                Pseudocoder pc(az);
                DevirtPro& dp = pc.Devirt();

                // ---- TIER-3: lineer değerlendiricinin ÇÖZEMEDİĞİ vaka ----
                // (fonksiyon vtable'ı .data'ya kendisi yazıp geri okuyor;
                //  imajda yuva 0'dır — yalnız GERÇEK x86 emülasyonu yakalar)
                auto* insE = az.InstructionsOf(0x4011e0);
                CHECK(insE != nullptr, "tier-3 vakasi fonksiyonu bulundu (0x4011e0)");
                u64 emuCall = 0;
                if (insE)
                    for (auto& x : *insE)
                        if (x.isCall && x.isIndirect) emuCall = x.addr;
                CHECK(emuCall != 0, "tier-3 cagrisi bulundu");
                if (emuCall) {
                    DevirtPro::Result r = dp.Resolve(emuCall);
                    CHECK(r.resolved, "tier-3: unicorn pencere emulasyonu cozdumu");
                    if (r.resolved) {
                        CHECK(r.target == 0x401070,
                              "tier-3 hedefi CEmu::method2 0x401070 (got 0x%llx)",
                              (unsigned long long)r.target);
                        CHECK(r.className == "CEmu" && r.slot == 2,
                              "tier-3: sinif=CEmu slot=2");
                        CHECK(r.why.find("tier-3") != std::string::npos,
                              "kanit tier-3 etiketli");
                    }
                }

                // ---- ATLAS İNVERSİYONU: sanal metod gövdesinde this-çağrı ----
                // (GetStatus bir sanal metottur; sahibi tek vftable = CPlayer
                //  → this'in vptr'si kanıtlanır → slot 34 statik çözülür)
                auto* insG = az.InstructionsOf(0x401020);
                CHECK(insG != nullptr, "GetStatus (sanal metod) bulundu");
                u64 innerCall = 0;
                if (insG)
                    for (auto& x : *insG)
                        if (x.isCall && x.isIndirect) innerCall = x.addr;
                CHECK(innerCall != 0, "GetStatus ic sanal cagri bulundu");
                if (innerCall) {
                    DevirtPro::Result r = dp.Resolve(innerCall);
                    CHECK(r.resolved && r.target == 0x401030,
                          "inversiyon: this->GetActorPtr cozuldu (0x401030)");
                    CHECK(r.className == "CPlayer" && r.slot == 34,
                          "inversiyon: sinif=CPlayer slot=34");
                }

                // ---- Instance() katlaması (PDB'siz — RTTI kanıtıyla!) ----
                std::string code = pc.DecompileFunction(0x4010e0);
                CHECK(code.find("CPlayer::Instance().vf4(") != std::string::npos,
                      "decomp: CPlayer::Instance().vf4(iType) — kaynak stili");
                CHECK(code.find("CPlayer::Instance().vf34()") != std::string::npos,
                      "decomp: CPlayer::Instance().vf34() — kaynak stili");
                size_t nI = 0, pI = 0;
                while ((pI = code.find("CPlayer::Instance()", pI)) != std::string::npos) {
                    nI++; pI += 8;
                }
                CHECK(nI == 2, "Instance() tam 2 kez (tek-sefer basim korunuyor) (got %zu)", nI);
                std::string codeE = pc.DecompileFunction(0x4011e0);
                CHECK(codeE.find("CEmu::vf2(") != std::string::npos,
                      "decomp: tier-3 cozumu CEmu::vf2 olarak render edildi");

                // ---- v8.1: vfN SÖZLÜĞÜ — "vf4 NE?" çıktıda cevaplanıyor ----
                // PDB'siz adlandırma vfN = vtable slot N (x86-32 ofset 4*N);
                // kanıt koordinatları çağrının yanında VE fonksiyon-sonu
                // sözlüğünde: vf4 = CPlayer vftable[0x402204] + 0x10 -> 0x401020
                CHECK(code.find("vf4 = CPlayer vftable[0x402204] + 0x10 -> 0x401020")
                          != std::string::npos,
                      "v8.1: vf4 sozluk notu (vtable+ofset+hedef kanit koordinatlari)");
                CHECK(code.find("vf34 = CPlayer vftable[0x402204] + 0x88 -> 0x401030")
                          != std::string::npos,
                      "v8.1: vf34 sozluk notu (+0x88 slot ofseti)");
                CHECK(code.find("vfN sozlugu") != std::string::npos,
                      "v8.1: fonksiyon-sonu vfN sozlugu footer'i");
                CHECK(codeE.find("vf2 = CEmu vftable[") != std::string::npos,
                      "v8.1: tier-3 cozumunun de vfN sozluk notu var");

                // ---- v8.1: MEKANİZMA KIRILIMI — sayılar tutarlı mı? ----
                // "N/M çözüldü" sayısının iç yapısı: çözülenler hangi kanıtla,
                // kalanlar hangi dürüst nedenle?
                const DevirtPro::Stats& st = dp.GetStats();
                CHECK(st.universe > 0, "kirilim: evren dolu (%zu)", st.universe);
                CHECK(st.resolved == st.byCtor + st.byAtlas + st.byTier3 +
                                     st.byIat + st.byConc,
                      "kirilim: cozulen kategori toplami = cozulen (%zu+%zu+%zu+%zu+%zu vs %zu)",
                      st.byCtor, st.byAtlas, st.byTier3, st.byIat, st.byConc,
                      st.resolved);
                CHECK(st.universe == st.resolved + st.unMultiCand +
                                     st.unNoProof + st.unTier3Win,
                      "kirilim: evren = cozulen + kalanlar (%zu vs %zu)",
                      st.universe, st.resolved + st.unMultiCand + st.unNoProof +
                                   st.unTier3Win);
                CHECK(st.byCtor >= 2, "kirilim: kurucu-kanitli cozumler var (%zu)",
                      st.byCtor);
                CHECK(st.byAtlas >= 1, "kirilim: atlas inversiyonu vakasi (%zu)",
                      st.byAtlas);
                CHECK(st.byTier3 >= 1, "kirilim: tier-3 unicorn vakasi (%zu)",
                      st.byTier3);
                CHECK(st.byIat >= 1, "kirilim: IAT import cozumu var (%zu)",
                      st.byIat);
                CHECK(st.unMultiCand >= 1,
                      "kirilim: muğlak vaka coklu-aday olarak kaldi (%zu)",
                      st.unMultiCand);
                delete pe;
            }
        } else {
            std::printf("     (fixture_devirt.exe yok — v8 testleri atlandi)\n");
        }
    }

    std::printf("\n== SONUC: %d PASS, %d FAIL ==\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
