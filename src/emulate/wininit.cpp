// ============================================================================
//  i4M GodTier Engine — emulate/wininit.cpp
//  Tier-5a WİNINIT uygulaması (bkz. wininit.h akış diyagramı).
//  Windows Internals süreç başlangıcı: kernel(peb/adres) → yığın → import
//  → TLS(EP'den önce!) → EP(CRT init) → WinMain(duvar). Her faz dürüst
//  raporlanır; herhangi birinde durursak o ana kadarki anlık görüntü yine
//  kanıt olarak çıkar.
// ============================================================================
#include "emulate/wininit.h"
#include "emulate/apishim.h"
#include "core/log.h"
#include "core/util.h"
#include <cstring>
#include <algorithm>

namespace gt {
namespace {

// deterministik çevre (her yürütmede AYNI — WinInit'in sözü)
constexpr u32 kFakePid = 0x1A2B;
constexpr u32 kFakeTid = 0x1A2C;
constexpr u32 kFakeTick = 0x11223344;
constexpr u64 kFakeQpc = 0x1234567890ull;
constexpr u64 kFakeFileTime = 0x01DB000000000000ull;   // 2026 civarı, sabit
constexpr u64 kFakeHeapHandle = 0x00AB1000ull;
constexpr u64 kFakeThreadHandle = 0x00AB3000ull;

} // namespace

WinInit::WinInit(const PE& pe, const MsvcRtti* rtti) : pe_(pe), rtti_(rtti) {}

// ----------------------------------------------------------------------------
const char* WinInitReport::StopName() const {
    switch (stop) {
        case Stop::Wall:   return "DUVAR";
        case Stop::Budget: return "BUTCE";
        case Stop::Fault:  return "HATA";
        case Stop::Ret:    return "EP-DONDU";
        case Stop::Exit:   return "EXIT";
        default:           return "yok";
    }
}

std::string WinInitReport::Summary() const {
    std::string s;
    char b[256];
    s += "== WININIT (Tier-5a) — Windows process-init benzetimi ==\n";
    if (!ok) {
        snprintf(b, sizeof b, "  HATA: %s\n", error.c_str());
        s += b;
        return s;
    }
    snprintf(b, sizeof b, "  giris 0x%llx (%s) | TLS: %zu/%zu callback kostu (EP oncesi)\n",
             (unsigned long long)entryVa, isDll ? "DllMain" : "EP",
             tlsCallbacksRun, tlsCallbacksTotal);
    s += b;
    snprintf(b, sizeof b, "  durus: %-8s %s", StopName(), stopDetail.c_str());
    s += b;
    if (stopPc) {
        snprintf(b, sizeof b, " @ rip=0x%llx", (unsigned long long)stopPc);
        s += b;
    }
    s += "\n";
    snprintf(b, sizeof b,
             "  yurutulen komut: %zu | API cagrisi: %zu (bilinmeyen: %zu, "
             "stdcall-temizligi belirsiz: %zu)\n",
             instructions, apiCalls, apiUnknown, stackCleanupUnknown);
    s += b;
    snprintf(b, sizeof b,
             "  KANIT: statik slot degisimi %zu | heap vptr %zu | heap alloc %zu"
             " | overlay: %zu giris\n",
             staticSlotsChanged, heapVptrSlots, heapAllocs, overlay.size());
    s += b;
    s += "  not: overlay = tek deterministik init yurutmesinin anlik goruntusu;\n"
         "       statik kanit zinciri (kurucu/atlas) her zaman onceliklidir\n";
    if (!apiTail.empty()) {
        s += "  son API cagrilari (teshis):\n";
        for (auto& t : apiTail) s += "    " + t + "\n";
    }
    if (!traceTail.empty()) {
        s += "  son KOMUTLAR (teshis, verbose):\n";
        for (auto& t : traceTail) s += "    " + t + "\n";
    }
    return s;
}

// ----------------------------------------------------------------------------
// ortam kurulumu
// ----------------------------------------------------------------------------
bool WinInit::SetupEnv(Arch arch, const WinInitConfig& cfg) {
    is64_ = (arch == Arch::X86_64);

    // 1) kendi eşlenmiş görüntü kopyamız (Shell görüntüsüne DOKUNMAZ):
    //    reloc uygula + shadow-IAT doldur — Windows Ldr'ın yaptıkları
    mapRep_ = mapper_.MapPE(pe_, wimg_, MapOptions{});
    if (!mapRep_.success) {
        rep_.error = "MapPE basarisiz";
        return false;
    }

    // 2) yığın/heap düzeni DevirtEmu ile BİREBİR aynı tutulur (overlay'deki
    //    heap adresleri tier-3 emülatöründe de geçerli olsun diye)
    EmuConfig ec;
    ec.traceEnabled = cfg.verbose;    // teşhis modunda tam iz
    ec.insCountOnly = !cfg.verbose;
    ec.quiet = true;
    ec.apiCallLimit = 200'000;
    ec.strictStdcall = true;             // WinInit modunda stdcall temizliği AÇIK
    if (!is64_) {
        ec.stackTop = 0x7FF00000ull;
        ec.heapBase = 0x52000000ull;
        ec.heapSize = 0x01000000ull;     // 16 MB (ilk 4 MB'ı tier-3 ile örtüşür)
    }
    emu_ = std::make_unique<Emulator>();
    if (!emu_->Setup(pe_, wimg_, mapRep_, arch, ec)) {
        rep_.error = "emulator kurulumu basarisiz: " + emu_->LastError();
        return false;
    }

    // 3) WinInit'e özgü shim ortamı
    ApiShim& sh = emu_->Shim();
    sh.SetWallMode();                    // duvar-API kümesi + gerçekçi Win32 shimleri
    sh.imageBaseOverride = pe_.ImageBase();

    // 4) NT TEB/PEB doğrulaması (Emulator'un lite sürümü üstüne gerçek ofsetler)
    //    x86-32: Self+0x18, StackBase+4, StackLimit+8, PEB+0x30, TLS dizi+0x2C
    //    x64:    Self+0x30, StackBase+8, StackLimit+0x10, PEB+0x60, TLS dizi+0x58
    const u64 teb = emu_->TebVa(), peb = emu_->PebVa();
    const u64 ps = PtrSize();
    u64 stackBase = emu_->Config().stackTop;
    u64 stackLimit = stackBase - emu_->Config().stackSize;
    u64 one = 0xFFFFFFFFull, zero = 0;
    emu_->WriteMem(teb + (is64_ ? 0x00 : 0x00), (u8*)&one, ps);        // ExceptionList boş
    emu_->WriteMem(teb + (is64_ ? 0x08 : 0x04), (u8*)&stackBase, ps);  // StackBase
    emu_->WriteMem(teb + (is64_ ? 0x10 : 0x08), (u8*)&stackLimit, ps); // StackLimit
    u64 self = teb;
    emu_->WriteMem(teb + (is64_ ? 0x30 : 0x18), (u8*)&self, ps);       // Self
    u64 pid = kFakePid, tid = kFakeTid;
    emu_->WriteMem(teb + (is64_ ? 0x40 : 0x20), (u8*)&pid, ps);        // ClientId.Pid
    emu_->WriteMem(teb + (is64_ ? 0x48 : 0x24), (u8*)&tid, ps);        // ClientId.Tid
    emu_->WriteMem(teb + (is64_ ? 0x68 : 0x34), (u8*)&zero, 4);        // LastErrorValue

    // PEB: ImageBaseAddress + ProcessParameters (CommandLine'lı, yığın değil heap'te)
    u64 imgBase = pe_.ImageBase();
    emu_->WriteMem(peb + (is64_ ? 0x10 : 0x08), (u8*)&imgBase, ps);
    u64 params = emu_->AllocHeap(0x200);
    if (params) {
        // RTL_USER_PROCESS_PARAMETERS (yalnız ihtiyaç duyulan alanlar)
        // CommandLine: UNICODE_STRING (u16 Len, u16 MaxLen, ptr Buffer)
        std::string cmd = "\"";
        cmd += "godtier_wininit.exe\"";      // sabit — determinizm
        std::vector<u8> wcmd;
        for (char c : cmd) { wcmd.push_back((u8)c); wcmd.push_back(0); }
        u64 cmdBuf = params + 0x100;
        emu_->WriteMem(cmdBuf, wcmd.data(), wcmd.size() + 2);
        u32 maxLen16 = (u32)wcmd.size() + 2;
        emu_->WriteMem(params + 0x40, (u8*)&maxLen16, 2);        // us.MaximumLength
        u32 len16 = (u32)wcmd.size();
        emu_->WriteMem(params + 0x42, (u8*)&len16, 2);           // us.Length
        emu_->WriteMem(params + 0x44, (u8*)&cmdBuf, ps);         // us.Buffer
        emu_->WriteMem(peb + (is64_ ? 0x20 : 0x10), (u8*)&params, ps);
        u32 maxLen = 0x200, len = 0x200;
        emu_->WriteMem(params + 0x00, (u8*)&maxLen, 4);          // MaximumLength
        emu_->WriteMem(params + 0x04, (u8*)&len, 4);             // Length
    }

    // 5) TLS: __tls_index = 0 + ThreadLocalStoragePointer -> sıfır sayfa
    //    (Windows Ldr'ın TLS dizinini işleyişi; callback'ler EP'den ÖNCE)
    auto tls = pe_.TLS();
    if (tls.present) {
        u64 zeroPage = emu_->AllocHeap(0x1000);
        if (tls.indexVa)
            emu_->WriteMem(tls.indexVa, (u8*)&zero, ps);         // index = 0
        if (zeroPage)
            emu_->WriteMem(teb + (is64_ ? 0x58 : 0x2C), (u8*)&zeroPage, ps);
    }
    (void)cfg;
    return true;
}

// ----------------------------------------------------------------------------
// faz 4: TLS callback'ler (Reason=DLL_PROCESS_ATTACH=1)
// ----------------------------------------------------------------------------
bool WinInit::RunTlsCallbacks(const WinInitConfig& cfg) {
    rep_.tlsPhaseRan = true;
    auto tls = pe_.TLS();
    if (!tls.present || !tls.callbacksVa) return true;

    // callback dizisi: VA... NULL sonlandırmalı (mapped görüntüden oku)
    std::vector<u64> cbs;
    const u64 ps = PtrSize();
    for (u64 va = tls.callbacksVa; cbs.size() < 64; va += ps) {
        u64 cb = 0;
        if (!wimg_.ReadBytes(va, (u8*)&cb, ps) || !cb) break;
        cbs.push_back(cb);
    }
    rep_.tlsCallbacksTotal = cbs.size();
    for (u64 cb : cbs) {
        // (DllHandle=imageBase, Reason=1, Reserved=0)
        std::vector<u64> args{ pe_.ImageBase(), 1, 0 };
        emu_->ResetExecuted();
        emu_->RunWithArgs(cb, args, cfg.timeoutUs, cfg.maxInstructions);
        rep_.tlsCallbacksRun++;
        if (!emu_->Faults().empty()) {
            char b[128];
            snprintf(b, sizeof b, "TLS callback 0x%llx hata yapti (0x%llx)",
                     (unsigned long long)cb,
                     (unsigned long long)emu_->Faults().front().addr);
            rep_.stopDetail = b;
            rep_.stopPc = emu_->CurrentPc();
            rep_.stop = WinInitReport::Stop::Fault;
            return false;   // Windows'ta yakalanmamış TLS istisnası = süreç ölür
        }
    }
    return true;
}

// ----------------------------------------------------------------------------
// faz 5: EP (CRT init → ... → duvar)
// ----------------------------------------------------------------------------
void WinInit::RunEntryPoint(const WinInitConfig& cfg) {
    std::vector<u64> args;
    if (pe_.IsDll()) {                   // DllMain(hInst, PROCESS_ATTACH, 0)
        args = { pe_.ImageBase(), 1, 0 };
        rep_.isDll = true;
    }
    emu_->ResetExecuted();
    bool epRunOk = emu_->RunWithArgs(entryVa_, args, cfg.timeoutUs, cfg.maxInstructions);
    rep_.instructions = emu_->Executed();
    if (rep_.instructions == 0 && !emu_->Trace().empty())
        rep_.instructions = emu_->Trace().size();   // verbose mod: iz uzunlugu
    if (cfg.verbose) {
        // teşhis: son 100 komut (adres + metin)
        const auto& tr = emu_->Trace();
        char b[192];
        size_t from = tr.size() > 400 ? tr.size() - 400 : 0;
        for (size_t i = from; i < tr.size(); i++) {
            snprintf(b, sizeof b, "0x%llx  %-40s rsp=0x%llx",
                     (unsigned long long)tr[i].addr, tr[i].text.c_str(),
                     (unsigned long long)tr[i].rsp);
            rep_.traceTail.push_back(b);
        }
    }

    const auto& calls = emu_->Shim().Calls();
    rep_.apiCalls = calls.size();
    rep_.apiUnknown = emu_->Shim().unknownCount();
    rep_.stackCleanupUnknown = emu_->Shim().stackCleanupUnknown();
    // teshis kuyrugu: son 40 cagri (ret + cagiran VA ile)
    {
        char b[176];
        size_t from = calls.size() > 40 ? calls.size() - 40 : 0;
        for (size_t i = from; i < calls.size(); i++) {
            snprintf(b, sizeof b, "%s.%s -> 0x%llx (cagiran 0x%llx) %s",
                     calls[i].dll.c_str(), calls[i].func.c_str(),
                     (unsigned long long)calls[i].ret,
                     (unsigned long long)calls[i].caller,
                     calls[i].note.c_str());
            rep_.apiTail.push_back(b);
        }
    }

    // niçin durduk? (öncelik: duvar > exit > hata > butçe > EP-ret)
    if (emu_->Shim().wallHit()) {
        rep_.stop = WinInitReport::Stop::Wall;
        rep_.stopDetail = emu_->Shim().wallApiName();
    } else if (emu_->Finished() && !emu_->Faults().empty()) {
        // ExitProcess/ExitThread shim'i durdurduysa Finished true olur; hata yok
        bool exited = false;
        for (auto it = calls.rbegin(); it != calls.rend(); ++it)
            if (ToLower(it->func) == "exitprocess" || ToLower(it->func) == "exitthread" ||
                ToLower(it->func) == "terminateprocess") { exited = true; break; }
        if (exited) {
            rep_.stop = WinInitReport::Stop::Exit;
            rep_.stopDetail = "ExitProcess ailesi (dogal son)";
        }
    }
    if (rep_.stop == WinInitReport::Stop::None && !epRunOk && emu_->Faults().empty()) {
        // int 0x29 (__fastfail) gibi CPU istisnaları: unicorn uc_emu_start hatasi
        char b[160];
        snprintf(b, sizeof b, "CPU istisnasi (%s) — rip=0x%llx [int 0x29 = CRT __fastfail olabilir]",
                 emu_->LastError().c_str(), (unsigned long long)emu_->CurrentPc());
        rep_.stopDetail = b;
        rep_.stopPc = emu_->CurrentPc();
        rep_.stop = WinInitReport::Stop::Fault;
    }
    if (rep_.stop == WinInitReport::Stop::None && !emu_->Faults().empty()) {
        char b[160];
        auto& f = emu_->Faults().front();
        snprintf(b, sizeof b, "eslenmemis bellek erisimi 0x%llx (%s)",
                 (unsigned long long)f.addr, f.write ? "YAZMA" : "OKUMA");
        rep_.stopDetail = b;
        rep_.stopPc = emu_->CurrentPc();
        rep_.stop = WinInitReport::Stop::Fault;
    }
    if (rep_.stop == WinInitReport::Stop::None) {
        if (rep_.instructions >= cfg.maxInstructions) {
            rep_.stop = WinInitReport::Stop::Budget;
            rep_.stopDetail = "komut butcesi doldu (" + std::to_string(cfg.maxInstructions) + ")";
            rep_.stopPc = emu_->CurrentPc();
        } else {
            rep_.stop = WinInitReport::Stop::Ret;
            rep_.stopDetail = "EP kendi ret'iyle bitti (duvara degmeden)";
        }
    }
}

// ----------------------------------------------------------------------------
// kanıt yardımcıları
// ----------------------------------------------------------------------------
bool WinInit::IsExecVa(u64 va) const {
    for (auto& s : pe_.Sections())
        if (s.executable && va >= s.va && va < s.va + std::max(s.vsize, s.rawSize))
            return true;
    return false;
}

bool WinInit::InImage(u64 va) const {
    return va >= pe_.ImageBase() && va < pe_.ImageBase() + pe_.ImageSize();
}

bool WinInit::IsIatSlot(u64 va) const {
    for (auto& d : pe_.Imports())
        for (auto& f : d.funcs)
            if (f.iatVa == va) return true;
    return false;
}

bool WinInit::IsVftableLike(u64 v) {
    if (!InImage(v) || IsExecVa(v)) return false;
    if (rtti_ && rtti_->ByVftable(v)) return true;
    // sezgisel: veri bölümünde dur + ilk slot kod işaretçisi
    const u64 ps = PtrSize();
    u64 first = 0;
    if (!emu_->ReadMem(v, (u8*)&first, ps)) return false;
    return first && IsExecVa(first);
}

// ----------------------------------------------------------------------------
// faz 6: anlık görüntü → overlay
// ----------------------------------------------------------------------------
void WinInit::BuildOverlay(const WinInitConfig& cfg) {
    const u64 ps = PtrSize();
    const auto& cfgE = emu_->Config();

    // 1) yazılabilir bölümler: mapped-görüntü (ön-durum) vs emülatör (son-durum)
    for (auto& s : pe_.Sections()) {
        if (!s.writable) continue;
        u64 lo = s.va & ~(ps - 1);
        u64 hi = s.va + std::max(s.vsize, s.rawSize);
        for (u64 va = lo; va + ps <= hi && rep_.overlay.size() < cfg.overlayMax; va += ps) {
            u64 now = 0, before = 0;
            if (!emu_->ReadMem(va, (u8*)&now, ps)) continue;
            if (!wimg_.ReadBytes(va, (u8*)&before, ps)) before = 0;
            if (now == before || now == 0) continue;
            if (IsIatSlot(va)) continue;                       // IAT: devirt kendi çözer
            if (now >= SHADOW_IAT_BASE && now < SHADOW_IAT_BASE + SHADOW_IAT_SIZE)
                continue;                                      // shadow adresi sızmaz
            rep_.staticSlotsChanged++;
            rep_.overlay[va] = now;
        }
    }

    // 2) heap taraması: vptr taşıyan slotlar (statik kanıt olmayan heap
    //    nesnelerinin init sırasında kurulmuş vtable'ları)
    u64 hb = cfgE.heapBase, hs = cfgE.heapSize;
    for (u64 va = hb; va + ps <= hb + hs && rep_.overlay.size() < cfg.overlayMax; va += ps) {
        u64 v = 0;
        if (!emu_->ReadMem(va, (u8*)&v, ps) || v == 0) continue;
        if (!IsVftableLike(v)) continue;
        if (rep_.overlay.count(va) && rep_.overlay[va] == v) continue;
        rep_.heapVptrSlots++;
        rep_.overlay[va] = v;
    }

    // 3) heap ayırma kayıtları (allocation-site kanıtı için hammadde)
    for (auto& c : emu_->Shim().Calls()) {
        std::string f = ToLower(c.func);
        if (f == "heapalloc" || f == "localalloc" || f == "globalalloc" ||
            f == "virtualalloc")
            rep_.heapAllocs++;
    }
}

// ----------------------------------------------------------------------------
// ana akış
// ----------------------------------------------------------------------------
WinInitReport WinInit::Run(Arch arch, const WinInitConfig& cfg) {
    rep_ = WinInitReport{};
    if (arch != Arch::X86_32 && arch != Arch::X86_64) {
        rep_.error = "wininit yalnız x86/x64 PE";
        return rep_;
    }
    entryVa_ = pe_.EntryPoint();
    rep_.entryVa = entryVa_;

    if (!SetupEnv(arch, cfg)) return rep_;

    LogInfo("wininit: TLS fazı (EP oncesi)...");
    if (!RunTlsCallbacks(cfg)) {
        rep_.ok = true;                   // kısmi sonuç yine kanıttır
        BuildOverlay(cfg);
        return rep_;
    }

    LogInfo("wininit: EP fazı (CRT-init → duvar) 0x%llx...", (unsigned long long)entryVa_);
    RunEntryPoint(cfg);
    LogInfo("wininit: anlık görüntü çıkarılıyor...");
    BuildOverlay(cfg);
    rep_.ok = true;
    return rep_;
}

} // namespace gt
