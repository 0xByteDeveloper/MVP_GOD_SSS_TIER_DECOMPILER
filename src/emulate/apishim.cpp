// ============================================================================
//  i4M GodTier Engine — emulate/apishim.cpp
// ============================================================================
#include "emulate/apishim.h"
#include "emulate/emulator.h"
#include "core/log.h"
#include "core/util.h"
#include <cstring>
#include <cstdio>

namespace gt {

// emülatör belleğinden null-sonlu string oku (max 260)
static std::string ReadStr(const ApiShim& shim, u64 va, size_t maxLen = 260) {
    if (!va || !shim.readMem) return "";
    std::vector<u8> buf(maxLen + 1, 0);
    if (!shim.readMem(va, buf.data(), maxLen)) return "";
    buf[maxLen] = 0;
    return std::string((const char*)buf.data());
}

u64 ApiShim::Handle(Emulator& emu, const std::string& dll, const std::string& func,
                    const u64 args[4], u64 rsp, u64& retAddr, bool& stopEmu) {
    (void)emu;
    retAddr = 0;
    if (readMem) {
        u8 tmp[8];
        if (readMem(rsp, tmp, 8))
            memcpy(&retAddr, tmp, 8);
    }

    ApiCall call;
    call.dll = dll; call.func = func;
    for (int i = 0; i < 4; i++) call.args[i] = args[i];
    u64 ret = 0;
    std::string lname = ToLower(func);

    // ------------------------------------------------------------------
    // Yaygın API'ler için gerçekçi davranış
    // ------------------------------------------------------------------
    if (lname == "exitprocess" || lname == "exitthread") {
        call.note = "process sonlandirildi (kod=" + std::to_string((u32)args[0]) + ")";
        stopEmu = true;
        ret = 0;
    }
    else if (lname == "heapalloc") {
        // x64: rcx=hHeap, rdx=flags, r8=size
        size_t sz = (size_t)args[2];
        ret = allocHeap ? allocHeap(sz) : 0;
        call.note = "size=" + std::to_string(sz) + " -> 0x" + ToHex(ret);
    }
    else if (lname == "heapfree") {
        ret = 1; // başarı
    }
    else if (lname == "getmodulehandlea" || lname == "getmodulehandlew" ||
             lname == "getmodulehandleexa" || lname == "getmodulehandleexw") {
        std::string name = ReadStr(*this, args[0]);
        std::string key = ToLower(name);
        auto it = moduleHandles_.find(key);
        if (it == moduleHandles_.end()) {
            fakeHandleCounter_ += 0x10000;
            moduleHandles_[key] = fakeHandleCounter_;
            it = moduleHandles_.find(key);
        }
        ret = it->second;
        call.note = name.empty() ? "(exe kendisi)" : name;
    }
    else if (lname == "getprocaddress") {
        // rcx = module, rdx = proc name (string ya da ordinal)
        std::string name = ReadStr(*this, args[1]);
        std::string key = ToLower(name);
        auto it = procAddresses_.find(key);
        if (it == procAddresses_.end()) {
            fakeHandleCounter_ += 0x100;
            procAddresses_[key] = fakeHandleCounter_;
            it = procAddresses_.find(key);
        }
        ret = it->second;
        call.note = name;
    }
    else if (lname == "isdebuggerpresent") {
        ret = 0; // Anti-debug: her zaman temiz — GOD mod
        call.note = "false (temiz)";
    }
    else if (lname == "getversion" || lname == "getversionexa" || lname == "getversionexw") {
        ret = 0x0A000004; // Win10 benzeri 10.0 major
        call.note = "Windows 10 sahtesi";
    }
    else if (lname == "messageboxa" || lname == "messageboxw") {
        // x64: rcx=hWnd, rdx=lpText, r8=lpCaption, r9=uType
        std::string text = ReadStr(*this, args[1]);
        std::string caption = ReadStr(*this, args[2]);
        call.note = "\"" + (text.size() > 60 ? text.substr(0, 60) + "..." : text) +
                    "\" / \"" + caption + "\"";
        if (out) out("[MessageBox] " + text + (caption.empty() ? "" : "  (caption: " + caption + ")"));
        ret = 1; // IDOK
    }
    else if (lname == "outputdebugstringa" || lname == "outputdebugstringw") {
        std::string text = ReadStr(*this, args[0]);
        call.note = text;
        if (out && !text.empty()) out("[OutputDebugString] " + text);
        ret = 0;
    }
    else if (lname == "getlasterror") { ret = 0; }
    else if (lname == "setlasterror") { call.note = "dwError=" + ToHex(args[0]); ret = 0; }
    else if (lname == "virtualalloc") {
        // rcx=addr, rdx=size, r8=type, r9=prot
        ret = allocHeap ? allocHeap((size_t)args[1]) : 0;
        call.note = "size=0x" + ToHex(args[1]) + " -> 0x" + ToHex(ret);
    }
    else if (lname == "virtualfree" || lname == "virtualprotect") { ret = 1; }
    else if (lname == "lstrlena" || lname == "lstrlenw" || lname == "strlen") {
        std::string s = ReadStr(*this, args[0], 4096);
        ret = s.size();
    }
    else if (lname == "getcommandlinea" || lname == "getcommandlinew") {
        ret = allocHeap ? allocHeap(64) : 0;
        if (ret && readMem) {
            const char* cmd = "\"godtier_emulated.exe\"";
            readMem(ret, (u8*)cmd, strlen(cmd) + 1);
        }
        call.note = "sahte komut satırı";
    }
    else if (lname == "getstartupinfoa" || lname == "getstartupinfow") {
        ret = 0; call.note = "(yapı doldurulmadı)";
    }
    else if (lname == "initializecriticalsection" || lname == "deletecriticalsection" ||
             lname == "entercriticalsection" || lname == "leavecriticalsection") {
        ret = 0;
    }
    else {
        // bilinmeyen API: güvenli log
        call.note = "(shim: bilinmeyen API, 0 dondu)";
        ret = 0;
    }

    call.ret = ret;
    if (calls_.size() < logLimit_) calls_.push_back(call);
    return ret;
}

} // namespace gt
