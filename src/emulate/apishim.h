// ============================================================================
//  i4M GodTier Engine — emulate/apishim.h
//  Windows API emülasyon katmanı (Speakeasy dersi).
//  Shadow IAT adresine düşüldüğünde bu katman devreye girer:
//   - çağrı günlüğü tutar (argümanlarla birlikte — "apitrace")
//   - yaygın API'ler için gerçekçi davranış: HeapAlloc, GetModuleHandleA,
//     GetProcAddress, ExitProcess, GetVersion, IsDebuggerPresent...
//   - bilinmeyen API'ler: log + zararsız dönüş (0 / stub)
// ============================================================================
#pragma once
#include "core/types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace gt {

struct ApiCall {
    std::string dll;        // "kernel32.dll"
    std::string func;       // "CreateFileA"
    u64 args[4] = {};       // ilk 4 argüman (x64: rcx,rdx,r8,r9)
    u64 ret = 0;            // döndürülen değer
    std::string note;       // okunabilen string argümanlar vs.
};

class Emulator; // ileri beyan

class ApiShim {
public:
    // Bir API çağrısını işle: dönüş değeri RAX'e yazılır
    // (retAddr = [rsp]; çağıran bu bilgiyi kullanıp rip'i ayarlar)
    u64 Handle(Emulator& emu, const std::string& dll, const std::string& func,
               const u64 args[4], u64 rsp, u64& retAddr, bool& stopEmu);

    const std::vector<ApiCall>& Calls() const { return calls_; }
    void SetLogLimit(size_t n) { logLimit_ = n; }

    // Okunabilir string argümanı okumak için emülatör bellek erişimi
    std::function<bool(u64, u8*, size_t)> readMem;
    std::function<u64(size_t)> allocHeap;
    std::function<void(const std::string&)> out; // konsol çıktısı (WriteFile/printf yakalama)

private:
    std::vector<ApiCall> calls_;
    size_t logLimit_ = 4096;
    std::unordered_map<std::string, u64> moduleHandles_; // GetModuleHandle sahtesi
    std::unordered_map<std::string, u64> procAddresses_; // GetProcAddress sahtesi
    u64 fakeHandleCounter_ = 0x00AB0000;
};

} // namespace gt
