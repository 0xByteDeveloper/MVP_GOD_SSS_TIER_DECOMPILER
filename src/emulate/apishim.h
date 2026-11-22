// ============================================================================
//  i4M GodTier Engine — emulate/apishim.h
//  Windows API emülasyon katmanı (Speakeasy dersi).
//  Shadow IAT adresine düşüldüğünde bu katman devreye girer:
//   - çağrı günlüğü tutar (argümanlarla birlikte — "apitrace")
//   - yaygın API'ler için gerçekçi davranış: HeapAlloc, GetModuleHandleA,
//     GetProcAddress, ExitProcess, GetVersion, IsDebuggerPresent...
//   - bilinmeyen API'ler: log + zararsız dönüş (0 / stub)
//  v9.2 (WinInit Tier-5a):
//   - DUVAR kipi: oyun mantığı API'lerinde (mesaj döngüsü/ağ/pencere)
//     emülasyon DÜRÜSTÇE durur — "sonsuz bekleme" tuzağı yok
//   - Win32 stdcall bayt tablosu: x86-32'de çağrılanın yığıttan söktüğü
//     argüman bayt sayısı (Qiling/Speakeasy prototip-DB fikrinin MVP'si)
//   - deterministik çevre: PID/TID/saat/QPC/tick sabit tohumlu
//   - writeMem kanalı: GetSystemTimeAsFileTime gibi yapı-dolduran API'ler
// ============================================================================
#pragma once
#include "core/types.h"
#include <set>
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
    u64 caller = 0;         // çağıran dönüş adresi (allocation-site kanıtı)
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

    // ---- v9.2 WinInit (Tier-5a) ----
    // duvar kipi: duvar-API kümesi + gerçekçi Win32 shimleri açılır
    void SetWallMode();
    bool wallHit() const { return wallHit_; }
    const std::string& wallApiName() const { return wallApiName_; }
    size_t unknownCount() const { return unknownCount_; }
    size_t stackCleanupUnknown() const { return stackCleanupUnknown_; }
    // x86-32 stdcall: fonksiyonun yığıttan söktüğü bayt sayısı
    // (0 = cdecl/bilinmiyor; 0xFFFFFFFF = tabloda yok → düzeltme yapılmaz)
    static u32 Win32StdcallBytes(const std::string& lowerFunc);
    void NoteStackCleanupUnknown() { stackCleanupUnknown_++; }

    // Okunabilir string argümanı okumak için emülatör bellek erişimi
    std::function<bool(u64, u8*, size_t)> readMem;
    std::function<bool(u64, const u8*, size_t)> writeMem;   // v9.2: yapı doldurma
    std::function<u64(size_t)> allocHeap;
    // v9.2: GetProcAddress için ÇAĞRILABİLİR dinamik stub üret
    // (statik UCRT CRT-init'te API'leri GetProcAddress ile bulup ÇAĞIRIYOR —
    //  sahte sayı dönersek çağrı 0xAC.. adresine düşüp çöker)
    std::function<u64(const std::string& dll, const std::string& func)> makeDynStub;
    std::function<void(const std::string&)> out; // konsol çıktısı (WriteFile/printf yakalama)

    u64 imageBaseOverride = 0;    // GetModuleHandle(NULL) → gerçek ImageBase

private:
    std::vector<ApiCall> calls_;
    size_t logLimit_ = 4096;
    std::unordered_map<std::string, u64> moduleHandles_; // GetModuleHandle sahtesi
    std::unordered_map<std::string, u64> procAddresses_; // GetProcAddress sahtesi
    u64 fakeHandleCounter_ = 0x00AB0000;
    // v9.2
    bool wallMode_ = false;
    bool wallHit_ = false;
    std::string wallApiName_;
    size_t unknownCount_ = 0;
    size_t stackCleanupUnknown_ = 0;
    std::set<std::string> wallApis_;
    u64 threadHandleCounter_ = 0x00AB3000;
};

} // namespace gt
