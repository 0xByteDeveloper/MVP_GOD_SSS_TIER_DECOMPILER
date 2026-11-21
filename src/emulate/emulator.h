// ============================================================================
//  i4M GodTier Engine — emulate/emulator.h
//  Unicorn Engine sarmalayıcı: "kod çalıştırmadan çalıştırma".
//  Özellikler (Unicorn 10/10 + Speakeasy API shim + Qiling OS katmanı dersi):
//   - mapped görüntüyü emülatör belleğine kurar (shadow IAT dahil)
//   - yığın + PEB-lite + TEB-lite kurar (fs/gs tabanlı erişimler çökmesin)
//   - instruction trace (her komut hook'u — x64dbg trace gibi)
//   - bellek erişim günlüğü (okuma/yazma/erişim ihlali)
//   - register görünümü, tek adım / N adım / çalıştır-durdur
//   - API çağrısı yakalama: shadow adrese düşülünce shim çalışır
// ============================================================================
#pragma once
#include "format/binary.h"
#include "format/image.h"
#include "mapper/mapper.h"
#include "emulate/apishim.h"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <functional>
#include <string>
#include <vector>

namespace gt {

struct TraceEntry {
    u64 addr = 0;
    std::string text;        // "mov rax, rbx"
    u64 rsp = 0, retAddr = 0;
};

struct MemAccess {
    u64 addr = 0;
    u64 size = 0;
    u64 value = 0;
    bool write = false;
    bool invalid = false;    // unmapped erişim
};

struct EmuConfig {
    u64 stackTop    = 0x7FF000000000ull;
    u64 stackSize   = 0x100000;              // 1 MB
    u64 heapBase    = 0x500000000000ull;
    u64 heapSize    = 0x1000000;             // 16 MB
    size_t traceLimit = 100000;
    bool  traceEnabled = true;
    size_t apiCallLimit = 4096;
};

class Emulator {
public:
    Emulator();
    ~Emulator();
    Emulator(const Emulator&) = delete;
    Emulator& operator=(const Emulator&) = delete;

    // MappedImage + MapReport ile emülatör kur (görüntü, shadow IAT, stack, heap)
    bool Setup(const Binary& bin, const MappedImage& img, const MapReport& mapRep,
               Arch arch, const EmuConfig& cfg = {});
    bool Ok() const { return uc_ != nullptr; }

    // Çalıştırma modları
    bool Run(u64 startVa, u64 untilVa = 0, u64 timeoutUs = 0, size_t maxIns = 0);
    bool Step(size_t n = 1);                  // son Run start'ından devam
    void Stop();
    u64  CurrentPc() const;

    // Register erişimi
    u64  GetReg(int ucReg) const;
    void SetReg(int ucReg, u64 v);
    struct RegDump {
        u64 rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15, rip, eflags;
    };
    RegDump DumpRegs() const;
    static void PrintRegs(const RegDump& r);

    // Veri
    const std::vector<TraceEntry>& Trace() const { return trace_; }
    const std::vector<MemAccess>&  MemLog() const { return memLog_; }
    const std::vector<ApiCall>&    ApiCalls() const { return api_.Calls(); }
    const std::vector<MemAccess>&  Faults() const { return faults_; }
    std::string LastError() const { return lastErr_; }

    // Bellek (GUI/CLI için)
    bool ReadMem(u64 va, u8* out, size_t n) const;
    bool WriteMem(u64 va, const u8* p, size_t n);
    u64  AllocHeap(size_t size);              // shim'in HeapAlloc'u bunu kullanır
    u64  HeapBase() const { return cfg_.heapBase; }

    // API shim'e erişim (yeni API tanımlamak için)
    ApiShim& Shim() { return api_; }

    // Emülasyon bitti mi? (ExitProcess shim'i ya da ret ile ana akış bitti)
    bool Finished() const { return finished_; }
    const EmuConfig& Config() const { return cfg_; }

private:
    static void HookCode(uc_engine* uc, uint64_t address, uint32_t size, void* ud);
    static void HookMemInvalid(uc_engine* uc, uc_mem_type type, uint64_t address,
                               int size, int64_t value, void* ud);
    static void HookMemAccess(uc_engine* uc, uc_mem_type type, uint64_t address,
                              int size, int64_t value, void* ud);
    bool MapShadowIat();
    bool SetupStackAndPeb();

    uc_engine* uc_ = nullptr;
    Arch arch_ = Arch::X86_64;
    EmuConfig cfg_;
    const MapReport* mapRep_ = nullptr;
    u64 startVa_ = 0;
    bool finished_ = false;
    bool running_ = false;
    u64 finishedMagic_ = 0;      // ana akış ret'i buraya düşerse emülasyon bitti
    u64 heapCursor_ = 0;         // bump allocator imleci
    std::string lastErr_;
    std::vector<TraceEntry> trace_;
    std::vector<MemAccess> memLog_;
    std::vector<MemAccess> faults_;
    ApiShim api_;
    // komut metni için mini disassembler'a ihtiyaç var; forward decl yerine
    // burada capstone handle'ı ayrıca tutuyoruz
    csh cs_ = 0;
};

} // namespace gt
