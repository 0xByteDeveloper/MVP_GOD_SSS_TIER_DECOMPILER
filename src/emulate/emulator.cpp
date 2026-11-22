// ============================================================================
//  i4M GodTier Engine — emulate/emulator.cpp
// ============================================================================
#include "emulate/emulator.h"
#include "core/log.h"
#include "core/util.h"
#include <capstone/capstone.h>
#include <cstring>

namespace gt {

Emulator::Emulator() = default;

Emulator::~Emulator() {
    if (uc_) uc_close(uc_);
    if (cs_) cs_close(&cs_);
}

// ----------------------------------------------------------------------------
// Kurulum
// ----------------------------------------------------------------------------
bool Emulator::Setup(const Binary& bin, const MappedImage& img, const MapReport& mapRep,
                     Arch arch, const EmuConfig& cfg) {
    if (uc_) { uc_close(uc_); uc_ = nullptr; }
    if (cs_) { cs_close(&cs_); cs_ = 0; }
    cfg_ = cfg;
    arch_ = arch;
    mapRep_ = &mapRep;
    finished_ = false;
    trace_.clear(); memLog_.clear(); faults_.clear();
    api_ = ApiShim{};
    api_.allocHeap = [this](size_t n) { return AllocHeap(n); };
    api_.readMem = [this](u64 va, u8* o, size_t n) { return ReadMem(va, o, n); };
    api_.writeMem = [this](u64 va, const u8* p, size_t n) { return WriteMem(va, p, n); };
    api_.out = [](const std::string& s) { LogLine(LogColor::Yellow, "    %s", s.c_str()); };
    api_.SetLogLimit(cfg.apiCallLimit);   // v9.2: yapılandırma artık gerçekten bağlandı
    api_.makeDynStub = [this](const std::string& d, const std::string& f) {
        return MakeDynApiStub(d, f);
    };
    dynStubCursor_ = DYN_STUB_BASE;
    dynStubs_.clear();

    uc_mode mode = (arch == Arch::X86_64) ? UC_MODE_64 : UC_MODE_32;
    if (uc_open(UC_ARCH_X86, mode, &uc_) != UC_ERR_OK) {
        lastErr_ = "uc_open basarisiz";
        return false;
    }
    // trace için capstone
    cs_mode cmode = (arch == Arch::X86_64) ? CS_MODE_64 : CS_MODE_32;
    cs_open(CS_ARCH_X86, cmode, &cs_);

    // 1) görüntüyü map et (sayfa hizalı)
    u64 base = img.Base() & ~0xFFFull;
    u64 end = (img.Base() + img.Size() + 0xFFF) & ~0xFFFull;
    if (uc_mem_map(uc_, base, end - base, UC_PROT_ALL) != UC_ERR_OK) {
        lastErr_ = "goruntu map edilemedi";
        return false;
    }
    if (uc_mem_write(uc_, img.Base(), img.Data().data(), img.Data().size()) != UC_ERR_OK) {
        lastErr_ = "goruntu yazilamadi";
        return false;
    }

    // 2) shadow IAT bölgesi
    if (!MapShadowIat()) return false;

    // 3) yığın + PEB/TEB
    if (!SetupStackAndPeb()) return false;

    // 4) heap
    if (uc_mem_map(uc_, cfg_.heapBase, cfg_.heapSize, UC_PROT_ALL) != UC_ERR_OK) {
        lastErr_ = "heap map edilemedi";
        return false;
    }
    heapCursor_ = cfg_.heapBase;

    // 4b) v9.2: dinamik API stub bölgesi (GetProcAddress yoluyla — WinInit)
    if (uc_mem_map(uc_, DYN_STUB_BASE, DYN_STUB_SIZE, UC_PROT_ALL) != UC_ERR_OK) {
        lastErr_ = "dinamik stub bolgesi map edilemedi";
        return false;
    }

    // 5) hook'lar
    uc_hook h1, h2, h3;
    uc_hook_add(uc_, &h1, UC_HOOK_CODE, (void*)HookCode, this, 1, 0);
    uc_hook_add(uc_, &h2, UC_HOOK_MEM_INVALID, (void*)HookMemInvalid, this, 1, 0);
    uc_hook_add(uc_, &h3, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, (void*)HookMemAccess, this, 1, 0);

    (void)bin;
    LogOk("Emulator hazir: goruntu 0x%llx + stack + heap (Unicorn %u.%u)",
          (unsigned long long)img.Base(), UC_VERSION_MAJOR, UC_VERSION_MINOR);
    return true;
}

bool Emulator::MapShadowIat() {
    if (!mapRep_) return true;
    // bölgeyi map et (çalıştırılabilir görünmesine gerek yok ama ALL güvenli)
    if (uc_mem_map(uc_, SHADOW_IAT_BASE, SHADOW_IAT_SIZE, UC_PROT_ALL) != UC_ERR_OK) {
        lastErr_ = "shadow IAT map edilemedi";
        return false;
    }
    // her stub: 0xC3 (ret) — kod hook'u shadow bölgesine girişte shim'i çağırır
    u8 ret = 0xC3;
    for (auto& s : mapRep_->shadowApis)
        uc_mem_write(uc_, s.stubVa, &ret, 1);
    return true;
}

bool Emulator::SetupStackAndPeb() {
    // stack
    u64 stackBase = cfg_.stackTop - cfg_.stackSize;
    if (uc_mem_map(uc_, stackBase, cfg_.stackSize, UC_PROT_ALL) != UC_ERR_OK) {
        lastErr_ = "stack map edilemedi";
        return false;
    }
    // sahte dönüş adresi: özel "emülsiyon sonu" sayfası
    u64 magicPage = cfg_.stackTop + 0x10000; // stack üstünde ayrı sayfa
    uc_mem_map(uc_, magicPage, 0x1000, UC_PROT_ALL);
    finishedMagic_ = magicPage;
    u64 sp = cfg_.stackTop - 0x100;
    u64 magicRet = magicPage;
    uc_mem_write(uc_, sp, (u8*)&magicRet, 8);
    // v8 DÜZELTME: x86-32'de yazmaç ESP'dir — RSP kimliği yazmak 32-bit
    // modda işaretçiyi bozuyordu (push'lar unmapped'e düşüyordu)
    if (arch_ == Arch::X86_64)
        uc_reg_write(uc_, UC_X86_REG_RSP, &sp);
    else {
        u32 sp32 = (u32)sp;
        uc_reg_write(uc_, UC_X86_REG_ESP, &sp32);
    }
    // PEB-lite + TEB-lite: gs:[0] = TEB, TEB+0x60 = PEB
    u64 tebVa = magicPage + 0x2000;
    uc_mem_map(uc_, tebVa & ~0xFFFull, 0x2000, UC_PROT_ALL);
    u64 teb = tebVa & ~0xFFFull;
    u64 peb = teb + 0x1000;
    u64 stackBaseUser = stackBase, stackLimitUser = cfg_.stackTop;
    // TEB: [0]=Self, [8]=ProcessEnvironmentBlock, [0x30]=PEB (fs/gs göreli)
    uc_mem_write(uc_, teb + 0x00, (u8*)&teb, 8);
    uc_mem_write(uc_, teb + 0x08, (u8*)&peb, 8);
    uc_mem_write(uc_, teb + 0x30, (u8*)&peb, 8);
    // TEB+0x10..: stack bilgileri (bazı runtime'lar okur)
    uc_mem_write(uc_, teb + 0x10, (u8*)&stackBaseUser, 8);
    uc_mem_write(uc_, teb + 0x18, (u8*)&stackLimitUser, 8);
    // PEB: [2]=BeingDebugged, [0x10]=ProcessParameters (boş)
    u8 pebBuf[0x100] = {};
    pebBuf[2] = 0;
    uc_mem_write(uc_, peb, pebBuf, sizeof(pebBuf));

    // GS base = TEB (x64). FS base = TEB (x86) — Unicorn'da MSR yazımı
    tebVa_ = teb;
    pebVa_ = peb;
    if (arch_ == Arch::X86_64) {
        uc_x86_msr msr;
        msr.rid = 0xC0000101; // MSR_GS_BASE
        msr.value = teb;
        uc_reg_write(uc_, UC_X86_REG_MSR, &msr);
    } else {
        uc_x86_msr msr;
        msr.rid = 0xC0000100; // MSR_FS_BASE
        msr.value = teb;
        uc_reg_write(uc_, UC_X86_REG_MSR, &msr);
    }
    return true;
}

// ----------------------------------------------------------------------------
// Hook'lar
// ----------------------------------------------------------------------------
void Emulator::HookCode(uc_engine* uc, uint64_t address, uint32_t size, void* ud) {
    Emulator* self = (Emulator*)ud;

    // 0) v9.2: DINAMİK stub (GetProcAddress yoluyla) — shadow IAT ile aynı
    // mekanizma: args oku → shim → dönüş + stdcall temizliği
    if (!self->dynStubs_.empty() &&
        address >= Emulator::DYN_STUB_BASE && address < Emulator::DYN_STUB_BASE + Emulator::DYN_STUB_SIZE) {
        auto dit = self->dynStubs_.find(address);
        if (dit != self->dynStubs_.end()) {
            u64 args[4] = {};
            if (self->arch_ == Arch::X86_64) {
                int regs[4] = {UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9};
                for (int i = 0; i < 4; i++) uc_reg_read(uc, regs[i], &args[i]);
            } else {
                for (int i = 0; i < 4; i++) {
                    u32 v = 0; u64 esp = 0;
                    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
                    uc_mem_read(uc, esp + 4 + i * 4, (u8*)&v, 4);
                    args[i] = v;
                }
            }
            u64 rsp = 0, rax = 0;
            uc_reg_read(uc, self->arch_ == Arch::X86_64 ? UC_X86_REG_RSP : UC_X86_REG_ESP, &rsp);
            bool stop = false;
            u64 retAddr = 0;
            rax = self->api_.Handle(*self, dit->second.first, dit->second.second,
                                    args, rsp, retAddr, stop);
            if (self->arch_ == Arch::X86_64)
                uc_reg_write(uc, UC_X86_REG_RAX, &rax);
            else {
                u32 eax32 = (u32)rax;
                uc_reg_write(uc, UC_X86_REG_EAX, &eax32);
            }
            u32 cleanup = 0;
            if (self->arch_ != Arch::X86_64 && self->cfg_.strictStdcall) {
                std::string lf = ToLower(dit->second.second);
                u32 tbl = ApiShim::Win32StdcallBytes(lf);
                if (tbl != 0xFFFFFFFFu) cleanup = tbl;
                else self->api_.NoteStackCleanupUnknown();
            }
            if (retAddr) {
                if (self->arch_ == Arch::X86_64) {
                    u64 newRsp = rsp + 8;
                    uc_reg_write(uc, UC_X86_REG_RSP, &newRsp);
                    uc_reg_write(uc, UC_X86_REG_RIP, &retAddr);
                } else {
                    u32 ret32 = (u32)retAddr, esp32;
                    uc_reg_read(uc, UC_X86_REG_ESP, &esp32);
                    esp32 += 4 + cleanup;
                    uc_reg_write(uc, UC_X86_REG_ESP, &esp32);
                    uc_reg_write(uc, UC_X86_REG_EIP, &ret32);
                }
            }
            if (stop) {
                self->finished_ = true;
                uc_emu_stop(uc);
            }
            return;
        }
    }

    // 1) shadow API stub'ına mı düştük?
    if (address >= SHADOW_IAT_BASE && address < SHADOW_IAT_BASE + SHADOW_IAT_SIZE) {
        for (auto& s : self->mapRep_->shadowApis) {
            if (s.stubVa == address) {
                // argümanlar
                u64 args[4];
                if (self->arch_ == Arch::X86_64) {
                    int regs[4] = {UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9};
                    for (int i = 0; i < 4; i++) uc_reg_read(uc, regs[i], &args[i]);
                } else {
                    // x86 stdcall: [esp+4], [esp+8]...
                    for (int i = 0; i < 4; i++) {
                        // v9.2 DÜZELTME: esp SIFIRDAN başlatılmalı — unicorn ESP'nin
                        // yalnız 4 baytını yazar, üst 4 bayt çöp kalıyordu (v8 hatası:
                        // x86-32 IAT shim argümanları hep 0 okunuyordu)
                        u32 v = 0; u64 esp = 0;
                        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
                        uc_mem_read(uc, esp + 4 + i * 4, (u8*)&v, 4);
                        args[i] = v;
                    }
                }
                u64 rsp = 0, rax = 0;
                uc_reg_read(uc, self->arch_ == Arch::X86_64 ? UC_X86_REG_RSP : UC_X86_REG_ESP, &rsp);
                bool stop = false;
                u64 retAddr = 0;
                rax = self->api_.Handle(*self, s.dllName, s.funcName, args, rsp, retAddr, stop);
                // v9.2 DÜZELTME: x86-32 modunda UC_X86_REG_RAX yazımı SESSİZCE
                // işe yaramıyor (unicorn 32-bit yalnız 32-bit reg kimliklerini
                // kabul eder) — API dönüş değeri v8'den beri x86-32'de hiç
                // yayılmıyordu. EAX'e yaz.
                if (self->arch_ == Arch::X86_64)
                    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
                else {
                    u32 eax32 = (u32)rax;
                    uc_reg_write(uc, UC_X86_REG_EAX, &eax32);
                }
                // stdcall'da çağrılan fonksiyon argümanları yığından çeker;
                // emülasyonda bunu bilmediğimiz için dönüşü normal ret ile yapıyoruz
                // (argüman temizlemesi: kaç bayt sökeceğimizi bilmiyoruz -> cdecl varsay)
                //
                // v9.2 (WinInit strictStdcall): x86-32'de Win32 API'leri stdcall'dır
                // — çağrılan argümanları kendisi söker. Temizlik baytı: (1) Win32
                // tablo, (2) dönüş adresinde "add esp,N" varsa cdecl=0, (3) bilinmiyor
                // → 0 + sayaç (WinInit raporunda görünür — sessiz yanlış YOK).
                u32 cleanup = 0;
                if (self->arch_ != Arch::X86_64 && self->cfg_.strictStdcall) {
                    std::string lf = ToLower(s.funcName);
                    u32 tbl = ApiShim::Win32StdcallBytes(lf);
                    if (tbl != 0xFFFFFFFFu) {
                        cleanup = tbl;
                    } else {
                        u8 pb[3] = {};
                        bool probe = retAddr && uc_mem_read(uc, retAddr, pb, 3) == UC_ERR_OK;
                        bool addEsp = probe && ((pb[0] == 0x83 && pb[1] == 0xC4) ||
                                                (pb[0] == 0x81 && pb[1] == 0xC4));
                        if (!addEsp)
                            self->api_.NoteStackCleanupUnknown();
                    }
                }
                if (retAddr) {
                    if (self->arch_ == Arch::X86_64) {
                        u64 newRsp = rsp + 8;
                        uc_reg_write(uc, UC_X86_REG_RSP, &newRsp);
                        uc_reg_write(uc, UC_X86_REG_RIP, &retAddr);
                    } else {
                        u32 ret32 = (u32)retAddr, esp32;
                        uc_reg_read(uc, UC_X86_REG_ESP, &esp32);
                        esp32 += 4 + cleanup;
                        uc_reg_write(uc, UC_X86_REG_ESP, &esp32);
                        uc_reg_write(uc, UC_X86_REG_EIP, &ret32);
                    }
                }
                if (stop) {
                    self->finished_ = true;
                    uc_emu_stop(uc);
                }
                return;
            }
        }
        // stub bulunamadı (bilinmeyen shadow adresi): ret gibi davran
        // v8 DÜZELTME: x86-32'de dönüş adresi 4 bayttır (önceden hep 8 okunup
        // rsp+=8 yapılıyordu — 32-bit yığını bozuyordu)
        {
            u64 rsp = 0, retAddr = 0;
            if (self->arch_ == Arch::X86_64) {
                uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
                uc_mem_read(uc, rsp, (u8*)&retAddr, 8);
                rsp += 8;
                uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
            } else {
                u32 esp = 0, ret32 = 0;
                uc_reg_read(uc, UC_X86_REG_ESP, &esp);
                uc_mem_read(uc, esp, (u8*)&ret32, 4);
                esp += 4;
                uc_reg_write(uc, UC_X86_REG_ESP, &esp);
                retAddr = ret32;
            }
            uc_reg_write(uc, UC_X86_REG_RIP, &retAddr);
        }
        return;
    }

    // 2) magic sayfasına düştük: ana akış bitti
    if (self->finishedMagic_ && address == self->finishedMagic_) {
        self->finished_ = true;
        uc_emu_stop(uc);
        return;
    }

    // 3) instruction trace / v8: yalnız-sayaç modu
    if (self->cfg_.insCountOnly) {
        self->executed_++;
        return;
    }
    if (self->cfg_.traceEnabled && self->trace_.size() < self->cfg_.traceLimit) {
        TraceEntry t;
        t.addr = address;
        if (self->cs_) {
            u8 buf[16] = {};
            uc_mem_read(uc, address, buf, size > 16 ? 16 : size);
            cs_insn* ins = nullptr;
            if (cs_disasm(self->cs_, buf, size > 16 ? 16 : size, address, 1, &ins)) {
                t.text = std::string(ins[0].mnemonic) + " " + ins[0].op_str;
                cs_free(ins, 1);
            }
        }
        if (self->arch_ == Arch::X86_64)
            uc_reg_read(uc, UC_X86_REG_RSP, &t.rsp);
        else {
            u32 esp = 0;
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            t.rsp = esp;
        }
        self->trace_.push_back(std::move(t));
    }
}

void Emulator::HookMemInvalid(uc_engine* uc, uc_mem_type type, uint64_t address,
                              int size, int64_t value, void* ud) {
    Emulator* self = (Emulator*)ud;
    MemAccess m;
    m.addr = address; m.size = (u64)size; m.value = (u64)value;
    // v9.2 DÜZELTME: UNMAPPED varyantları da doğru sınıfla (önceden
    // UC_MEM_WRITE_UNMAPPED "OKUMA" basıyordu)
    m.write = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED);
    m.invalid = true;
    self->faults_.push_back(m);
    if (!self->cfg_.quiet)
        LogErr("ERISIM IHMALI: %s 0x%llx (%d bayt) @ rip=0x%llx",
               m.write ? "YAZMA" : (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED)
                        ? "OKUMA" : "CALISTIRMA",
               (unsigned long long)address, size, (unsigned long long)self->CurrentPc());
    uc_emu_stop(uc);
    // işlemi durduruldu (uc_emu_stop çağrıldı)
}

void Emulator::HookMemAccess(uc_engine* uc, uc_mem_type type, uint64_t address,
                             int size, int64_t value, void* ud) {
    (void)uc;
    Emulator* self = (Emulator*)ud;
    if (self->memLog_.size() < 65536) {
        MemAccess m;
        m.addr = address; m.size = (u64)size; m.value = (u64)value;
        m.write = (type == UC_MEM_WRITE);
        self->memLog_.push_back(m);
    }
}

// ----------------------------------------------------------------------------
// Çalıştırma
// ----------------------------------------------------------------------------
bool Emulator::Run(u64 startVa, u64 untilVa, u64 timeoutUs, size_t maxIns) {
    if (!uc_) return false;
    startVa_ = startVa;
    finished_ = false;
    // dönüş sihirbazı: ana akışın ret'i magic sayfaya düşer
    u64 magicRet = finishedMagic_;
    u64 sp = cfg_.stackTop - 0x100;
    uc_mem_write(uc_, sp, (u8*)&magicRet, 8);
    if (arch_ == Arch::X86_64)
        uc_reg_write(uc_, UC_X86_REG_RSP, &sp);
    else {
        u32 sp32 = (u32)sp;   // v8: x86-32'de ESP yaz (RSP kimliği bozuyordu)
        uc_reg_write(uc_, UC_X86_REG_ESP, &sp32);
    }

    uc_err err = uc_emu_start(uc_, startVa, untilVa, timeoutUs, maxIns);
    if (err != UC_ERR_OK && !finished_) {
        lastErr_ = std::string(uc_strerror(err));
        if (!cfg_.quiet)
            LogWarn("Emulasyon durdu: %s (rip=0x%llx)", lastErr_.c_str(),
                    (unsigned long long)CurrentPc());
        return false;
    }
    return true;
}

// v9.2 (WinInit): argümanlı giriş — DllMain(hInst,reason,res) / TLS callback
// (dllHandle,reason,res) düzenleri. x86: [sp]=ret, [sp+4..]=args;
// x64: ilk 4 arg kayıtlarda, 5.+ [sp+8]..
bool Emulator::RunWithArgs(u64 startVa, const std::vector<u64>& args,
                           u64 timeoutUs, size_t maxIns) {
    if (!uc_) return false;
    startVa_ = startVa;
    finished_ = false;
    const bool is64 = (arch_ == Arch::X86_64);
    const u64 ps = is64 ? 8 : 4;
    u64 sp = cfg_.stackTop - 0x100;
    u64 magicRet = finishedMagic_;
    uc_mem_write(uc_, sp, (u8*)&magicRet, ps);        // [sp] = sihirli dönüş
    if (is64) {
        int regs[4] = {UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9};
        for (size_t i = 0; i < args.size() && i < 4; i++) {
            u64 v = args[i];
            uc_reg_write(uc_, regs[i], &v);
        }
        for (size_t i = 4; i < args.size(); i++) {
            u64 v = args[i];
            uc_mem_write(uc_, sp + 8 + (i - 4) * 8, (u8*)&v, 8);
        }
        u64 rsp = sp;
        uc_reg_write(uc_, UC_X86_REG_RSP, &rsp);
    } else {
        for (size_t i = 0; i < args.size(); i++) {
            u32 v = (u32)args[i];
            uc_mem_write(uc_, sp + 4 + i * 4, (u8*)&v, 4);
        }
        u32 sp32 = (u32)sp;
        uc_reg_write(uc_, UC_X86_REG_ESP, &sp32);
    }
    uc_err err = uc_emu_start(uc_, startVa, 0, timeoutUs, maxIns);
    if (err != UC_ERR_OK && !finished_) {
        lastErr_ = std::string(uc_strerror(err));
        if (!cfg_.quiet)
            LogWarn("Emulasyon durdu: %s (rip=0x%llx)", lastErr_.c_str(),
                    (unsigned long long)CurrentPc());
        return false;
    }
    return true;
}

bool Emulator::Step(size_t n) {
    if (!uc_ || finished_) return false;
    u64 pc = CurrentPc();
    uc_err err = uc_emu_start(uc_, pc, 0, 0, n);
    if (err != UC_ERR_OK && !finished_) {
        lastErr_ = uc_strerror(err);
        return false;
    }
    return true;
}

void Emulator::Stop() { if (uc_) uc_emu_stop(uc_); }

u64 Emulator::CurrentPc() const {
    u64 pc = 0;
    if (!uc_) return 0;
    uc_reg_read(uc_, arch_ == Arch::X86_64 ? UC_X86_REG_RIP : UC_X86_REG_EIP, &pc);
    return pc;
}

u64 Emulator::GetReg(int ucReg) const {
    u64 v = 0;
    if (uc_) uc_reg_read(uc_, ucReg, &v);
    return v;
}

void Emulator::SetReg(int ucReg, u64 v) {
    if (uc_) uc_reg_write(uc_, ucReg, &v);
}

Emulator::RegDump Emulator::DumpRegs() const {
    RegDump r = {};
    if (!uc_) return r;
    int regs[] = {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                  UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
                  UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                  UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
                  UC_X86_REG_RIP, UC_X86_REG_EFLAGS};
    u64* out[] = {&r.rax, &r.rbx, &r.rcx, &r.rdx, &r.rsi, &r.rdi, &r.rbp, &r.rsp,
                  &r.r8, &r.r9, &r.r10, &r.r11, &r.r12, &r.r13, &r.r14, &r.r15,
                  &r.rip, &r.eflags};
    for (int i = 0; i < 18; i++) uc_reg_read(uc_, regs[i], out[i]);
    return r;
}

void Emulator::PrintRegs(const RegDump& r) {
    Log("  rax=%016llx rbx=%016llx rcx=%016llx\n", r.rax, r.rbx, r.rcx);
    Log("  rdx=%016llx rsi=%016llx rdi=%016llx\n", r.rdx, r.rsi, r.rdi);
    Log("  rbp=%016llx rsp=%016llx rip=%016llx\n", r.rbp, r.rsp, r.rip);
    Log("  r8 =%016llx r9 =%016llx r10=%016llx\n", r.r8, r.r9, r.r10);
    Log("  r11=%016llx r12=%016llx r13=%016llx\n", r.r11, r.r12, r.r13);
    Log("  r14=%016llx r15=%016llx efl=%08llx\n", r.r14, r.r15, r.eflags);
}

bool Emulator::ReadMem(u64 va, u8* out, size_t n) const {
    return uc_ && uc_mem_read(uc_, va, out, n) == UC_ERR_OK;
}

bool Emulator::WriteMem(u64 va, const u8* p, size_t n) {
    return uc_ && uc_mem_write(uc_, va, p, n) == UC_ERR_OK;
}

// v9.2 (WinInit): GetProcAddress için çağrılabilir dinamik stub.
// Statik UCRT, CRT-init'te API'leri GetProcAddress ile bulup doğrudan
// ÇAĞIRIR (ör. InitializeCriticalSectionEx) — dönen adres stub bölgesinde
// olur, HookCode yakalar, shim gerçek davranışı uygular.
u64 Emulator::MakeDynApiStub(const std::string& dll, const std::string& func) {
    if (!uc_) return 0;
    // aynı isim için önceden üretilmiş stub'ı kullan
    for (auto& [va, name] : dynStubs_)
        if (name.second == func && name.first == dll) return va;
    if (dynStubCursor_ + 16 > DYN_STUB_BASE + DYN_STUB_SIZE) return 0;
    u64 stub = dynStubCursor_;
    dynStubCursor_ += 16;
    u8 ret = 0xC3;
    uc_mem_write(uc_, stub, &ret, 1);
    dynStubs_[stub] = { dll, func };
    return stub;
}

u64 Emulator::AllocHeap(size_t size) {
    // 16 bayt hizalı basit bump allocator
    u64 va = (heapCursor_ + 15) & ~0xFull;
    u64 next = va + ((size + 15) & ~0xFull);
    if (next > cfg_.heapBase + cfg_.heapSize) return 0;
    heapCursor_ = next;
    return va;
}

bool Emulator::MapRegion(u64 base, size_t size) {
    if (!uc_) return false;
    u64 b = base & ~0xFFFull;
    u64 e = (base + size + 0xFFF) & ~0xFFFull;
    if (uc_mem_map(uc_, b, e - b, UC_PROT_ALL) != UC_ERR_OK) {
        lastErr_ = "bolge map edilemedi";
        return false;
    }
    return true;
}

} // namespace gt
