// ============================================================================
//  i4M GodTier Engine — decomp/devirtemu.cpp
//  DEVRİT TIER-3: Unicorn tohumlu pencere emülasyonu ("livestep god mod").
//
//  Akış (TryCall):
//    1. Çağrının temel bloğunu bul (dallar ARASINDA düz çizgi — semantik
//       yol-bağımsız, bu yüzden SOUNDDUR)
//    2. Önceki denemenin kirli belleğini geri al (imajdan)
//    3. Statik-kanıt tohumlarını yaz: [S]=&sentetik, [sentetik+K]=vftable
//    4. Yazmaçları sıfırla, ebp'yi yığın çerçevesine bağla
//    5. Unicorn: blok başından çağrı noktasına DEK gerçek x86 yürütme
//    6. rip == çağrı adresi ise operandı çöz: yazmaç / [reg+disp] / [imm]
//    7. Hedefi doğrula: kod bölümünde mi + (vftable biliniyorsa RTTI atlasi
//       ile çapraz kontrol)
// ============================================================================
#include "decomp/devirtemu.h"
#include "decomp/devirtpro.h"
#include "emulate/emulator.h"
#include "core/log.h"
#include <unicorn/unicorn.h>
#include <algorithm>
#include <cstring>
#include <sstream>

namespace gt {
namespace {

// sentetik nesne bölgesi (imaj/yığın/heap/shadow-IAT ile çakışmaz)
const u64 kSynthBase = 0x60000000ull;
const u64 kSynthSize = 0x00100000ull;   // 1 MB

// ---- basit operand yardımcıları (capstone opStr formatı) ----
std::vector<std::string> SplitTop(const std::string& s) {
    std::vector<std::string> out;
    int depth = 0;
    std::string cur;
    for (char c : s) {
        if (c == '[' || c == '(') depth++;
        else if (c == ']' || c == ')') depth--;
        if (c == ',' && depth == 0) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    for (auto& o : out) {
        size_t a = o.find_first_not_of(" \t");
        size_t b = o.find_last_not_of(" \t");
        o = (a == std::string::npos) ? "" : o.substr(a, b - a + 1);
    }
    return out;
}

// yazmaç adı -> unicorn kimliği (kanonik aile: "eax"->EAX, "rax"->RAX, r8d..)
int UcRegOf(const std::string& r, bool is64) {
    struct Ent { const char* n; int id32, id64; };
    static const Ent kEnts[] = {
        {"rax", UC_X86_REG_EAX, UC_X86_REG_RAX}, {"rcx", UC_X86_REG_ECX, UC_X86_REG_RCX},
        {"rdx", UC_X86_REG_EDX, UC_X86_REG_RDX}, {"rbx", UC_X86_REG_EBX, UC_X86_REG_RBX},
        {"rsp", UC_X86_REG_ESP, UC_X86_REG_RSP}, {"rbp", UC_X86_REG_EBP, UC_X86_REG_RBP},
        {"rsi", UC_X86_REG_ESI, UC_X86_REG_RSI}, {"rdi", UC_X86_REG_EDI, UC_X86_REG_RDI},
        {"r8",  UC_X86_REG_R8D, UC_X86_REG_R8},  {"r9",  UC_X86_REG_R9D, UC_X86_REG_R9},
        {"r10", UC_X86_REG_R10D, UC_X86_REG_R10},{"r11", UC_X86_REG_R11D, UC_X86_REG_R11},
        {"r12", UC_X86_REG_R12D, UC_X86_REG_R12},{"r13", UC_X86_REG_R13D, UC_X86_REG_R13},
        {"r14", UC_X86_REG_R14D, UC_X86_REG_R14},{"r15", UC_X86_REG_R15D, UC_X86_REG_R15},
        // 32-bit girdi adları (capstone x86-32 "eax" yazar)
        {"eax", UC_X86_REG_EAX, UC_X86_REG_RAX}, {"ecx", UC_X86_REG_ECX, UC_X86_REG_RCX},
        {"edx", UC_X86_REG_EDX, UC_X86_REG_RDX}, {"ebx", UC_X86_REG_EBX, UC_X86_REG_RBX},
        {"esp", UC_X86_REG_ESP, UC_X86_REG_RSP}, {"ebp", UC_X86_REG_EBP, UC_X86_REG_RBP},
        {"esi", UC_X86_REG_ESI, UC_X86_REG_RSI}, {"edi", UC_X86_REG_EDI, UC_X86_REG_RDI},
    };
    for (auto& e : kEnts)
        if (r == e.n) return is64 ? e.id64 : e.id32;
    return -1;
}

bool IsRegName(const std::string& t) { return UcRegOf(t, true) >= 0; }

} // namespace

// ----------------------------------------------------------------------------
// kurucu/sonlandırıcı — tam tipler (Emulator) bu TU'da
// ----------------------------------------------------------------------------
DevirtEmu::DevirtEmu(Analyzer& az, DevirtPro& dp, const MsvcRtti& rtti)
    : az_(az), dp_(dp), rtti_(rtti) {}

DevirtEmu::~DevirtEmu() = default;

// ----------------------------------------------------------------------------
// kurulum
// ----------------------------------------------------------------------------
void DevirtEmu::BuildStaticIndex() {
    synthOf_.clear();
    staticSlots_.clear();
    u64 next = kSynthBase;
    u64 ps = az_.Bin().Is64() ? 8 : 4;
    for (u64 s : dp_.AllStaticVas()) {
        if (next + 0x400 > kSynthBase + kSynthSize) break;   // bütçe dolu
        synthOf_[s] = next;
        staticSlots_.insert(s);
        next += 0x400;
        (void)ps;
    }
    thisSynth_ = next;          // this-tohumu en sonda (statiklerle çakışmaz)
}

bool DevirtEmu::EnsureSetup() {
    if (tried_) return ok_;
    tried_ = true;
    ok_ = false;
    // yalnız x86 (32/64) — emulator Unicorn x86
    Arch arch = az_.Bin().GetArch();
    if (arch != Arch::X86_32 && arch != Arch::X86_64) return false;
    is64_ = az_.Bin().Is64();

    BuildStaticIndex();

    EmuConfig cfg;
    cfg.traceEnabled = false;
    cfg.insCountOnly = true;      // komut metni YOK — sadece sayaç (toplu hız)
    cfg.quiet = true;             // toplu modda erişim ihlalleri konsolu boşamaz
    cfg.apiCallLimit = 64;
    if (!is64_) {
        // x86-32: 4GB altı klasik adresler (ESP 0x7FF000000000'u tutamaz!)
        cfg.stackTop = 0x7FF00000ull;
        cfg.heapBase = 0x52000000ull;
        cfg.heapSize = 0x00400000ull;
    }
    emu_ = std::make_unique<Emulator>();
    if (!emu_->Setup(az_.Bin(), az_.Image(), mapRep_, arch, cfg)) {
        emu_.reset();
        return false;
    }
    if (!emu_->MapRegion(kSynthBase, kSynthSize)) {
        emu_.reset();
        return false;
    }
    ok_ = true;
    return true;
}

bool DevirtEmu::Available() { return EnsureSetup(); }

u64 DevirtEmu::StaticSynthAddr(u64 staticVa) {
    auto it = synthOf_.find(staticVa);
    return it == synthOf_.end() ? 0 : it->second;
}

// ----------------------------------------------------------------------------
// pencere: çağrının temel bloğu (dallar arası düz çizgi — sound)
// ----------------------------------------------------------------------------
u64 DevirtEmu::WindowStart(const std::vector<Ins>& ins, size_t callIdx) {
    std::set<u64> targets;
    for (auto& i : ins)
        if (i.isJcc || i.isJmp) targets.insert(i.target);
    size_t head = callIdx;
    const size_t maxBack = 64;
    while (head > 0 && (callIdx - head) < maxBack) {
        const Ins& prev = ins[head - 1];
        if (prev.isJcc || prev.isJmp || prev.isRet) break;   // blok sınırı
        if (targets.count(ins[head].addr)) break;             // head zaten etiket
        head--;
    }
    return ins[head].addr;
}

// ----------------------------------------------------------------------------
// tohumlar + kirli bellek geri alma
// ----------------------------------------------------------------------------
void DevirtEmu::ApplySeeds(const SeedChoice& sc) {
    const u64 ps = is64_ ? 8 : 4;
    for (auto& [sva, offs] : sc.staticSeeds) {
        u64 obj = StaticSynthAddr(sva);
        if (!obj) continue;
        u64 v = obj;
        emu_->WriteMem(sva, (u8*)&v, ps);          // [S] = &sentetikNesne
        for (auto& [off, vft] : offs) {
            u64 fv = vft;
            emu_->WriteMem(obj + (u64)off, (u8*)&fv, ps);
        }
    }
    if (sc.useThis) {
        u64 tv = sc.thisVft;
        emu_->WriteMem(thisSynth_ + (u64)sc.thisOff, (u8*)&tv, ps);
    }
}

void DevirtEmu::RestoreDirty() {
    if (!emu_) return;
    // imaj içindeki yazımları orijinal baytlarla geri al; sentetik bölge
    // yazımlarını sıfırla (tohumlar her pass'te yeniden yazılır)
    const u64 ib = az_.Image().Base();
    const u64 ie = ib + az_.Image().Size();
    u8 zero[64] = {};
    for (auto& m : emu_->MemLog()) {
        if (!m.write) continue;
        u64 a = m.addr, e = m.addr + m.size;
        if (a >= ib && a < ie) {
            u8 buf[64];
            size_t n = (size_t)std::min<u64>(e - a, 64);
            if (az_.Image().ReadBytes(a, buf, n))
                emu_->WriteMem(a, buf, n);
        } else if (a >= kSynthBase && a < kSynthBase + kSynthSize) {
            size_t n = (size_t)std::min<u64>(e - a, 64);
            emu_->WriteMem(a, zero, n);
        }
    }
    emu_->ClearMemLog();
}

void DevirtEmu::ZeroRegs() {
    static const char* kRegs64[] = {"rax","rcx","rdx","rbx","rbp","rsi","rdi",
                                    "r8","r9","r10","r11","r12","r13","r14","r15"};
    for (auto* r : kRegs64) {
        if (!is64_ && r[0] == 'r' && isdigit((unsigned char)r[1]))
            continue;   // x86-32: r8-r15 yok (unicorn uyarisi verir)
        emu_->SetReg(UcRegOf(r, is64_), 0);
    }
}

u64 DevirtEmu::ReadRegByName(const std::string& reg) {
    int id = UcRegOf(reg, is64_);
    if (id < 0) return 0;
    return emu_->GetReg(id);
}

bool DevirtEmu::ReadPtr(u64 va, u64* out) {
    if (!out) return false;
    const u64 ps = is64_ ? 8 : 4;
    *out = 0;
    return emu_->ReadMem(va, (u8*)out, ps);
}

bool DevirtEmu::IsExecVa(u64 va) const {
    for (auto& s : az_.Bin().Sections())
        if (s.executable && va >= s.va && va < s.va + std::max(s.vsize, s.rawSize))
            return true;
    return false;
}

std::string DevirtEmu::ImportAt(u64 iatVa) {
    if (importByIat_.empty()) {
        for (auto& d : az_.Bin().Imports())
            for (auto& f : d.funcs)
                if (f.iatVa) {
                    std::string nm = f.name.empty()
                        ? ("#" + std::to_string(f.ordinal)) : f.name;
                    importByIat_[f.iatVa] = d.name + "." + nm;
                }
    }
    auto it = importByIat_.find(iatVa);
    return it == importByIat_.end() ? "" : it->second;
}

// ----------------------------------------------------------------------------
// ana giriş: tek pencere denemesi
// ----------------------------------------------------------------------------
DevirtEmu::Attempt DevirtEmu::TryCall(u64 callAddr, const SeedChoice& sc,
                                      std::vector<std::string>* trace) {
    Attempt at;
    if (!EnsureSetup()) { at.why = "emulator kurulamadi (x86 degil / map yok)"; return at; }

    const FuncInfo* f = az_.FunctionAt(callAddr);
    if (!f) { at.why = "cagri bir fonksiyonun icinde degil"; return at; }
    auto* ins = az_.InstructionsOf(f->start);
    if (!ins) { at.why = "fonksiyon komutlari cozumlenmemis"; return at; }
    size_t ci = ins->size();
    for (size_t i = 0; i < ins->size(); i++)
        if ((*ins)[i].addr == callAddr) { ci = i; break; }
    if (ci == ins->size()) { at.why = "cagri komut listede degil"; return at; }
    if (!(*ins)[ci].isCall || !(*ins)[ci].isIndirect) {
        at.why = "dolayli cagri degil"; return at;
    }

    // 1) pencere
    u64 winStart = WindowStart(*ins, ci);
    // 2-3) temizlik + tohumlar
    RestoreDirty();
    ApplySeeds(sc);
    // 4) yazmaçlar
    ZeroRegs();
    u64 frame = emu_->Config().stackTop - 0x800;
    emu_->SetReg(UcRegOf(is64_ ? "rbp" : "ebp", is64_), frame);
    if (sc.useThis) {
        u64 thisv = thisSynth_ + (u64)sc.thisOff;
        emu_->SetReg(UcRegOf(is64_ ? "rcx" : "ecx", is64_), thisv);
        if (az_.Bin().FormatName().find("ELF") != std::string::npos)
            emu_->SetReg(UcRegOf("rdi", true), thisv);   // SysV this
    }
    if (trace) {
        char b[160];
        snprintf(b, sizeof b, "tier-3 unicorn: pencere 0x%llx..0x%llx (%zu komut)",
                 (unsigned long long)winStart, (unsigned long long)callAddr,
                 ci - (size_t)(winStart - f->start) + 1);
        trace->push_back(b);
        for (auto& [sva, offs] : sc.staticSeeds) {
            if (offs.empty()) continue;
            snprintf(b, sizeof b, "  tohum: [0x%llx] = &sentetik0x%llx",
                     (unsigned long long)sva,
                     (unsigned long long)StaticSynthAddr(sva));
            trace->push_back(b);
            for (auto& [off, vft] : offs) {
                const RttiClass* rc = rtti_.ByVftable(vft);
                snprintf(b, sizeof b, "  tohum: [sentetik+0x%llx] = vftable 0x%llx (%s)",
                         (unsigned long long)off, (unsigned long long)vft,
                         rc ? rc->name.c_str() : "?");
                trace->push_back(b);
            }
        }
        if (sc.useThis) {
            const RttiClass* rc = rtti_.ByVftable(sc.thisVft);
            snprintf(b, sizeof b, "  tohum: this = sentetik+0x%llx, [this] = 0x%llx (%s)",
                     (unsigned long long)sc.thisOff,
                     (unsigned long long)sc.thisVft,
                     rc ? rc->name.c_str() : "?");
            trace->push_back(b);
        }
    }

    // 5) emülasyon: blok başından çağrıya (çağrı YÜRÜTÜLMEZ — rip'te durur)
    emu_->ResetExecuted();
    emu_->Run(winStart, callAddr, 60000 /*us*/, 20000 /*ins*/);
    at.executed = emu_->Executed();

    // dokunulan statikler (bu pass'in okuma kayıtları)
    for (auto& m : emu_->MemLog())
        if (!m.write && staticSlots_.count(m.addr))
            at.touchedStatics.insert(m.addr);

    if (emu_->CurrentPc() != callAddr) {
        at.why = "pencere cagriya ulasamadi (hata/yol)";
        if (trace) trace->push_back(std::string("  ulasilamadi: rip=0x") +
                                    ((std::ostringstream{} << std::hex
                                     << emu_->CurrentPc())).str());
        RestoreDirty();
        return at;
    }
    at.reached = true;
    if (trace) {
        char b[96];
        snprintf(b, sizeof b, "  ulasildi: rip=cagri, %zu komut yurutuldu",
                 at.executed);
        trace->push_back(b);
    }

    // 6) operandı çöz
    auto ops = SplitTop((*ins)[ci].opStr);
    if (ops.empty()) { at.why = "operand yok"; RestoreDirty(); return at; }
    const std::string& op0 = ops[0];
    if (IsRegName(op0)) {
        u64 v = ReadRegByName(op0);
        if (trace) {
            char b[96];
            snprintf(b, sizeof b, "  %s = 0x%llx", op0.c_str(),
                     (unsigned long long)v);
            trace->push_back(b);
        }
        if (v && IsExecVa(v)) at.target = v;
        else at.why = "yazmac kod adresi tasiyor degil";
        // v8: "call reg" — reg bir vtable SLOT değeri taşır (mov reg,[vft+K]
        // deseni). Kanıt için: çağrı anındaki DİĞER yazmaçlarda vftable ara
        // (zincirde vft tabanı genelde hâlâ bir yazmaçta durur), sonra
        // hedefin vftable içindeki ofsetini doğrula.
        if (v && IsExecVa(v) && rtti_.ByVftable(v) == nullptr) {
            static const char* kScan[] = {"eax","ecx","edx","ebx","esi","edi",
                                          "rax","rcx","rdx","rbx","rsi","rdi"};
            const u64 ps = is64_ ? 8 : 4;
            for (auto* rn : kScan) {
                u64 rv = ReadRegByName(rn);
                if (!rv || rtti_.ByVftable(rv) == nullptr) continue;
                for (u64 off = 0; off < 0x400; off += ps) {
                    u64 t = 0;
                    if (ReadPtr(rv + off, &t) && t == v) {
                        at.vftVa = rv;
                        at.slotOff = (i64)off;
                        break;
                    }
                }
                if (at.vftVa) break;
            }
        }
    } else if (op0.find('[') != std::string::npos) {
        // "dword ptr [edx + 0x88]" / "[0x402000]"
        size_t lb = op0.find('[');
        size_t rb = op0.rfind(']');
        std::string inner = op0.substr(lb + 1, rb - lb - 1);
        std::string base;
        i64 disp = 0;
        bool neg = false;
        std::string tok;
        auto flush = [&]() {
            if (tok.empty()) return;
            if (IsRegName(tok)) base = tok;
            else {
                i64 v = (i64)strtoull(tok.c_str(), nullptr, 0);
                disp += neg ? -v : v;
            }
            tok.clear();
        };
        for (char c : inner) {
            if (c == '+') { flush(); neg = false; }
            else if (c == '-') { flush(); neg = true; }
            else if (c == ' ' || c == '\t') { flush(); }
            else tok += c;
        }
        flush();
        if (base.empty()) {
            // mutlak bellek: IAT importu mu, imaj verisi mi?
            std::string imp = ImportAt((u64)disp);
            if (!imp.empty()) {
                at.isImport = true;
                at.importName = imp;
                if (trace) trace->push_back("  [0x" + ((std::ostringstream{}
                    << std::hex << disp)).str() + "] = IAT -> " + imp);
            } else {
                u64 t = 0;
                if (ReadPtr((u64)disp, &t) && IsExecVa(t)) at.target = t;
                else at.why = "mutlak yuva kod adresi tasiyor degil";
            }
        } else {
            u64 bv = ReadRegByName(base);
            at.vftVa = bv;
            at.slotOff = disp;
            u64 t = 0;
            if (trace) {
                char b[112];
                snprintf(b, sizeof b, "  %s = 0x%llx, [%s%+lld] okunuyor",
                         base.c_str(), (unsigned long long)bv,
                         base.c_str(), (long long)disp);
                trace->push_back(b);
            }
            if (bv && ReadPtr(bv + (u64)disp, &t)) {
                if (IsExecVa(t)) at.target = t;
                else at.why = "slot degeri kod adresi degil";
            } else at.why = "slot okunamadi (taban 0 / eslenmemis)";
        }
    } else {
        at.why = "bilinmeyen operand turu: " + op0;
    }

    // 7) RTTI çapraz doğrulaması (vftable biliniyorsa)
    if (at.target && at.vftVa) {
        const RttiClass* rc = rtti_.ByVftable(at.vftVa);
        if (rc) {
            u64 atlasT = rtti_.ResolveSlot(at.vftVa, (u32)at.slotOff, nullptr);
            if (atlasT && atlasT != at.target) {
                // emülasyon ile atlas çelişiyor — GÜVENİLMEZ, dürüst reddet
                at.why = "emulasyon/RTTI atlasi celisiyor — red";
                at.target = 0;
            } else if (atlasT == at.target && trace) {
                char b[128];
                snprintf(b, sizeof b,
                         "  dogrulama: RTTI atlasi uyumlu (%s vftable[%lld])",
                         rc->name.c_str(),
                         (long long)(at.slotOff / (is64_ ? 8 : 4)));
                trace->push_back(b);
            }
        }
    }
    RestoreDirty();
    return at;
}

} // namespace gt
