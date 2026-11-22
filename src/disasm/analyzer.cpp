// ============================================================================
//  i4M GodTier Engine — disasm/analyzer.cpp
// ============================================================================
#include "disasm/analyzer.h"
#include "core/log.h"
#include "core/util.h"
#include <algorithm>
#include <queue>

namespace gt {

// ----------------------------------------------------------------------------
// Fonksiyon keşfi
// ----------------------------------------------------------------------------
void Analyzer::DiscoverFunctions() {
    // goruntu tabani, binary tabanindan farkli olabilir (forceBase/reloc)
    const u64 bd = img_.Base() - bin_.ImageBase();
    // 1) Semboller (ELF symtab / PE export + COFF)
    for (auto& s : bin_.Symbols()) {
        u64 va = s.va + bd;
        if (s.isFunction && va >= img_.Base() && va < img_.Base() + img_.Size()) {
            funcs_[va] = FuncInfo{va, va, s.name, {}, true, 0};
        }
    }
    // 2) Entry point
    u64 ep = bin_.EntryPoint() + bd;
    if (ep && img_.InRange(ep) && !funcs_.count(ep))
        funcs_[ep] = FuncInfo{ep, ep, "entry_point", {}, false, 0};

    // 3) Import IAT haritası (sembol çözümü için)
    for (auto& dll : bin_.Imports())
        for (auto& fn : dll.funcs)
            importsByVa_[fn.iatVa + bd] = ToLower(dll.name) + "." + (fn.name.empty()
                                ? ("ord" + std::to_string(fn.ordinal)) : fn.name);

    // 4) Çağrı hedefleri: tüm çalışan bölgede linear sweep yapıp call'ları
    //    toplayacağız (recursive traversal başlangıç noktaları bunlar).
    std::set<u64> callTargets;
    for (auto& sec : bin_.Sections()) {
        if (!sec.executable || sec.rawSize < 8) continue;
        u64 va = sec.va + bd;   // goruntu tabanina gore kaydir
        u64 end = va + std::min<u64>(sec.vsize, sec.rawSize);
        u8 buf[32];
        u64 cur = va;
        while (cur < end) {
            if (!img_.ReadBytes(cur, buf, 32)) break;
            Ins x;
            if (!eng_.DisasmOne(buf, 32, cur, x)) { cur++; continue; }
            if (x.isCall && !x.isIndirect && x.target >= img_.Base() &&
                x.target < img_.Base() + img_.Size())
                callTargets.insert(x.target);
            cur += x.len ? x.len : 1;
        }
    }
    for (u64 t : callTargets)
        if (!funcs_.count(t))
            funcs_[t] = FuncInfo{t, t, "", {}, false, 0};

    // 5) PLT stub'larına gerçek isim ver (printf, memset ...) ve
    //    _start içindeki "lea rdi,[main]; call __libc_start_main" kalıbıyla
    //    strip edilmiş binary'lerde bile main'i bul.
    const u64 libcMainPlt = bin_.PltVaOf("__libc_start_main");
    u64 lastLeaRdiTarget = 0;    // son görülen "lea rdi, [rip+X]" hedefi
    for (auto& sec : bin_.Sections()) {
        if (!sec.executable || sec.rawSize < 8) continue;
        u64 va = sec.va + bd;
        u64 end = va + std::min<u64>(sec.vsize, sec.rawSize);
        u8 buf[32];
        u64 cur = va;
        while (cur < end) {
            if (!img_.ReadBytes(cur, buf, 32)) break;
            Ins x;
            if (!eng_.DisasmOne(buf, 32, cur, x)) { cur++; continue; }
            if (x.mnemonic == "lea" && x.opStr.rfind("rdi, [rip", 0) == 0 && x.memRef)
                lastLeaRdiTarget = x.memRef + bd;
            bool callsLibcMain =
                (x.isCall && x.isIndirect && x.memRef &&
                 bin_.GotName(x.memRef) == "__libc_start_main") ||
                (x.isCall && !x.isIndirect && x.target == libcMainPlt);
            if (callsLibcMain && lastLeaRdiTarget) {
                u64 mainVa = lastLeaRdiTarget;
                if (img_.InRange(mainVa)) {
                    auto it = funcs_.find(mainVa);
                    if (it == funcs_.end())
                        funcs_[mainVa] = FuncInfo{mainVa, mainVa, "main", {}, false, 0};
                    else if (it->second.name.empty() || it->second.name.rfind("sub_", 0) == 0)
                        it->second.name = "main";
                }
            }
            cur += x.len ? x.len : 1;
        }
    }

    // isimlendir: sub_XXXXXXXX / PLT import adı
    for (auto& [va, f] : funcs_) {
        if (f.name.empty()) {
            std::string plt = bin_.PltName(va - bd);
            f.name = !plt.empty() ? plt : ("sub_" + ToHex(va, 8));
        }
    }
}

// ----------------------------------------------------------------------------
// Tek fonksiyon analizi: komutları çıkar, xref'leri kaydet
// ----------------------------------------------------------------------------
void Analyzer::AnalyzeFunction(u64 start) {
    auto ins = DisassembleFunction(start);
    (void)ins;
}

// ----------------------------------------------------------------------------
// Doğrusal çözümleme: jump-table case blokları gibi dal hedefi olmayan
// aralıkların disassembly'si (flag'ler DisasmOne tarafından doldurulur)
// ----------------------------------------------------------------------------
std::vector<Ins> Analyzer::DisassembleLinear(u64 start, u64 endExclusive, size_t maxIns) {
    std::vector<Ins> out;
    u64 cur = start;
    while (out.size() < maxIns && cur < endExclusive && img_.InRange(cur)) {
        u8 buf[32];
        if (!img_.ReadBytes(cur, buf, 32)) break;
        Ins x;
        if (!eng_.DisasmOne(buf, 32, cur, x)) break;
        x.comment = SymbolOrLabel(x.target);
        out.push_back(x);
        cur += x.len ? x.len : 1;
        if (x.isJmp || x.isRet) break;   // basic block sonu
    }
    return out;
}

std::vector<Ins> Analyzer::DisassembleFunction(u64 start, size_t maxIns) {
    std::vector<Ins> out;
    if (!img_.InRange(start)) return out;

    // zaten çözülmüşse geri ver
    auto it = funcIns_.find(start);
    if (it != funcIns_.end()) return it->second;

    std::set<u64> visitedLocal;
    // (basit doğrusal akış + dal hedeflerine sıçrama — tam CFG decomp'ta kurulur)
    std::queue<u64> work;
    work.push(start);

    while (!work.empty() && out.size() < maxIns) {
        u64 cur = work.front(); work.pop();
        while (out.size() < maxIns) {
            if (!img_.InRange(cur)) break;
            if (visitedLocal.count(cur)) break;
            visitedLocal.insert(cur);

            u8 buf[32];
            if (!img_.ReadBytes(cur, buf, 32)) break;
            Ins x;
            if (!eng_.DisasmOne(buf, 32, cur, x)) break;
            // --- padding tespiti: ayni komutun tekrari (0x00 katari = add [rax],al) ---
            if (!out.empty()) {
                const Ins& prev = out.back();
                if (prev.mnemonic == x.mnemonic && prev.opStr == x.opStr) {
                    if (++sameRun_ >= 12) break;   // dolgu: fonksiyon bitti
                } else sameRun_ = 0;
                if (x.mnemonic == "int3" || (x.mnemonic == "nop" && x.opStr.empty()))
                    if (++padRun_ >= 6) break;
                else if (x.mnemonic != "nop") padRun_ = 0;
            }
            x.comment = SymbolOrLabel(x.target);
            out.push_back(x);

            // xref kayıtları
            if ((x.isCall || x.isJmp || x.isJcc) && !x.isIndirect)
                AddXref(cur, x.target, x.isCall ? RefType::Call
                          : x.isJmp ? RefType::Jmp : RefType::Jcc);
            if (x.hasMemRef && x.memRef >= img_.Base() &&
                x.memRef < img_.Base() + img_.Size())
                AddXref(cur, x.memRef, RefType::Data);

            if (x.isRet) break;
            if (x.isJmp) {
                if (!x.isIndirect && x.target >= img_.Base() &&
                    x.target < img_.Base() + img_.Size() &&
                    !visitedLocal.count(x.target))
                    work.push(x.target);
                break; // jmp akışı bitirir
            }
            if (x.isJcc && !x.isIndirect &&
                x.target >= img_.Base() && x.target < img_.Base() + img_.Size() &&
                !visitedLocal.count(x.target)) {
                work.push(x.target);         // hedef dal
            }
            cur += x.len;                    // düşen akış devam
        }
    }

    std::sort(out.begin(), out.end(),
              [](const Ins& a, const Ins& b) { return a.addr < b.addr; });

    // fonksiyon kaydını güncelle
    auto& f = funcs_[start];
    f.start = start;   // v8 DÜZELTME: start atanmamıştı — FunctionAt kapsama
                       // kontrolü ve InstructionsOf(f.start) bu alanda bozuluyordu
    if (f.name.empty())
        f.name = "sub_" + ToHex(start, 8);
    if (!out.empty()) {
        f.end = out.back().addr + out.back().len;
        f.insCount = out.size();
    }
    funcIns_[start] = out;
    totalIns_ += out.size();
    return out;
}

// ----------------------------------------------------------------------------
// Fonksiyon garantisi (PDB/DWARF isim importu): varsa adlandır, yoksa kur
// ----------------------------------------------------------------------------
void Analyzer::EnsureFunction(u64 va, const std::string& name) {
    if (!img_.InRange(va)) return;
    auto it = funcs_.find(va);
    if (it != funcs_.end()) {
        if (!name.empty() && (it->second.name.empty() ||
                              it->second.name.rfind("sub_", 0) == 0 ||
                              it->second.name == "entry_point"))
            it->second.name = name;
        return;
    }
    FuncInfo fi;
    fi.start = va;
    fi.name = name.empty() ? ("sub_" + ToHex(va, 8)) : name;
    fi.fromSymbol = true;
    funcs_[va] = fi;
    AnalyzeFunction(va);
}

void Analyzer::AddXref(u64 src, u64 dst, RefType t) {
    Xref r{src, dst, t};
    xrefs_.push_back(r);
    xrefsByDst_.insert({dst, r});
}

// ----------------------------------------------------------------------------
// Tüm analiz
// ----------------------------------------------------------------------------
void Analyzer::RunFull(bool verbose) {
    if (verbose) LogInfo("Fonksiyon keşfi (semboller + entry + call hedefleri)...");
    DiscoverFunctions();
    if (verbose) LogInfo("Bulunan aday: %zu fonksiyon", funcs_.size());

    if (verbose) LogInfo("Recursive traversal disassembly...");
    for (auto& [va, f] : funcs_)
        if (!funcIns_.count(va)) DisassembleFunction(va);

    if (verbose) LogInfo("String taraması (ASCII + UTF-16LE)...");
    ExtractStrings();

    if (verbose) {
        LogOk("Analiz bitti: %zu fonksiyon, %zu komut, %zu xref, %zu string",
              funcs_.size(), totalIns_, xrefs_.size(), strings_.size());
    }
}

// ----------------------------------------------------------------------------
// String çıkarma
// ----------------------------------------------------------------------------
void Analyzer::ExtractStrings(size_t minLen) {
    strings_.clear();
    for (size_t si = 0; si < bin_.Sections().size(); si++) {
        auto& sec = bin_.Sections()[si];
        if (!sec.vsize) continue;
        u64 va = sec.va;
        size_t span = (size_t)std::min<u64>(sec.vsize, img_.Size() - (va - img_.Base()));

        // --- Gecis 1: ASCII (null sonlandirmali) ---
        {
            std::string cur;
            for (size_t i = 0; i < span; i++) {
                u8 c = img_.Read8(va + i);
                bool printable = (c >= 0x20 && c < 0x7F) || c == '\t';
                if (printable) {
                    cur += (char)c;
                } else {
                    // GNU strings davranisi: NUL'a kadar beklemeden her
                    // yazdirilabilir kosul >= minLen kayda girer. (Onceki
                    // surum '\n' ile biten string'leri yutuyordu.)
                    if (cur.size() >= minLen)
                        strings_.push_back({va + i - cur.size(), cur, false, si});
                    cur.clear();
                }
            }
            if (cur.size() >= minLen)   // bolum sonu flush
                strings_.push_back({va + span - cur.size(), cur, false, si});
        }
        // --- Gecis 2: UTF-16LE (2 bayt adimli) ---
        {
            std::string cur;
            size_t runStart = 0;
            for (size_t i = 0; i + 1 < span; i += 2) {
                u8 lo = img_.Read8(va + i);
                u8 hi = img_.Read8(va + i + 1);
                if (lo >= 0x20 && lo < 0x7F && hi == 0x00) {
                    if (cur.empty()) runStart = i;
                    cur += (char)lo;
                } else {
                    if (cur.size() >= minLen)
                        strings_.push_back({va + runStart, cur, true, si});
                    cur.clear();
                }
            }
            if (cur.size() >= minLen)
                strings_.push_back({va + runStart, cur, true, si});
        }
    }
}

// ----------------------------------------------------------------------------
// Sorgular
// ----------------------------------------------------------------------------
const FuncInfo* Analyzer::FunctionAt(u64 va) const {
    // va bir fonksiyonun gövdesine mi düşer?
    auto it = funcs_.upper_bound(va);
    if (it == funcs_.begin()) return nullptr;
    --it;
    if (va >= it->second.start && va < it->second.end) return &it->second;
    return nullptr;
}

const FuncInfo* Analyzer::FunctionStart(u64 va) const {
    auto it = funcs_.find(va);
    return it == funcs_.end() ? nullptr : &it->second;
}

const std::vector<Ins>* Analyzer::InstructionsOf(u64 funcStart) const {
    auto it = funcIns_.find(funcStart);
    return it == funcIns_.end() ? nullptr : &it->second;
}

std::vector<Xref> Analyzer::XrefsTo(u64 dst) const {
    std::vector<Xref> out;
    auto range = xrefsByDst_.equal_range(dst);
    for (auto it = range.first; it != range.second; ++it) out.push_back(it->second);
    return out;
}

std::vector<Xref> Analyzer::XrefsFrom(u64 src) const {
    std::vector<Xref> out;
    for (auto& x : xrefs_) if (x.src == src) out.push_back(x);
    return out;
}

std::string Analyzer::SymbolOrLabel(u64 va) const {
    if (!va) return "";
    // 1) iç sembol
    if (auto* f = FunctionStart(va)) return f->name;
    // 2) IAT yuvası (call qword [rip+X] hedefi)
    auto it = importsByVa_.find(va);
    if (it != importsByVa_.end()) return it->second;
    // 2b) PLT stub / GOT yuvası (ELF)
    std::string plt = bin_.PltName(va);
    if (!plt.empty()) return plt + "@plt";
    std::string got = bin_.GotName(va);
    if (!got.empty()) return got + "@got";
    // 3) export
    for (auto& e : bin_.Exports()) if (e.va == va) return e.name;
    // 4) ELF sembolü (fonksiyon olmayan)
    for (auto& s : bin_.Symbols()) if (s.va == va) return s.name;
    return "";
}

std::string Analyzer::NameFor(u64 va) const {
    if (auto* f = FunctionStart(va)) return f->name;
    return "sub_" + ToHex(va, 8);
}

bool Analyzer::IsStringAt(u64 va, std::string* out) const {
    for (auto& s : strings_)
        if (s.va == va) { if (out) *out = s.text; return true; }
    // tarama listesinde yoksa (kısa stringler minLen'e takılır) canlı oku:
    // en az 2 yazdırılabilir karakter + NUL sonlandırıcı
    u8 buf[96];
    if (!img_.ReadBytes(va, buf, sizeof buf)) return false;
    size_t n = 0;
    while (n < sizeof buf && buf[n] >= 0x20 && buf[n] < 0x7F) n++;
    if (n < 2 || n >= sizeof buf || buf[n] != 0) return false;
    if (out) out->assign((const char*)buf, n);
    return true;
}

} // namespace gt
