// ============================================================================
//  i4M GodTier Engine — decomp/devirtpro.cpp
//  DEVRİT-PRO çekirdeği: WindowEvaluator ("livestep-lite").
//
//  livestep.cpp'den devralınan fikirler (kullanıcının projesi):
//    - sparse bellek görüntüsü → burada MappedImage (VA tabanlı okuma)
//    - TEB/PEB simülasyonu → burada gerekmedi (vtable zincirleri FS/GS
//      dokunmaz; vtable SLotları .rdata'da DURUR)
//    - komut komuta yürütme → burada: çağrıya KADAR olan pencere,
//      somut-simgesel karma değerlerle
//  livestep'e ekleneN (eksik olan): GERÇEK ModRM semantiği —
//  mov reg,[reg+K] artık DEĞER olarak yürütülür (livestep'te yalnızca
//  uzunluk çözümlemesi vardı), bellek okumaları kanıt tablosuyla birleşir.
// ============================================================================
#include "decomp/devirtpro.h"
#include "decomp/devirtemu.h"
#include "core/log.h"
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <chrono>

namespace gt {

DevirtPro::DevirtPro(Analyzer& az, TypeInferer& ti, const MsvcRtti& rtti)
    : az_(az), ti_(ti), rtti_(rtti) {}

DevirtPro::~DevirtPro() = default;   // v8: DevirtEmu tam tipi burada
namespace {

// MSVC veri sembolü basit demangle: "?ad@?$CSingleton@VX@@@@0PA" →
// "CSingleton<X>::ad"  /  "?TWO@@3HA" → "TWO"
std::string DpDemangleData(const std::string& m) {
    if (m.empty() || m[0] != '?') return m;
    std::string body = m.substr(1);
    size_t at = body.find('@');
    if (at == std::string::npos) return m;
    std::string name = body.substr(0, at);
    std::string rest = body.substr(at + 1);
    if (rest.empty()) return name;
    if (rest.rfind("?$", 0) == 0) {
        size_t at2 = rest.find('@', 2);
        if (at2 != std::string::npos) {
            std::string tname = rest.substr(2, at2 - 2);
            std::string after = rest.substr(at2 + 1);
            if (!after.empty() && after[0] == 'V') {
                size_t at3 = after.find('@', 1);
                if (at3 != std::string::npos)
                    return tname + "<" + after.substr(1, at3 - 1) + ">::" + name;
            }
        }
    } else if (rest[0] != '@') {
        size_t dd = rest.find("@@");
        if (dd != std::string::npos && dd > 0)
            return rest.substr(0, dd) + "::" + name;
    }
    return name;
}

// ---------------- yardımcı: operand ayrıştırma (kendine yeten) ----------------

std::vector<std::string> DpSplitOps(const std::string& s) {
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
    // kenar boşlukları
    for (auto& o : out) {
        size_t a = o.find_first_not_of(" \t");
        size_t b = o.find_last_not_of(" \t");
        o = (a == std::string::npos) ? "" : o.substr(a, b - a + 1);
    }
    return out;
}

bool DpIsImm(const std::string& t) {
    if (t.empty()) return false;
    const char* p = t.c_str();
    if (p[0] == '-') p++;
    if (t.rfind("0x", 0) == 0 || (p[0] == '-' && t.rfind("0x", 1) == 1)) {
        return t.find_first_not_of("0123456789abcdefABCDEFx-", 2) ==
               std::string::npos || true;   // güvenli kaba izin
    }
    if (!isdigit((unsigned char)*p)) return false;
    return t.find_first_not_of("0123456789-") == std::string::npos;
}

u64 DpParseImm(const std::string& t, bool* ok = nullptr) {
    if (ok) *ok = false;
    if (t.empty()) return 0;
    bool neg = t[0] == '-';
    const char* p = t.c_str() + (neg ? 1 : 0);
    char* end = nullptr;
    u64 v = strtoull(p, &end, 0);
    if (end && *end == 0) {
        if (ok) *ok = true;
        return neg ? (u64)(0 - (i64)v) : v;
    }
    return 0;
}

// register aileleri — x86-32/64 karışık girdiyi tam genişliğe kanonize et
const char* kReg64From32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                              "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
const char* kReg64[]        = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                               "r8","r9","r10","r11","r12","r13","r14","r15"};

bool DpIsReg(const std::string& t) {
    if (t.empty()) return false;
    // segment + bayrak yazmaçları
    static const char* segs[] = {"cs","ds","es","fs","gs","ss"};
    for (auto* s : segs) if (t == s) return true;
    if (t.size() > 3 && t[0] == 'r' && isdigit((unsigned char)t[1])) return true; // r8..r15 (+d/w/b)
    static const char* names[] = {
        "al","bl","cl","dl","ah","bh","ch","dh","ax","bx","cx","dx","si","di",
        "sp","bp","eax","ebx","ecx","edx","esi","edi","esp","ebp",
        "rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp","sil","dil","bpl","spl",
        "eiz","riz"};
    for (auto* n : names) if (t == n) return true;
    return false;
}

// kanonik (tam genişlik) yazmaç adı; x86-32 modunda "eax" ailesi korunur
std::string DpCanon(const std::string& t, bool is64) {
    if (!DpIsReg(t)) return t;
    for (int i = 0; i < 16; i++) {
        if (t == kReg64[i]) return kReg64[i];
        if (t == kReg64From32[i]) return kReg64[i];
    }
    static const char* sub8[]  = {"al","bl","cl","dl","ah","bh","ch","dh",
                                 "sil","dil","bpl","spl"};
    static const char* sub8p[] = {"rax","rbx","rcx","rdx","rsp","rbp","rsi","rdi",
                                  "rsi","rdi","rbp","rsp"};
    for (int i = 0; i < 12; i++)
        if (t == sub8[i]) return sub8p[i];
    static const char* sub16[] = {"ax","bx","cx","dx","si","di","sp","bp"};
    for (int i = 0; i < 8; i++)
        if (t == sub16[i]) return kReg64[i];
    return t;   // r8w/r8b gibi uc uçlar
}

struct DpMem {
    bool isMem = false;
    std::string base, index;
    u32 scale = 1;
    i64 disp = 0;
    bool absolute = false;   // [0x404000] — taban yok
    u32 size = 0;            // 1/2/4/8 (önekten)
};

DpMem DpParseMem(const std::string& op) {
    DpMem m;
    size_t lb = op.find('[');
    if (lb == std::string::npos) return m;
    m.isMem = true;
    std::string pre = op.substr(0, lb);
    for (auto& kw : {"xmmword ptr ","ymmword ptr ","qword ptr ","dword ptr ",
                     "word ptr ","byte ptr ","tbyte ptr "}) {
        size_t p = pre.find(kw);
        if (p != std::string::npos) {
            std::string k = kw;
            k.erase(k.find(" ptr"), 5);
            if (k == "byte") m.size = 1;
            else if (k == "word") m.size = 2;
            else if (k == "dword") m.size = 4;
            else if (k == "qword") m.size = 8;
            else m.size = 16;
            break;
        }
    }
    size_t rb = op.rfind(']');
    if (rb == std::string::npos) { m.isMem = false; return m; }
    std::string inner = op.substr(lb + 1, rb - lb - 1);
    // boşlukları normalize et, + ve - etrafında böl
    std::string tok;
    std::vector<std::pair<bool, std::string>> parts;   // (pozitif mi, parça)
    bool positive = true;
    for (size_t i = 0; i <= inner.size(); i++) {
        char c = (i < inner.size()) ? inner[i] : ',';
        if (c == '+' || c == '-' || c == ',') {
            size_t a = tok.find_first_not_of(" \t");
            size_t b = tok.find_last_not_of(" \t");
            if (a != std::string::npos)
                parts.push_back({positive, tok.substr(a, b - a + 1)});
            if (c == ',') break;
            positive = (c == '+');
            tok.clear();
        } else tok += c;
    }
    for (auto& [pos, p] : parts) {
        i64 sign = pos ? 1 : -1;
        // reg*scale?
        size_t star = p.find('*');
        if (star != std::string::npos) {
            std::string r = p.substr(0, star), s = p.substr(star + 1);
            m.index = r;
            m.scale = (u32)DpParseImm(s);
            continue;
        }
        if (DpIsReg(p)) {
            if (m.base.empty()) m.base = p;
            else if (m.index.empty()) { m.index = p; m.scale = 1; }
            continue;
        }
        if (p == "rip") { m.base = "rip"; continue; }
        bool ok = false;
        u64 v = DpParseImm(p, &ok);
        if (ok) m.disp += sign * (i64)v;
    }
    if (m.base.empty() && m.index.empty() && m.disp != 0) m.absolute = true;
    if (m.base == "rip") { m.absolute = false; }
    return m;
}

} // namespace

// ----------------------------------------------------------------------------
// kurucu-yazıcı taraması: tüm fonksiyonlarda this-türevi statik yazımları ve
// vftable depolamaları topla (her fonksiyon pencere değerlendirmesinden)
// ----------------------------------------------------------------------------
void DevirtPro::ScanWriters() {
    statics_.clear();
    std::map<u64, WriterScan> scans;   // funcVa -> scan
    for (auto& [va, f] : az_.Functions()) {
        auto* ins = az_.InstructionsOf(va);
        if (!ins) continue;
        WriterScan ws;
        EvalFunction(va, *ins, &ws, 0, nullptr);
        if (!ws.staticsWritten.empty() || !ws.vptrAt.empty())
            scans[va] = std::move(ws);
    }
    // statikler birleştir
    for (auto& [fva, ws] : scans) {
        for (u64 s : ws.staticsWritten) {
            ObjFacts& of = statics_[s];
            of.writers.push_back(fva);
            for (auto& [off, vft] : ws.vptrAt)
                of.vptrCand[off].push_back(vft);
        }
    }
    if (!statics_.empty()) {
        size_t withProof = 0;
        for (auto& [s, of] : statics_)
            if (!of.vptrCand.empty()) withProof++;
        LogInfo("devirt-pro: %zu statik nesne yazicisi, %zu tanesi vtable kanitli",
                statics_.size(), withProof);
    }
}

void DevirtPro::Build() {
    ScanWriters();
    results_.clear();
    std::vector<u64> calls;
    CollectIndirectCalls(calls);
    size_t ok = 0, byTier3 = 0;
    auto t0 = std::chrono::steady_clock::now();
    tier3Enabled_ = true;
    stats_ = Stats{};               // v8.1: mekanizma kırılımı
    stats_.universe = calls.size();
    for (u64 c : calls) {
        // v8 bütçe: tier-3 toplu modda çok uzun sürmesin (dev binary'ler)
        if (tier3Enabled_) {
            double sec = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - t0).count();
            if (sec > 180.0) {
                LogWarn("devirt-pro: tier-3 sure butcesi doldu — kalan siteler"
                        " tier-1 ile degerlendirilecek");
                tier3Enabled_ = false;
            }
        }
        Result r = Resolve(c);
        if (r.resolved) {
            results_[c] = r; ok++;
            if (r.why.find("tier-3") != std::string::npos) byTier3++;
            // v8.1: çözülen kırılımı — hangi kanıt mekanizması?
            if (r.isImport)                 stats_.byIat++;
            else if (r.proofKind == "tier-3") stats_.byTier3++;
            else if (r.proofKind == "atlas")  stats_.byAtlas++;
            else if (r.proofKind == "kurucu") stats_.byCtor++;
            else if (r.proofKind == "init")   stats_.byInit++;
            else                              stats_.byConc++;
        }
        else if (!r.candidates.empty()) {
            results_[c] = r;   // dürüst çoklu aday
            stats_.unMultiCand++;
        }
        else if (r.why.rfind("tier-3", 0) == 0) stats_.unTier3Win++;
        else                                     stats_.unNoProof++;
    }
    stats_.resolved = ok;
    double sec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    LogInfo("devirt-pro: %zu/%zu dolayli cagri statik cozuldu "
            "(tier-1: %zu, tier-3 unicorn: %zu, %.1fs)",
            ok, calls.size(), ok - byTier3, byTier3, sec);
    // v8.1: "N/M çözüldü" sayısının İÇ YAPISI — çözülenler nasıl,
    // kalanlar neden (ayrıntı: 'devirt stats')
    LogInfo("devirt-pro kirilim: kurucu-kanit %zu, atlas %zu, unicorn %zu, "
            "IAT %zu, vtablesiz-somut %zu",
            stats_.byCtor, stats_.byAtlas, stats_.byTier3, stats_.byIat,
            stats_.byConc);
    LogInfo("devirt-pro kalanlar: coklu-aday(durust) %zu, kanit-yok "
            "(heap/param alici) %zu, tier-3-pencere %zu",
            stats_.unMultiCand, stats_.unNoProof, stats_.unTier3Win);
}

// v9.2 (Tier-5a): WinInit init-anlık-görüntü kanıtları bağlanır.
// Öncelik sırası DEĞİŞMEZ: IAT > statik yazıcı > overlay > imaj baytı.
// Overlay yalnız statik kanıtın sussa kaldığı yerde değer verir; verildiği
// çözümler proofKind="init" ile dürüstçe etiketlenir.
void DevirtPro::SetInitOverlay(const std::map<u64, u64>* ov) {
    initOverlay_ = ov;
}

// v8: statik-kanıt görünümleri (tier-3 + Instance() katlaması için)
DevirtPro::StaticFactsView DevirtPro::StaticView(u64 va) const {
    StaticFactsView v;
    auto it = statics_.find(va);
    if (it == statics_.end()) return v;
    v.proven = true;
    v.writers = it->second.writers;
    v.vptrCand = it->second.vptrCand;
    return v;
}

std::vector<u64> DevirtPro::AllStaticVas() const {
    std::vector<u64> out;
    out.reserve(statics_.size());
    for (auto& [s, of] : statics_) out.push_back(s);
    return out;   // map sırası = adres sırası (kararlı)
}

size_t DevirtPro::ResolvedCount() const {
    size_t n = 0;
    for (auto& [a, r] : results_) if (r.resolved) n++;
    return n;
}

void DevirtPro::CollectIndirectCalls(std::vector<u64>& out) const {
    for (auto& [va, f] : az_.Functions()) {
        auto* ins = az_.InstructionsOf(va);
        if (!ins) continue;
        for (auto& x : *ins)
            if (x.isCall && x.isIndirect) out.push_back(x.addr);
    }
}

bool DevirtPro::IsExecVa(u64 va) const {
    for (auto& s : az_.Bin().Sections())
        if (s.executable && va >= s.va && va < s.va + std::max(s.vsize, s.rawSize))
            return true;
    return false;
}

// IAT yuvası mı? (bound import: dosyadaki değer sahte kod adresi olabilir!)
std::string DevirtPro::ImportAt(u64 iatVa) const {
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

std::string DevirtPro::NameForTarget(u64 va) const {
    std::string n = az_.NameFor(va);
    if (!n.empty() && n.rfind("sub_", 0) != 0) return n;
    // sembol yoksa RTTI sınıf adı + slot bilgisi çağıran tarafça eklenir
    return n.empty() ? ("sub_" + [va]{
        char b[32]; snprintf(b, sizeof b, "%llx", (unsigned long long)va);
        return std::string(b);}()) : n;
}

DevirtPro::VVal DevirtPro::Reg(const std::string& canon) const {
    auto it = regs_.find(canon);
    return it == regs_.end() ? VVal{} : it->second;
}

void DevirtPro::SetReg(const std::string& canon, VVal v) {
    if (canon.empty() || !DpIsReg(canon)) return;
    // kanonik ad DaimA tam genişlik ailesidir (eax→rax): okuma/yazma uyumu
    std::string c = DpCanon(canon, true);
    regs_[c] = v;
}

// ----------------------------------------------------------------------------
// bellek okuma: kanıt tablosu → imaj (livestep'in Mem.r32'sinin bilge hali)
// ----------------------------------------------------------------------------
DevirtPro::VVal DevirtPro::ReadMemory(u64 addr, std::vector<std::string>* trace) {
    (void)trace;
    VVal v;
    // IAT yuvası: dosyadaki değer (bound import) YALANCI işaretçidir —
    // gerçek değer runtime'da loader yazar; statik çözüm import ismidir.
    // (oku-kaydet: çağrı anında lastIatSlot_ üzerinden isim çözülür)
    if (!ImportAt(addr).empty()) {
        lastIatSlot_ = addr;
        return v;   // Unknown — dürüst
    }
    // statik yazıcı kanıtı: [S] = nesne işaretçisi (imajda .bss=0!)
    auto sit = statics_.find(addr);
    if (sit != statics_.end() && !sit->second.writers.empty()) {
        // v9.2: yazıcı var ama HİÇ vtable adayı yoksa (fabrika deseni: this
        // saklanıyor, kurucu ayrı çağrıda) Sym maskesi çözümsüz Unknown'a
        // düşerdi — init-anlık görüntüsü varsa o devreye girer. vtable adayı
        // VARSA statik aday semantiği korunur (overlay karışmaz).
        bool hasVptr = false;
        for (auto& [o, c] : sit->second.vptrCand)
            if (!c.empty()) { hasVptr = true; break; }
        if (hasVptr || !initOverlay_) {
            v.k = VVal::Sym;
            v.c = addr;          // nesne anahtarı = statik VA
            v.off = 0;
            return v;
        }
        // düş: overlay değerine (varsa) — yoksa eski Unknown sonucu
    }
    // v9.2: WinInit init-anlık görüntüsü — runtime init sonrası GERÇEK değer.
    // (dosyada .bss=0 / bayat .data; init koşunca yazıldı. Tek deterministik
    //  yürütmenin gözlemi — kanıt etiketi "init" olarak taşınır)
    if (initOverlay_) {
        auto oit = initOverlay_->find(addr);
        if (oit != initOverlay_->end()) {
            v.k = VVal::Conc;
            v.c = oit->second;
            usedInitFact_ = true;
            if (trace) {
                char b[112];
                snprintf(b, sizeof b,
                         "[0x%llx] init-anlik-goruntu: 0x%llx (WinInit Tier-5a)",
                         (unsigned long long)addr, (unsigned long long)v.c);
                trace->push_back(b);
            }
            return v;
        }
    }
    // imaj okuma (vftable slotları, hazır veriler)
    u64 ptrSize = az_.Bin().Is64() ? 8 : 4;
    u64 raw = 0;
    if (az_.Image().ReadBytes(addr, (u8*)&raw, ptrSize)) {
        v.k = VVal::Conc;
        v.c = raw;
        return v;
    }
    return v;   // Unknown
}

// simgesel nesnenin belleği: vptr kanıtları
static DevirtPro::VVal ReadObjMem(const DevirtPro::VVal& addr,
                                  const std::map<i64, std::vector<u64>>& vptrCand,
                                  std::vector<std::string>* trace) {
    DevirtPro::VVal v;
    auto it = vptrCand.find(addr.off);
    if (it == vptrCand.end()) return v;
    std::set<u64> uniq(it->second.begin(), it->second.end());
    if (trace) {
        char buf[96];
        snprintf(buf, sizeof buf, "[nesne+0x%llx] vptr okuma: %zu aday vftable",
                 (unsigned long long)addr.off, uniq.size());
        trace->push_back(buf);
    }
    if (uniq.size() == 1) {
        v.k = DevirtPro::VVal::Conc;
        v.c = *uniq.begin();
    } else {
        v.k = DevirtPro::VVal::Cand;
        v.cands.assign(uniq.begin(), uniq.end());
    }
    return v;
}

// tek-değerli vptr tablosu (yazıcı taraması: son yazım kazanır zaten)
static DevirtPro::VVal ReadObjMem(const DevirtPro::VVal& addr,
                                  const std::map<i64, u64>& vptrLast,
                                  std::vector<std::string>*) {
    DevirtPro::VVal v;
    auto it = vptrLast.find(addr.off);
    if (it == vptrLast.end()) return v;
    v.k = DevirtPro::VVal::Conc;
    v.c = it->second;
    return v;
}

// ----------------------------------------------------------------------------
// pencere değerlendirici — livestep-lite çekirdeği
// ----------------------------------------------------------------------------
void DevirtPro::EvalFunction(u64 funcVa, const std::vector<Ins>& ins,
                             WriterScan* out, u64 stopAt, Result* result) {
    regs_.clear();
    usedInitFact_ = false;          // v9.2: pass başında temiz başla
    memFacts_.clear();
    thisVptr_.clear();
    thisVptrAll_.clear();
    thisVptrCand_.clear();
    thisStatics_.clear();
    thisKey_ = funcVa;
    const bool is64 = az_.Bin().Is64();
    const bool isElf = az_.Bin().FormatName().find("ELF") != std::string::npos;
    const u64 ptrSize = is64 ? 8 : 4;

    // giriş this'i (kurucu taraması için): thiscall ecx / Win64 rcx / SysV rdi
    {
        VVal th; th.k = VVal::Sym; th.c = thisKey_; th.off = 0;
        if (is64) SetReg(isElf ? "rdi" : "rcx", th);
        else      SetReg("ecx", th);
    }
    // v8 ATLAS İNVERSİYONU: bu fonksiyon bir sanal metod ise this'in
    // dinamik tipi, metodun bulunduğu vftable kümesiyle kısıtlıdır
    // (gövdeye hangi sınıfın vtable'ından girildiyse this odur — CHA).
    // Dürüstlük: tek sahipli vtable → somut; çok sahipli → aday kümesi
    // (sonraki [reg+K] okuması tek hedefe çökerse kanıtlanmış çözüm).
    if (auto* owners = rtti_.VtablesContaining(funcVa)) {
        std::set<u64> uniq;
        for (auto* rc : *owners) uniq.insert(rc->vftVa);
        for (u64 vft : uniq)
            thisVptrCand_[0].push_back(vft);   // [this+0] = sahibin vftable'i
    }
    std::vector<VVal> stack;             // push/pop modeli (callee-save kurtarma)
    int earlyArgGuard = 12;              // cdecl kurucu: [ebp+8] ilk ~komutlar

    // son vftable okuma kanıtı (çağrı çözümünde sınıf/slot eki için)
    u64 lastVft = 0;
    i64 lastVftOff = -1;
    std::string lastProof;               // v8.1: kanıtın KAYNAĞI (kurucu/atlas)
    lastIatSlot_ = 0;

    auto evalMemAddr = [&](const DpMem& m, std::vector<std::string>* tr,
                           VVal* objOut) -> VVal {
        // adres DEĞERİ hesapla (lea gibi); objOut: simgesel nesne kimliği
        if (objOut) *objOut = VVal{};
        if (m.base == "rip") {
            // rip-göreli: çözülmüş memRef kullanılmalı (çağıran verir)
            return VVal{};   // (memRef dışarıdan eklenir — aşağıda x.memRef)
        }
        VVal base;
        if (!m.base.empty()) base = Reg(DpCanon(m.base, is64));
        VVal index;
        if (!m.index.empty()) index = Reg(DpCanon(m.index, is64));
        VVal v;
        if (m.base.empty() && m.index.empty()) {          // mutlak [0x...]
            v.k = VVal::Conc; v.c = (u64)m.disp;
            return v;
        }
        if (base.k == VVal::Conc) {
            v.k = VVal::Conc;
            v.c = base.c + (u64)m.disp;
            if (index.k == VVal::Conc) v.c += index.c * m.scale;
            else if (!m.index.empty()) v.k = VVal::Unknown;
            return v;
        }
        if (base.k == VVal::Sym) {
            v = base;
            v.off = base.off + m.disp;
            if (index.k == VVal::Conc) {
                // nesne + sabit indeks: ofset büyür
                v.off += (i64)(index.c * m.scale);
            } else if (!m.index.empty()) return VVal{};
            if (objOut) *objOut = v;
            return v;    // adres simgesel — okuma ReadObjMem yoluyla
        }
        return VVal{};
    };

    auto readFromMem = [&](const DpMem& m, const Ins& x,
                           std::vector<std::string>* tr) -> VVal {
        // rip-göreli: analyzer çözümü memRef
        if (m.base == "rip") {
            if (x.hasMemRef) {
                VVal a; a.k = VVal::Conc; a.c = x.memRef;
                return ReadMemory(a.c, tr);
            }
            return VVal{};
        }
        // vftable tabanlı okuma mu? (base = son bulunan vftable)
        if (!m.base.empty() && lastVft) {
            VVal bv = Reg(DpCanon(m.base, is64));
            if (bv.k == VVal::Conc && bv.c == lastVft)
                lastVftOff = m.disp;
        }
        // ÇOKLU-ADAY vftable tabanı (CHA dürüstlüğü): "call [edx+0x88]"
        // benzeri okumalarda base birden çok vftable adayı taşıyabilir.
        // Her adayın aynı ofsetteki slotunu oku: hepsi TEK hedefe giderse
        // kanıtlanmış çözüm, yoksa dürüst aday listesi (Cand: vft listesi).
        if (!m.base.empty() && m.index.empty()) {
            VVal bv = Reg(DpCanon(m.base, is64));
            if (bv.k == VVal::Cand && !bv.cands.empty()) {
                bool allVft = true;
                for (u64 v : bv.cands) if (!IsVftable(v)) { allVft = false; break; }
                if (allVft) {
                    lastVftOff = m.disp;
                    std::set<u64> targets;
                    for (u64 vft : bv.cands) {
                        u64 raw = 0;
                        if (az_.Image().ReadBytes(vft + (u64)m.disp,
                                                  (u8*)&raw, ptrSize) &&
                            IsExecVa(raw))
                            targets.insert(raw);
                    }
                    if (targets.size() == 1) {
                        VVal r; r.k = VVal::Conc; r.c = *targets.begin();
                        // v8: çöken aday kümesinden temsilci vftable —
                        // sınıf/slot adlandırması kaybolmasın
                        lastVft = *bv.cands.begin();
                        lastProof = "kurucu";   // adaylar yazıcı kanıtından
                        if (tr) {
                            char b[112];
                            snprintf(b, sizeof b,
                                     "coklu-aday vtable[slot 0x%llx] tek hedefe "
                                     "daraldi: 0x%llx",
                                     (unsigned long long)m.disp,
                                     (unsigned long long)r.c);
                            tr->push_back(b);
                        }
                        return r;
                    }
                    if (tr) {
                        char b[96];
                        snprintf(b, sizeof b,
                                 "[aday vtable+0x%llx]: %zu aday sinif",
                                 (unsigned long long)m.disp, bv.cands.size());
                        tr->push_back(b);
                    }
                    return bv;   // Cand: vftable adayları (Resolve slot çöz)
                }
            }
        }
        VVal obj;
        VVal addr = evalMemAddr(m, tr, &obj);
        if (addr.k == VVal::Conc) {
            VVal r = ReadMemory(addr.c, tr);
            // v9.2: overlay'den GELDiYSE ve değer bir vftable ise kanıt
            // etiketini "init" olarak taşı (varsayılan davranış DEĞİŞMEZ:
            // yalnız overlay kullanıldıysa lastVft kurulur)
            if (usedInitFact_ && r.k == VVal::Conc && IsVftable(r.c)) {
                lastVft = r.c;
                lastProof = "init";
            }
            return r;
        }
        if (addr.k == VVal::Sym) {
            // this-nesnesi mi (bu fonksiyonun yazıcı taraması)?
            if (addr.c == thisKey_) {
                VVal r = ReadObjMem(addr, thisVptr_, tr);
                std::string proof = "kurucu";   // kendi vtable yazımı
                // v8: bu fonksiyonun kendi vtable yazımı yoksa ATLAS
                // İNVERSİYON adaylarına düş (sanal metod gövdesi)
                if (r.IsUnknown() && !thisVptrCand_.empty()) {
                    r = ReadObjMem(addr, thisVptrCand_, tr);
                    proof = "atlas";            // metod sahibi sınıflar (CHA)
                }
                if (r.k == VVal::Conc) {
                    lastVft = r.c;
                    lastProof = proof;
                    if (tr) {
                        char b[96];
                        snprintf(b, sizeof b, "vptr(+0x%llx) = vftable 0x%llx",
                                 (unsigned long long)addr.off,
                                 (unsigned long long)r.c);
                        tr->push_back(b);
                    }
                }
                return r;
            }
            // statik-nesne kanıtı (ReadMemory zaten Sym üretir; vptr'yi oku)
            auto sit = statics_.find(addr.c);
            if (sit != statics_.end()) {
                VVal r = ReadObjMem(addr, sit->second.vptrCand, tr);
                if (r.k == VVal::Conc) {
                    lastVft = r.c;
                    lastProof = "kurucu";       // statik yazıcı kanıtı
                }
                return r;
            }
            return VVal{};
        }
        return VVal{};
    };

    for (const Ins& x : ins) {
        if (x.addr == stopAt && result) {
            // ---- HEDEF ÇAĞRI: çöz ----
            auto ops = DpSplitOps(x.opStr);
            VVal target;
            u64 iatSlot = 0;
            if (!ops.empty()) {
                if (DpIsReg(ops[0])) {
                    target = Reg(DpCanon(ops[0], is64));
                } else {
                    DpMem m = DpParseMem(ops[0]);
                    if (m.isMem) {
                        if (m.absolute) iatSlot = (u64)m.disp;
                        target = readFromMem(m, x, &result->trace);
                    }
                }
            }
            // IAT import çağrısı: (a) call [IAT] doğrudan  (b) mov reg,[IAT];
            // call reg — bound-import dosya değeri YALANCI kod işaretçisidir,
            // gerçek statik çözüm import tablosundaki İMDİR
            if (iatSlot || lastIatSlot_) {
                u64 slot = iatSlot ? iatSlot : lastIatSlot_;
                std::string imp = ImportAt(slot);
                if (!imp.empty()) {
                    char b[128];
                    snprintf(b, sizeof b,
                             "0x%llx: IAT 0x%llx -> %s (import cagrisi)",
                             (unsigned long long)x.addr,
                             (unsigned long long)slot, imp.c_str());
                    result->trace.push_back(b);
                    result->resolved = true;
                    result->isImport = true;
                    result->target = 0;
                    result->name = imp;
                    result->why = "IAT import cagrisi (dll.api)";
                    result->proofKind = "IAT";
                    return;
                }
            }
            if (target.k == VVal::Conc && IsExecVa(target.c)) {
                result->resolved = true;
                result->target = target.c;
                result->name = NameForTarget(target.c);
                // v8.1: kanıt mekanizması etiketi (kırılım istatistiği)
                // v9.2: kanıt kaynağı etiketi — zincir init-anlık görüntüsü
                // (WinInit Tier-5a) kullandıysa dürüstçe "init" de
                result->proofKind = lastVft ? lastProof
                              : (usedInitFact_ ? "init" : "pencere");
                if (lastVft && rtti_.ByVftable(lastVft)) {
                    result->vftVa = lastVft;
                    result->slot = (int)(lastVftOff / (i64)ptrSize);
                    const RttiClass* rc = rtti_.ByVftable(lastVft);
                    result->className = rc->name;
                    if (result->name.rfind("sub_", 0) == 0)
                        result->name = rc->name + "::vf" +
                                       std::to_string(result->slot);
                }
            } else if (target.k == VVal::Cand) {
                result->slot = (int)(lastVftOff / (i64)ptrSize);
                for (u64 vft : target.cands) {
                    const RttiClass* rc = rtti_.ByVftable(vft);
                    if (!rc) continue;
                    u64 t = rtti_.ResolveSlot(vft, (u32)lastVftOff, nullptr);
                    result->candidates.push_back(t);
                    result->candidateNames.push_back(
                        rc->name + "::" + (t ? NameForTarget(t)
                                             : "slot" + std::to_string(
                                                   lastVftOff / (i64)ptrSize)));
                }
            }
            return;
        }

        const std::string& mn = x.mnemonic;
        auto ops = DpSplitOps(x.opStr);
        // NOT: ret/retn burada KIRMAZ — aşağıdaki özel blok ( erken çıkış
        // ret'i pencereyi durdurmaz ) devralır; ops boşluğu önemsiz.
        if (ops.empty()) continue;

        // ---- çağrı: kayıp yazmaçları temizle (caller-saved) ----
        if (x.isCall) {
            if (is64) {
                for (auto* r : {"rax","rcx","rdx","rsi","rdi",
                                "r8","r9","r10","r11"}) SetReg(r, VVal{});
            } else {
                SetReg("rax", VVal{}); SetReg("rcx", VVal{}); SetReg("rdx", VVal{});
            }
            continue;
        }
        if (mn == "cdq" || mn == "cwd") { SetReg(is64 ? "rdx" : "rdx", VVal{}); continue; }
        if (mn == "cdqe" || mn == "cwde" || mn == "cbw") continue;

        // ---- yazmaç yazan ana komutlar ----
        if (mn == "mov" || mn == "movzx" || mn == "movsx" || mn == "movsxd" ||
            mn == "movbe") {
            if (ops.size() != 2) continue;
            const std::string& dst = ops[0];
            const std::string& src = ops[1];
            if (dst.find('[') != std::string::npos) {
                // ---- belleğe yazım: KANIT TOPLAMA ----
                DpMem m = DpParseMem(dst);
                if (!m.isMem) continue;
                VVal val;
                if (DpIsReg(src)) val = Reg(DpCanon(src, is64));
                else if (DpIsImm(src)) { val.k = VVal::Conc; val.c = DpParseImm(src); }
                else continue;
                if (m.base == "rip" && x.hasMemRef) {
                    // mutlak adrese yazım (x64): memRef hedefi
                    if (val.k == VVal::Conc) memFacts_[x.memRef] = val;
                    continue;
                }
                VVal obj;
                VVal addr = evalMemAddr(m, nullptr, &obj);
                if (addr.k == VVal::Conc) {
                    // statik yazımı: this-türevi mi?
                    if (val.k == VVal::Sym && val.c == thisKey_ && val.off == 0) {
                        if (out) out->staticsWritten.insert(addr.c);
                        thisStatics_.insert(addr.c);
                        if (result) {
                            char b[128];
                            snprintf(b, sizeof b,
                                     "statik 0x%llx <- this (kurucu kaniti)",
                                     (unsigned long long)addr.c);
                            result->trace.push_back(b);
                        }
                    }
                    memFacts_[addr.c] = val;
                } else if (addr.k == VVal::Sym && addr.c == thisKey_) {
                    // this+K'ya vftable yazımı (SON yazım kazanır)
                    if (val.k == VVal::Conc && IsVftable(val.c)) {
                        thisVptr_[addr.off] = val.c;
                        thisVptrAll_[addr.off].insert(val.c);
                        if (out) out->vptrAt[addr.off] = val.c;
                        if (out) out->vptrAll[addr.off].insert(val.c);
                        if (result) {
                            char b[128];
                            snprintf(b, sizeof b,
                                     "[this+0x%llx] = vftable 0x%llx (%s)",
                                     (unsigned long long)addr.off,
                                     (unsigned long long)val.c,
                                     rtti_.ByVftable(val.c)
                                         ? rtti_.ByVftable(val.c)->name.c_str()
                                         : "?");
                            result->trace.push_back(b);
                        }
                    }
                }
                continue;
            }
            if (!DpIsReg(dst)) continue;
            std::string dc = DpCanon(dst, is64);
            if (DpIsReg(src)) {
                SetReg(dc, Reg(DpCanon(src, is64)));
            } else if (src.find('[') != std::string::npos) {
                DpMem m = DpParseMem(src);
                // cdecl kurucu: erken [ebp+8]/[ebp+0xC] okuması = stack this/arg
                if (m.base == (is64 ? "rbp" : "ebp") && m.disp >= 8 &&
                    earlyArgGuard > 0 && !is64) {
                    VVal th; th.k = VVal::Sym; th.c = thisKey_; th.off = 0;
                    if (m.disp == 8) { SetReg(dc, th); earlyArgGuard--; continue; }
                }
                SetReg(dc, readFromMem(m, x, nullptr));
            } else if (DpIsImm(src)) {
                VVal v; v.k = VVal::Conc; v.c = DpParseImm(src);
                SetReg(dc, v);
            } else SetReg(dc, VVal{});
            continue;
        }
        if (mn == "lea") {
            if (ops.size() != 2 || !DpIsReg(ops[0])) continue;
            DpMem m = DpParseMem(ops[1]);
            if (!m.isMem) continue;
            if (m.base == "rip" && x.hasMemRef) {
                VVal v; v.k = VVal::Conc; v.c = x.memRef;
                SetReg(DpCanon(ops[0], is64), v);
                continue;
            }
            VVal obj;
            VVal addr = evalMemAddr(m, nullptr, &obj);
            SetReg(DpCanon(ops[0], is64), addr);
            continue;
        }
        if (mn == "add" || mn == "sub" || mn == "and" || mn == "or" ||
            mn == "xor" || mn == "adc" || mn == "sbb") {
            if (ops.size() != 2) continue;
            // xor r, r = 0
            if (mn == "xor" && DpIsReg(ops[0]) && DpIsReg(ops[1]) &&
                DpCanon(ops[0], is64) == DpCanon(ops[1], is64)) {
                VVal z; z.k = VVal::Conc; z.c = 0;
                SetReg(DpCanon(ops[0], is64), z);
                continue;
            }
            if (!DpIsReg(ops[0])) continue;
            std::string dc = DpCanon(ops[0], is64);
            VVal a = Reg(dc), b;
            if (DpIsReg(ops[1])) b = Reg(DpCanon(ops[1], is64));
            else if (DpIsImm(ops[1])) { b.k = VVal::Conc; b.c = DpParseImm(ops[1]); }
            else continue;
            if (a.k == VVal::Conc && b.k == VVal::Conc) {
                u64 r = a.c;
                if (mn == "add" || mn == "adc") r += b.c;
                else if (mn == "sub" || mn == "sbb") r -= b.c;
                else if (mn == "and") r &= b.c;
                else if (mn == "or") r |= b.c;
                else r ^= b.c;
                a.c = r;
                SetReg(dc, a);
            } else if (a.k == VVal::Sym && b.k == VVal::Conc &&
                       (mn == "add" || mn == "sub")) {
                a.off += (mn == "add" ? (i64)b.c : -(i64)b.c);
                SetReg(dc, a);
            } else SetReg(dc, VVal{});
            continue;
        }
        if (mn == "inc" || mn == "dec" || mn == "neg" || mn == "not") {
            if (!DpIsReg(ops[0])) continue;
            std::string dc = DpCanon(ops[0], is64);
            VVal a = Reg(dc);
            if (a.k == VVal::Conc) {
                if (mn == "inc") a.c++;
                else if (mn == "dec") a.c--;
                else if (mn == "neg") a.c = (u64)(0 - (i64)a.c);
                else a.c = ~a.c;
                SetReg(dc, a);
            } else SetReg(dc, VVal{});
            continue;
        }
        if (mn == "shl" || mn == "shr" || mn == "sar") {
            if (ops.size() != 2 || !DpIsReg(ops[0])) continue;
            std::string dc = DpCanon(ops[0], is64);
            VVal a = Reg(dc);
            u64 sh = DpIsImm(ops[1]) ? DpParseImm(ops[1]) : 1;
            if (a.k == VVal::Conc && sh < 64) {
                if (mn == "shl") a.c <<= sh;
                else if (mn == "shr") a.c >>= sh;
                else a.c = (u64)(((i64)a.c) >> sh);
                SetReg(dc, a);
            } else SetReg(dc, VVal{});
            continue;
        }
        if (mn == "imul" && ops.size() == 2 && DpIsReg(ops[0])) {
            std::string dc = DpCanon(ops[0], is64);
            VVal a = Reg(dc), b;
            if (DpIsReg(ops[1])) b = Reg(DpCanon(ops[1], is64));
            else if (DpIsImm(ops[1])) { b.k = VVal::Conc; b.c = DpParseImm(ops[1]); }
            else continue;
            if (a.k == VVal::Conc && b.k == VVal::Conc) { a.c *= b.c; SetReg(dc, a); }
            else SetReg(dc, VVal{});
            continue;
        }
        if (mn == "pop") {
            if (DpIsReg(ops[0])) {
                std::string dc = DpCanon(ops[0], is64);
                if (!stack.empty()) { SetReg(dc, stack.back()); stack.pop_back(); }
                else SetReg(dc, VVal{});
            }
            continue;
        }
        if (mn == "push") {
            VVal v;
            if (DpIsReg(ops[0])) v = Reg(DpCanon(ops[0], is64));
            else if (DpIsImm(ops[0])) { v.k = VVal::Conc; v.c = DpParseImm(ops[0]); }
            stack.push_back(v);
            continue;
        }
        if (mn == "leave" || mn == "ret" || mn == "retn") {
            // ERKEN ÇIKIŞ ret'i pencereyi DURDURMAZ: MSVC'de "hata yolu"
            // (test al,al / jne / ... / ret) sonrası ana gövde gelir; zincir
            // deseni her şeyi yeniden yüklediğinden lineer devam GÜVENLİDİR.
            stack.clear();
            continue;
        }
        // bilinmeyen komut: ilk operand yazmaçsa temizle (güvenli taraf)
        if (!ops.empty() && DpIsReg(ops[0])) {
            std::string dc = DpCanon(ops[0], is64);
            if (mn != "cmp" && mn != "test" && mn != "push" &&
                mn.rfind("j", 0) != 0 && mn.rfind("set", 0) != 0 &&
                mn.rfind("cmov", 0) != 0)
                SetReg(dc, VVal{});
        }
        earlyArgGuard--;
    }
}

// ----------------------------------------------------------------------------
// v8 TIER-3: Unicorn tohumlu pencere emülasyonu — çoklu pass orkestrasyonu
// ----------------------------------------------------------------------------
bool DevirtPro::EmuResolve(u64 callAddr, Result& r) {
    if (!tier3Enabled_) return false;
    if (!emu3_)
        emu3_ = std::make_unique<DevirtEmu>(az_, *this, rtti_);
        emu3_->SetInitOverlay(initOverlay_);   // v9.2: WinInit kanıtları tier-3'e de iner
    if (!emu3_->Available()) return false;

    // 1) varsayılan tohumlar: her statik, her ofset → ilk aday
    DevirtEmu::SeedChoice def;
    for (u64 s : AllStaticVas()) {
        auto fv = StaticView(s);
        for (auto& [off, cands] : fv.vptrCand)
            if (!cands.empty()) def.staticSeeds[s][off] = cands.front();
    }
    std::vector<std::string> tr;
    DevirtEmu::Attempt a1 = emu3_->TryCall(callAddr, def, &tr);

    std::vector<DevirtEmu::Attempt> passes;
    if (a1.reached) {
        passes.push_back(a1);
    } else {
        // 2) ulaşamadı: sanal metod gövdesi olabilir — this-tohumu varyantları
        const FuncInfo* f = az_.FunctionAt(callAddr);
        if (f)
            if (auto* owners = rtti_.VtablesContaining(f->start)) {
                size_t tried = 0;
                for (auto* rc : *owners) {
                    if (tried++ >= 4) break;          // bütçe
                    DevirtEmu::SeedChoice sc = def;
                    sc.useThis = true;
                    sc.thisOff = (i64)rc->objectOffset;
                    sc.thisVft = rc->vftVa;
                    auto ax = emu3_->TryCall(callAddr, sc, passes.empty() ? &tr : nullptr);
                    if (ax.reached) { passes.push_back(ax); break; }
                }
            }
    }
    if (passes.empty()) {
        if (!tr.empty()) r.trace = tr;
        // v8.1: dürüst neden — pencere bile çağrıya ulaşamadı (hata/yol)
        r.why = "tier-3: pencere cagriya ulasamadi (hata/yol)";
        return false;
    }

    // 3) dürüst aday genişletme: dokunulan statiklerde çoklu aday varsa
    //    HER alternatifi ayrı pass'te dene (yanlış tekil tahmine izin YOK)
    std::set<u64> targets;
    if (a1.isImport) {
        r.resolved = true;
        r.isImport = true;
        r.target = 0;
        r.name = a1.importName;
        r.why = "tier-3 unicorn: IAT import cagrisi";
        r.proofKind = "tier-3";
        r.trace = tr;
        return true;
    }
    if (a1.target) targets.insert(a1.target);
    for (auto& p : passes)
        if (p.target) targets.insert(p.target);
    for (u64 s : a1.touchedStatics) {
        auto fv = StaticView(s);
        for (auto& [off, cands] : fv.vptrCand) {
            if (cands.size() <= 1) continue;
            for (u64 alt : cands) {
                auto dit = def.staticSeeds.find(s);
                if (dit != def.staticSeeds.end() &&
                    dit->second.count(off) &&
                    dit->second[off] == alt) continue;
                DevirtEmu::SeedChoice sc = def;
                sc.staticSeeds[s][off] = alt;
                auto ax = emu3_->TryCall(callAddr, sc, nullptr);
                if (ax.reached && ax.target) targets.insert(ax.target);
                if (targets.size() > 6) break;        // bütçe
            }
        }
    }

    r.trace = tr;
    if (targets.size() == 1) {
        const DevirtEmu::Attempt& proof = a1.reached && a1.target ? a1 : passes[0];
        r.resolved = true;
        r.isImport = false;
        r.target = *targets.begin();
        r.name = NameForTarget(r.target);
        char b[160];
        snprintf(b, sizeof b,
                 "  hedef = 0x%llx (tum aday pass'leri ayni sonuc — KANITLANMIS)",
                 (unsigned long long)r.target);
        r.trace.push_back(b);
        r.trace.push_back("  call -> " + r.name + "  [TIER-3 UNICORN COZUM]");
        r.proofKind = "tier-3";
        if (proof.vftVa && rtti_.ByVftable(proof.vftVa)) {
            r.vftVa = proof.vftVa;
            r.slot = (int)(proof.slotOff / (az_.Bin().Is64() ? 8 : 4));
            r.className = rtti_.ByVftable(proof.vftVa)->name;
            if (r.name.rfind("sub_", 0) == 0)
                r.name = r.className + "::vf" + std::to_string(r.slot);
            r.why = r.className + " vftable[" + std::to_string(r.slot) +
                    "] (tier-3 unicorn pencere emulasyonu)";
        } else {
            r.why = "tier-3 unicorn pencere emulasyonu (vtable'siz kanit)";
        }
        return true;
    }
    if (targets.size() > 1) {
        // dürüst çoklu aday — çözülmedi ama zenginleştirilmiş liste
        r.resolved = false;
        r.candidates.assign(targets.begin(), targets.end());
        r.candidateNames.clear();
        for (u64 t : r.candidates)
            r.candidateNames.push_back(NameForTarget(t));
        r.why = "tier-3: coklu aday (dürüst sanal kaldi)";
        return false;
    }
    return false;   // ulaşıldı ama yazmaç/kanıt yetersiz — dürüst fail
    // v8.1: (aşağıya düşmez — neden etiketi kırılımda görünsün)
}

// ----------------------------------------------------------------------------
// v8.1: mekanizma kırılımı raporu (devirt stats)
// ----------------------------------------------------------------------------
void DevirtPro::DumpStats(std::string& out) const {
    char buf[160];
    const Stats& s = stats_;
    out += "== DEVRIT-PRO KIRILIM: nasil cozuldu / neden cozulemedi ==\n";
    snprintf(buf, sizeof buf,
             "  evren: %zu dolayli cagri | cozulen: %zu | kalan: %zu\n",
             s.universe, s.resolved, s.universe - s.resolved);
    out += buf;
    out += "  -- cozulenler (kanit mekanizmasi) --\n";
    snprintf(buf, sizeof buf,
             "    kurucu vtable-saklama kaniti : %zu\n", s.byCtor); out += buf;
    snprintf(buf, sizeof buf,
             "    atlas inversiyonu (CHA)      : %zu\n", s.byAtlas); out += buf;
    snprintf(buf, sizeof buf,
             "    tier-3 unicorn pencere emu.  : %zu\n", s.byTier3); out += buf;
    snprintf(buf, sizeof buf,
             "    WinInit init-anlik-goruntusu : %zu\n", s.byInit); out += buf;
    snprintf(buf, sizeof buf,
             "    IAT importu (dll.api)        : %zu\n", s.byIat); out += buf;
    snprintf(buf, sizeof buf,
             "    vtable'siz somut zincir      : %zu\n", s.byConc); out += buf;
    out += "  -- kalanlar (dürüst neden etiketleri) --\n";
    snprintf(buf, sizeof buf,
             "    coklu aday (tekil tahmin yok): %zu\n", s.unMultiCand); out += buf;
    snprintf(buf, sizeof buf,
             "    kanit yok (heap/param alici) : %zu\n", s.unNoProof); out += buf;
    snprintf(buf, sizeof buf,
             "    tier-3 pencere yetersiz      : %zu\n", s.unTier3Win); out += buf;
    out += "  not: 'tier-3 pencere yetersiz' = unicorn da denendi ama tohum/yol\n";
    out += "       yok — alici statik kanit tasimiyor (heap/parametre); bu\n";
    out += "       grubun buyuk cogunlugu kanit-yok sinifidir\n";
}

// ----------------------------------------------------------------------------
// tek dolaylı çağrıyı çöz
// ----------------------------------------------------------------------------
DevirtPro::Result DevirtPro::Resolve(u64 callAddr) {
    Result r;
    const FuncInfo* f = az_.FunctionAt(callAddr);
    if (!f) return r;
    auto* ins = az_.InstructionsOf(f->start);
    if (!ins) return r;
    EvalFunction(f->start, *ins, nullptr, callAddr, &r);

    // neden çözülemedi / çözüldü özeti
    if (r.resolved) {
        // v8.1: kanıt MEKANİZMASINA göre dürüst etiket (kırılım istatistiği)
        if (r.isImport) {
            r.why = "IAT import cagrisi (dll.api)";   // EvalFunction yazdı
        } else if (r.vftVa && !r.className.empty()) {
            const char* kanit =
                r.proofKind == "atlas" ? "atlas inversiyonu (CHA)"
                : r.proofKind == "init" ? "WinInit init-anlik-goruntusu (Tier-5a)"
                                       : "kurucu vtable-saklama kaniti";
            r.why = r.className + " vftable[" + std::to_string(r.slot) +
                    "] (" + kanit + ")";
        } else if (r.proofKind == "init") {
            r.why = "WinInit init-anlik-goruntusu (Tier-5a) — vtable'siz somut zincir";
        } else {
            r.why = "pencere degerlendiricisi: zincir kapandi (vtable'siz somut)";
        }
        char head[96];
        snprintf(head, sizeof head, "  0x%llx: hedef = 0x%llx",
                 (unsigned long long)callAddr, (unsigned long long)r.target);
        r.trace.push_back(head);
        r.trace.push_back("  call -> " + r.name + "  [STATIK COZUM]");
    } else if (!r.candidates.empty()) {
        r.why = "coklu aday (dürüst sanal kaldi)";
    } else if (r.why.empty()) {
        // v8.1: çözülemeyenlerin de dürüst bir NEDENİ olur — kırılımda
        // "kanıt yok" kategorisi: alıcı heap'te/parametrede, zincirde tek
        // somut değer üreten statik kanıt yok (yanlış tahmin YASAK)
        r.why = "kanit yok (alici heap/parametre — statik kanit uretilemedi)";
    }
    // v8: tier-1 çözemediyse TIER-3 (Unicorn tohumlu pencere emülasyonu)
    if (!r.resolved) {
        Result r3;
        if (EmuResolve(callAddr, r3)) {
            r3.trace.insert(r3.trace.begin(),
                            std::string("  tier-1 pencere yetersiz — tier-3'e dusuldu"));
            return r3;
        }
        // tier-3 aday listesi ürettiyse dürüst göster
        if (!r3.candidates.empty() && r.candidates.empty())
            return r3;
        // v8.1: tier-3'ün dürüst başarısızlık nedeni (pencereye ulaşamadı
        // vs.) çözülemeyen kırılımında görünsün
        if (r3.why.rfind("tier-3:", 0) == 0 && r.why.rfind("tier-3", 0) != 0)
            r.why = r3.why;
    }
    return r;
}

// ----------------------------------------------------------------------------
// raporlar
// ----------------------------------------------------------------------------
void DevirtPro::DumpStatics(std::string& out) const {
    char buf[160];
    out += "== DEVRIT-PRO: STATIK NESNE KANIT TABLOSU ==\n";
    for (auto& [s, of] : statics_) {
        if (of.vptrCand.empty()) continue;
        snprintf(buf, sizeof buf,
                 "  statik 0x%llx: %zu yazici, vptr kanitlari:",
                 (unsigned long long)s, of.writers.size());
        out += buf;
        for (auto& [off, vfts] : of.vptrCand) {
            std::set<u64> uniq(vfts.begin(), vfts.end());
            snprintf(buf, sizeof buf, " [+0x%llx] =", (unsigned long long)off);
            out += buf;
            for (u64 v : uniq) {
                const RttiClass* rc = rtti_.ByVftable(v);
                snprintf(buf, sizeof buf, " 0x%llx(%s)",
                         (unsigned long long)v, rc ? rc->name.c_str() : "?");
                out += buf;
            }
        }
        out += "\n";
        for (u64 w : of.writers) {
            snprintf(buf, sizeof buf, "      yazici: 0x%llx (%s)\n",
                     (unsigned long long)w, az_.NameFor(w).c_str());
            out += buf;
        }
    }
}

void DevirtPro::DumpResolved(std::string& out) const {
    char buf[192];
    snprintf(buf, sizeof buf,
             "== DEVRIT-PRO: %zu cagri statik cozuldu (toplam dolayli icinde) ==\n",
             (unsigned long long)ResolvedCount());
    out += buf;
    for (auto& [a, r] : results_) {
        if (r.resolved) {
            snprintf(buf, sizeof buf,
                     "  0x%llx -> %-40s  (%s)\n",
                     (unsigned long long)a, r.name.c_str(), r.why.c_str());
            out += buf;
        } else if (!r.candidates.empty()) {
            out += "  0x";
            char ab[32]; snprintf(ab, sizeof ab, "%llx", (unsigned long long)a);
            out += ab;
            out += " -> sanal kaldi, adaylar:";
            for (auto& n : r.candidateNames) out += " " + n + ",";
            out += "\n";
        }
    }
}

} // namespace gt
