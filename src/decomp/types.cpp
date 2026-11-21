// ============================================================================
//  i4M GodTier Engine — decomp/types.cpp
//  TypeInferer: iki fazlı global tip analizi (gövde taraması + çağrı grafiği
//  yayılımı + union-find struct geri kazanımı).
// ============================================================================
#include "decomp/types.h"
#include "core/log.h"
#include "core/util.h"
#include <algorithm>
#include <cstdio>
#include <cctype>

namespace gt {

// ----------------------------------------------------------------------------
// Operand ayrıştırma yardımcıları (Capstone Intel sözdizimi)
// ----------------------------------------------------------------------------
namespace {

const std::map<std::string, std::string>& RegParents() {
    static const std::map<std::string, std::string> m = {
        {"al","rax"},{"cl","rcx"},{"dl","rdx"},{"bl","rbx"},
        {"ax","rax"},{"cx","rcx"},{"dx","rdx"},{"bx","rbx"},
        {"eax","rax"},{"ecx","rcx"},{"edx","rdx"},{"ebx","rbx"},
        {"esp","rsp"},{"ebp","rbp"},
        {"spl","rsp"},{"bpl","rbp"},{"sil","rsi"},{"dil","rdi"},
        {"esi","rsi"},{"edi","rdi"},
        {"r8d","r8"},{"r9d","r9"},{"r10d","r10"},{"r11d","r11"},
        {"r12d","r12"},{"r13d","r13"},{"r14d","r14"},{"r15d","r15"},
        {"r8b","r8"},{"r9b","r9"},{"r10b","r10"},{"r11b","r11"},
        {"r12b","r12"},{"r13b","r13"},{"r14b","r14"},{"r15b","r15"},
    };
    return m;
}

std::string CanonReg(const std::string& r) {
    if (r.empty()) return r;
    auto& m = RegParents();
    auto it = m.find(r);
    if (it != m.end()) return it->second;
    return r;   // rax..r15, rsp, rbp, rsi, rdi, xmmN
}

std::vector<std::string> SplitOps(const std::string& s) {
    std::vector<std::string> out;
    int depth = 0; std::string cur;
    for (char c : s) {
        if (c == '[') depth++;
        if (c == ']') depth--;
        if (c == ',' && depth == 0) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    for (auto& x : out) x = Trim(x);
    return out;
}

struct MemOp {
    bool isMem = false;
    std::string base;
    std::string index;
    u32 scale = 1;
    i64 disp = 0;
    u32 size = 0;
};

bool IsNumberTok(const std::string& t) {
    if (t.empty()) return false;
    if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0)
        return t.size() > 2 && t.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
    return isdigit((unsigned char)t[0]) &&
           t.find_first_not_of("0123456789") == std::string::npos;
}

MemOp ParseMem(const std::string& op) {
    MemOp m;
    size_t lb = op.find('[');
    if (lb == std::string::npos) return m;
    m.isMem = true;
    std::string pre = Trim(op.substr(0, lb));
    if (pre.find("xmmword") != std::string::npos || pre.find("tbyte") != std::string::npos ||
        pre.find("ymmword") != std::string::npos) m.size = 16;
    else if (pre.find("qword") != std::string::npos) m.size = 8;
    else if (pre.find("dword") != std::string::npos) m.size = 4;
    else if (pre.find("word") != std::string::npos) m.size = 2;
    else if (pre.find("byte") != std::string::npos) m.size = 1;

    size_t rb = op.rfind(']');
    if (rb == std::string::npos) return m;
    std::string inner = op.substr(lb + 1, rb - lb - 1);

    std::vector<std::string> toks;
    std::string cur;
    for (char c : inner) {
        if (c == '+' || c == '-' || c == '*') {
            if (!cur.empty()) { toks.push_back(cur); cur.clear(); }
            toks.push_back(std::string(1, c));
        } else if (c == ' ') {
            if (!cur.empty()) { toks.push_back(cur); cur.clear(); }
        } else cur += c;
    }
    if (!cur.empty()) toks.push_back(cur);

    int sign = 1;
    std::string pendingIdx;
    for (size_t ti = 0; ti < toks.size(); ti++) {
        const std::string& t = toks[ti];
        if (t == "+") { sign = 1; continue; }
        if (t == "-") { sign = -1; continue; }
        if (t == "*") continue;   // olcek bir sonraki sayi token'inda
        if (IsNumberTok(t)) {
            // onceki token '*' idiyse ve bir indeks adayi varsa: SCALE
            bool scaleMode = ti > 0 && toks[ti - 1] == "*";
            if (scaleMode && !pendingIdx.empty()) {
                m.index = pendingIdx;
                m.scale = (u32)strtoull(t.c_str(), 0, 0);
                pendingIdx.clear();
            } else {
                m.disp += sign * (i64)strtoull(t.c_str(), 0, 0);
                sign = 1;
            }
            continue;
        }
        // register: bir sonraki token '*' ise INDEKSTIR (base degil)
        bool starNext = (ti + 1 < toks.size() && toks[ti + 1] == "*");
        if (starNext) {
            if (m.index.empty() && pendingIdx.empty()) pendingIdx = CanonReg(t);
            continue;
        }
        if (m.base.empty() && pendingIdx.empty()) m.base = CanonReg(t);
        else if (m.index.empty() && pendingIdx.empty()) pendingIdx = CanonReg(t);
    }
    if (m.index.empty() && !pendingIdx.empty())
        m.index = pendingIdx;           // scale'siz indeks
    return m;
}

bool IsRegTok(const std::string& s) {
    if (s.empty() || s.find(' ') != std::string::npos || s.find('[') != std::string::npos)
        return false;
    if (s.rfind("xmm", 0) == 0 || s.rfind("ymm", 0) == 0) return true;
    if (s.size() > 5) return false;
    for (char c : s)
        if (!islower((unsigned char)c) && !isdigit((unsigned char)c)) return false;
    return s[0] >= 'a' && s[0] <= 'z';
}

struct LibcSig { int nArgs; const char* kinds; ArgKind ret; bool variadic; bool noreturn; };
const std::map<std::string, LibcSig>& LibcSigs() {
    static const std::map<std::string, LibcSig> m = {
        {"printf",            {1, "p",     ArgKind::Int,  true,  false}},
        {"puts",              {1, "p",     ArgKind::Int,  false, false}},
        {"memset",            {3, "pii",   ArgKind::Ptr,  false, false}},
        {"memcpy",            {3, "ppi",   ArgKind::Ptr,  false, false}},
        {"memmove",           {3, "ppi",   ArgKind::Ptr,  false, false}},
        {"strcpy",            {2, "pp",    ArgKind::Ptr,  false, false}},
        {"strncpy",           {3, "ppI",   ArgKind::Ptr,  false, false}},
        {"strlen",            {1, "p",     ArgKind::Int,  false, false}},
        {"strcmp",            {2, "pp",    ArgKind::Int,  false, false}},
        {"malloc",            {1, "i",     ArgKind::Ptr,  false, false}},
        {"calloc",            {2, "ii",    ArgKind::Ptr,  false, false}},
        {"realloc",           {2, "pi",    ArgKind::Ptr,  false, false}},
        {"free",              {1, "p",     ArgKind::None, false, false}},
        {"exit",              {1, "i",     ArgKind::None, false, true }},
        {"abort",             {0, "",      ArgKind::None, false, true }},
        {"_exit",             {1, "i",     ArgKind::None, false, true }},
        {"__libc_start_main", {5, "ipppp", ArgKind::None, false, true }},
        {"fwrite",            {4, "pipp",  ArgKind::Int,  false, false}},
        {"scanf",             {1, "p",     ArgKind::Int,  true,  false}},
        {"sscanf",            {2, "pp",    ArgKind::Int,  true,  false}},
        {"sprintf",           {2, "pp",    ArgKind::Int,  true,  false}},
        {"snprintf",          {3, "ipp",   ArgKind::Int,  true,  false}},
        {"fprintf",           {2, "pp",    ArgKind::Int,  true,  false}},
        {"atoi",              {1, "p",     ArgKind::Int,  false, false}},
        {"atol",              {1, "p",     ArgKind::Int,  false, false}},
        {"__cxa_finalize",    {1, "p",     ArgKind::None, false, false}},
    };
    return m;
}

} // anonim

// ----------------------------------------------------------------------------
// FuncSig yardımcıları
// ----------------------------------------------------------------------------
const char** FuncSig::ArgRegs(bool elf) {
    static const char* sysv[6]  = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    static const char* win64[4] = {"rcx", "rdx", "r8", "r9"};
    return elf ? sysv : win64;
}

std::string FuncSig::SignatureLine() const {
    // DWARF/PDB kanıtı varsa gerçek tipler ve adlar
    std::string ret = !retTypeName.empty() ? retTypeName
                    : retKind == ArgKind::Float ? "double"
                    : retKind == ArgKind::None  ? "void" : "int";
    std::string s = ret + " " + name + "(";
    for (int i = 0; i < nArgs; i++) {
        if (i) s += ", ";
        std::string tn;
        if (fromDwarf && !argTypeNames[i].empty()) tn = argTypeNames[i];
        else if (!argStructNames[i].empty()) tn = argStructNames[i] + " *";
        else if (argStruct[i] > 0) {
            tn = "struct_" + std::to_string(argStruct[i]) + " *";
        }
        else if (argKinds[i] == ArgKind::Float) tn = "double";
        else if (argKinds[i] == ArgKind::Ptr)
            tn = (argStride[i] == 4) ? "int *" : "void *";
        else tn = "int";
        s += tn;
        std::string an = (fromDwarf && !argNames[i].empty()) ? argNames[i]
                       : "a" + std::to_string(i + 1);
        s += " " + an;
    }
    if (variadic) s += nArgs ? ", ..." : "...";
    s += ")";
    return s;
}

const StructMember* StructInfo::MemberAt(u64 off) const {
    auto it = members.find(off);
    return it == members.end() ? nullptr : &it->second;
}

const StructMember* StructInfo::MemberContaining(u64 off, u64* idxOut) const {
    if (auto* m = MemberAt(off)) {
        if (idxOut) *idxOut = 0;
        return m;
    }
    for (auto& [moff, m] : members) {
        if (!m.isArray || !m.stride) continue;
        u64 span = m.stride * (m.arrayLen ? m.arrayLen : 4096);
        if (off > moff && off < moff + span && (off - moff) % m.stride == 0) {
            if (idxOut) *idxOut = (off - moff) / m.stride;
            return &m;
        }
    }
    return nullptr;
}

// v6: DWARF tip metni "int [8]" -> eleman tipi "int" (dizi boyutu
// isArray/arrayLen alanlarında taşınır; Decl'de çift [8][8] olmasın)
static std::string StripArraySuffix(const std::string& tn) {
    if (!tn.empty() && tn.back() == ']') {
        size_t ob = tn.rfind('[');
        if (ob != std::string::npos) {
            std::string s = tn.substr(0, ob);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
            return s;
        }
    }
    return tn;
}

std::string StructInfo::Decl() const {
    std::string s = "struct " + name + " {";
    for (auto& [off, m] : members) {
        s += "\n    ";
        if (!m.typeName.empty()) s += m.typeName;
        else if (m.isString) s += "char";
        else if (m.kind == ArgKind::Float) s += "float";
        else if (m.kind == ArgKind::Ptr) s += "void *";
        else s += "int";
        s += " ";
        s += m.name.empty() ? ("field_" + ToHex(off)) : m.name;
        if (m.isArray) {
            s += "[";
            if (m.arrayLen) s += std::to_string(m.arrayLen);
            s += "]";
        }
        s += ";   // +0x" + ToHex(off);
    }
    s += "\n};";
    return s;
}

// ----------------------------------------------------------------------------
// Faz A: gövde taraması (köken/provenance izleme)
// ----------------------------------------------------------------------------
TypeInferer::BodyInfo TypeInferer::ScanBody(u64 funcVa) {
    BodyInfo bi;
    const std::vector<Ins>* insPtr = az_.InstructionsOf(funcVa);
    if (!insPtr) return bi;

    const bool isElf = az_.Bin().FormatName().find("ELF") != std::string::npos;
    const int nArgRegs = isElf ? 6 : 4;
    const char** argRegs = FuncSig::ArgRegs(isElf);

    struct Prov {
        bool valid = false; bool isLocal = false;
        int arg = -1;
        i64 disp = 0;       // local nesne anahtarı (rbp-göreli taban veya RSP_OBJ)
        u64 off = 0;        // taban üstü ofset
    };
    static const i64 RSP_OBJ = 0x1000000ll;   // "mov rdi, rsp" nesnesi için anahtar
    std::map<std::string, Prov> reg;
    std::map<i64, Prov> slot;
    std::set<i64> objects;
    u64 immArgs[6] = {0, 0, 0, 0, 0, 0};
    int argState[6] = {0, 0, 0, 0, 0, 0};   // 0=bilinmiyor 1=canli 2=olu
    bool curEaxWritten = false, curXmm0Written = false;
    // sanal çağrı kanıtı: vptr yüklenen reg -> nesne kökeni,
    // metot işaretçisi yüklenen reg -> (nesne kökeni, slot)
    std::map<std::string, Prov> vptrReg;
    std::map<std::string, std::pair<Prov, int>> methReg;

    auto argRegIdx = [&](const std::string& canon) -> int {
        for (int i = 0; i < nArgRegs; i++)
            if (canon == argRegs[i]) return i;
        return -1;
    };
    // arg register'lari isleme arg olarak girer; dokunulmamissa sentetik
    // Arg(i) kokeni gecerli, dokunulduysa gercek haritadan bakilir.
    std::set<std::string> argTouched;
    std::map<std::string, std::pair<Prov, u32>> regIdx;


    auto setReg = [&](const std::string& r, Prov p) {
        if (!IsRegTok(r)) return;
        argTouched.insert(CanonReg(r));
        reg[CanonReg(r)] = p;
    };
    auto getReg = [&](const std::string& r) -> Prov {
        if (!IsRegTok(r)) return Prov{};
        std::string root = CanonReg(r);
        int ai = argRegIdx(root);
        if (ai >= 0 && !argTouched.count(root)) {
            Prov p; p.valid = true; p.isLocal = false; p.arg = ai;
            return p;
        }
        auto it = reg.find(root);
        return it == reg.end() ? Prov{} : it->second;
    };
    auto record = [&](bool isLocal, i64 key, u64 off, u32 size, bool indexed, u32 stride) {
        if (getenv("GODTIER_TI_DEBUG"))
            std::printf("[REC] %s%lld off=%llu sz=%u idx=%d stride=%u\n",
                        isLocal ? "L" : "A", (long long)key,
                        (unsigned long long)off, size, (int)indexed, stride);
        SiteData& sd = isLocal ? bi.localSites[key] : bi.argSites[(int)key];
        sd.accesses.push_back({off, size, ArgKind::Int, false, indexed, stride});
    };

    // [rbp+D] (index'li) veya [rsp+D] erişimini nesneye bağla
    auto handleFrameMem = [&](MemOp& m, bool write) -> bool {
        if (m.base == "rbp") {
            if (m.index.empty()) return false;   // düz yerel değişken
            i64 D = m.disp;
            i64 best = 0; bool found = false;
            for (i64 B : objects)
                if (B <= D && D - B < 256 && (!found || B > best)) { best = B; found = true; }
            if (found) {
                record(true, best, (u64)(D - best), m.size ? m.size : 4, true, m.scale);
                return true;
            }
            return false;
        }
        if (m.base == "rsp") {
            // rbp'siz çerçeve (O2): nesne [rsp+0]'da; tüm erişimleri ona bağla
            record(true, RSP_OBJ, (u64)m.disp, m.size ? m.size : 4,
                   !m.index.empty(), m.scale);
            (void)write;
            return true;
        }
        return false;
    };

    // nesne tabanlari (lea r,[rbp-D] / mov r,rsp) ONCE kesfedilmeli;
    // yoksa "mov [rbp-0x50], 7" yazimi taban bilinmeden gecer.
    for (const Ins& x0 : *insPtr) {
        if (x0.mnemonic == "lea") {
            MemOp m0 = ParseMem(x0.opStr);
            if (m0.base == "rbp" && m0.index.empty() && m0.disp)
                objects.insert(m0.disp);
        } else if (x0.mnemonic == "mov") {
            auto o0 = SplitOps(x0.opStr);
            if (o0.size() == 2 && o0[0] == "rdi" && o0[1] == "rsp")
                objects.insert(RSP_OBJ);
        }
    }

    for (const Ins& x : *insPtr) {
        const std::string& mn = x.mnemonic;
        auto ops = SplitOps(x.opStr);

        // --- arg canlılığı: TANIM ÖNCE KULLANIM ---
        // arg reg ilk kez YAZILIYorsa ölü (scratch), ilk kez OKUNUYORsa canlı.
        {
            bool writesOp1 = (mn == "mov" || mn == "lea" || mn == "movsx" ||
                              mn == "movzx" || mn == "movsxd" || mn == "pop" ||
                              mn.rfind("set", 0) == 0 || mn.rfind("cmov", 0) == 0 ||
                              mn == "xor" || mn == "imul" || mn == "add" ||
                              mn == "sub" || mn == "and" || mn == "or" ||
                              mn == "shl" || mn == "shr" || mn == "sar" ||
                              mn == "neg" || mn == "not" || mn == "inc" ||
                              mn == "dec" || mn == "cdqe" || mn == "movsxd" ||
                              mn == "movq" || mn == "movd");
            for (int i = 0; i < nArgRegs; i++) {
                if (argState[i] != 0) continue;   // 0=bilinmiyor 1=canli 2=olu
                const std::string& root = argRegs[i];
                for (size_t k = 0; k < ops.size(); k++) {
                    const std::string& o = ops[k];
                    if (o.find('[') != std::string::npos) {
                        MemOp m = ParseMem(o);
                        if (m.base == root || m.index == root) { argState[i] = 1; break; }
                        continue;
                    }
                    if (CanonReg(o) != root) continue;
                    bool isWrite = (k == 0) && writesOp1 && ops.size() >= 2 && ops[0] != ops[1];
                    if (!isWrite) { argState[i] = 1; break; }
                    argState[i] = 2;   // tanım: artık ölü
                    break;
                }
            }
        }

        if (mn == "ret") {
            // dönüş kanıtı: ret anında eax/xmm0 yazılmış mı?
            if (curEaxWritten) bi.writesEax = true;
            if (curXmm0Written) bi.writesXmm0 = true;
            break;
        }
        if (ops.empty()) continue;

        // --- çağrı kenarı ---
        if (mn == "call") {
            // sanal çağrı kanıtı: call rC (rC = vtable[slot]) veya call [rA + K]
            if (x.isIndirect && !ops.empty()) {
                if (IsRegTok(ops[0])) {
                    auto mit = methReg.find(CanonReg(ops[0]));
                    if (mit != methReg.end() && mit->second.first.valid) {
                        VirtCall vc;
                        vc.slot = mit->second.second;
                        vc.isArg = !mit->second.first.isLocal;
                        vc.argIdx = mit->second.first.arg;
                        vc.localDisp = mit->second.first.disp;
                        vc.callReg = CanonReg(ops[0]);
                        vc.callerVa = funcVa;
                        virtCalls_[x.addr] = vc;
                    }
                } else if (ops[0].find('[') != std::string::npos) {
                    MemOp mm = ParseMem(ops[0]);
                    auto vit = vptrReg.find(mm.base);
                    if (vit != vptrReg.end() && vit->second.valid) {
                        VirtCall vc;
                        vc.slot = (int)(mm.disp / 8);
                        vc.isArg = !vit->second.isLocal;
                        vc.argIdx = vit->second.arg;
                        vc.localDisp = vit->second.disp;
                        vc.callerVa = funcVa;
                        virtCalls_[x.addr] = vc;
                    }
                }
            }
            CallEdge ce;
            ce.callAddr = x.addr;
            ce.callee = x.isIndirect ? 0 : x.target;
            for (int k = 0; k < nArgRegs; k++) {
                CallEdge::Prov p;
                Prov pv = getReg(argRegs[k]);
                p.valid = pv.valid; p.isLocal = pv.isLocal;
                p.localDisp = pv.disp; p.srcArg = pv.arg; p.off = pv.off;
                ce.argProv.push_back(p);
                ce.argIsFloat.push_back(false);
                ce.argImm.push_back(immArgs[k]);
            }
            bi.calls.push_back(ce);
            for (int k = 0; k < nArgRegs; k++) {
                reg.erase(argRegs[k]);
                argTouched.erase(argRegs[k]);
            }
            memset(immArgs, 0, sizeof(immArgs));
            curEaxWritten = false;   // çağrı dönüş değerini ezer
            curXmm0Written = false;
            continue;
        }

        // --- veri taşımaları ---
        if (mn == "mov" || mn == "movsx" || mn == "movzx" || mn == "movsxd") {
            const std::string& dst = ops[0];
            const std::string& src = ops.size() > 1 ? ops[1] : "";
            int ai = IsRegTok(dst) ? argRegIdx(CanonReg(dst)) : -1;
            if (ai >= 0) immArgs[ai] = 0;

            // ONCE: hedef bellek mi? (mov [mem], reg/imm -> yazma)
            if (dst.find('[') != std::string::npos) {
                MemOp m = ParseMem(dst);
                if (m.base == "rbp" && m.index.empty()) {
                    if (mn == "mov" && ops.size() > 1 && IsRegTok(ops[1])) {
                        Prov pv = getReg(ops[1]);
                        if (pv.valid) slot[m.disp] = pv;
                    }
                    if (mn == "mov" && objects.count(m.disp))
                        record(true, m.disp, 0, m.size ? m.size : 4, false, 1);
                } else if ((m.base == "rbp" || m.base == "rsp") && !m.index.empty()) {
                    handleFrameMem(m, true);
                } else if (!m.base.empty()) {
                    Prov pv = getReg(m.base);
                    if (pv.valid) {
                        u64 off = pv.off + (u64)m.disp;
                        if (m.size == 0) m.size = 4;
                        SiteData& sd = pv.isLocal ? bi.localSites[pv.disp]
                                                  : bi.argSites[pv.arg];
                        sd.accesses.push_back({off, m.size, ArgKind::Int, true,
                                               !m.index.empty(), m.scale});
                    }
                }
                continue;
            }

            if (!src.empty() && src.find('[') != std::string::npos) {
                MemOp m = ParseMem(src);
                if (m.base == "rbp" && m.index.empty()) {
                    auto it = slot.find(m.disp);
                    setReg(dst, it != slot.end() ? it->second : Prov{});
                } else if ((m.base == "rbp" || m.base == "rsp") && handleFrameMem(m, false)) {
                    setReg(dst, Prov{});
                } else if (!m.base.empty()) {
                    Prov pv = getReg(m.base);
                    // vptr yükleme: mov rX, [nesne] (8 bayt, ofset 0)
                    if (pv.valid && m.disp == 0 && (m.size == 8 || m.size == 0))
                        vptrReg[CanonReg(dst)] = pv;
                    // metot yükleme: mov rC, [vptrReg + K]
                    {
                        auto vit = vptrReg.find(m.base);
                        if (vit != vptrReg.end() && vit->second.valid &&
                            m.disp >= 0 && m.disp % 8 == 0 &&
                            (m.size == 8 || m.size == 0))
                            methReg[CanonReg(dst)] = {vit->second, (int)(m.disp / 8)};
                    }
                    if (pv.valid) {
                        u64 off = pv.off + (u64)m.disp;
                        if (m.size == 0) m.size = 8;
                        ArgKind kind = (mn == "movss" || mn == "movsd") ? ArgKind::Float : ArgKind::Int;
                        SiteData& sd = pv.isLocal ? bi.localSites[pv.disp]
                                                  : bi.argSites[pv.arg];
                        sd.accesses.push_back({off, m.size, kind, false,
                                               !m.index.empty(), m.scale});
                    } else {
                        auto ii = regIdx.find(CanonReg(m.base));
                        if (ii != regIdx.end() && ii->second.first.valid) {
                            Prov bp = ii->second.first;
                            u64 off2 = bp.off + (u64)m.disp;
                            u32 sz2 = m.size ? m.size : 4;
                            SiteData& sd = bp.isLocal ? bi.localSites[bp.disp]
                                                      : bi.argSites[bp.arg];
                            sd.accesses.push_back({off2, sz2, ArgKind::Int,
                                                   false, true, ii->second.second});
                        }
                    }
                    setReg(dst, Prov{});
                } else setReg(dst, Prov{});
                if (dst == "eax" || dst == "rax") curEaxWritten = true;
                if (dst == "xmm0") curXmm0Written = true;
            } else if (IsRegTok(src)) {
                std::string srcRoot = CanonReg(src);
                if (srcRoot == "rsp") {
                    Prov p; p.valid = true; p.isLocal = true; p.disp = RSP_OBJ;
                    setReg(dst, p);
                    objects.insert(RSP_OBJ);
                } else {
                    setReg(dst, getReg(src));
                }
                if (dst == "eax" || dst == "rax") curEaxWritten = true;
                if (dst == "xmm0") curXmm0Written = true;
            } else {
                setReg(dst, Prov{});
                if (ai >= 0) immArgs[ai] = strtoull(src.c_str(), 0, 0);
                if (dst == "eax" || dst == "rax") curEaxWritten = true;
                if (dst == "xmm0") curXmm0Written = true;
            }
            continue;
        }
        if (mn == "movss" || mn == "movsd" || mn == "movaps" || mn == "movups" ||
            mn == "movdqa" || mn == "movdqu") {
            const std::string& dst = ops[0];
            const std::string& src = ops.size() > 1 ? ops[1] : "";
            if (src.find('[') != std::string::npos) {
                MemOp m = ParseMem(src);
                if ((m.base == "rbp" || m.base == "rsp") && !m.index.empty())
                    handleFrameMem(m, false);
                else if (!m.base.empty()) {
                    Prov pv = getReg(m.base);
                    if (pv.valid) {
                        ArgKind kind = (mn == "movss" || mn == "movsd") ? ArgKind::Float
                                                                        : ArgKind::Int;
                        u64 off = pv.off + (u64)m.disp;
                        if (m.size == 0) m.size = 16;
                        SiteData& sd = pv.isLocal ? bi.localSites[pv.disp]
                                                  : bi.argSites[pv.arg];
                        sd.accesses.push_back({off, m.size, kind, false,
                                               !m.index.empty(), m.scale});
                    }
                }
            }
            if (dst == "xmm0") curXmm0Written = true;
            continue;
        }
        if (mn == "lea") {
            const std::string& dst = ops[0];
            int ai = IsRegTok(dst) ? argRegIdx(CanonReg(dst)) : -1;
            if (ai >= 0) immArgs[ai] = 0;
            MemOp m = ParseMem(ops.size() > 1 ? ops[1] : "");
            if (m.base == "rbp" && m.index.empty()) {
                Prov p; p.valid = true; p.isLocal = true; p.disp = m.disp;
                setReg(dst, p);
                if (m.disp != 0) objects.insert(m.disp);
            } else if (m.base == "rsp") {
                Prov p; p.valid = true; p.isLocal = true; p.disp = RSP_OBJ;
                p.off = (u64)m.disp;
                setReg(dst, p);
                objects.insert(RSP_OBJ);
            } else if (!m.base.empty() && !m.index.empty() && m.base != "rip") {
                Prov pv = getReg(m.base);
                if (pv.valid) regIdx[CanonReg(dst)] = {pv, m.scale};
                setReg(dst, Prov{});
            } else if (!m.base.empty() && m.index.empty()) {
                Prov pv = getReg(m.base);
                if (pv.valid) { pv.off += (u64)m.disp; setReg(dst, pv); }
                else setReg(dst, Prov{});
            } else {
                if (!m.index.empty())
                    regIdx[CanonReg(dst)] = {Prov{}, m.scale};
                setReg(dst, Prov{});
            }
            continue;
        }
        if (mn == "add" || mn == "sub") {
            const std::string& dst = ops[0];
            const std::string& src = ops.size() > 1 ? ops[1] : "";
            int ai = IsRegTok(dst) ? argRegIdx(CanonReg(dst)) : -1;
            if (ai >= 0) immArgs[ai] = 0;
            if (IsRegTok(dst) && !src.empty() && IsRegTok(src)) {
                Prov pvx = getReg(dst);
                auto six = regIdx.find(CanonReg(src));
                if (pvx.valid && six != regIdx.end())
                    regIdx[CanonReg(dst)] = {pvx, six->second.second};
                setReg(dst, Prov{});   // ptr + idx -> index, köken kayboldu
            } else if (IsRegTok(dst) && !src.empty()) {
                Prov pv = getReg(dst);
                if (pv.valid) {
                    i64 k = (i64)strtoll(src.c_str(), 0, 0);
                    if (mn == "sub") k = -k;
                    i64 noff = (i64)pv.off + k;
                    if (noff < 0) setReg(dst, Prov{});
                    else { pv.off = (u64)noff; setReg(dst, pv); }
                }
            }
            if (dst == "rax" || dst == "eax") curEaxWritten = true;
            continue;
        }
        if ((mn == "xor" || mn == "pxor") && ops.size() == 2 && ops[0] == ops[1]) {
            setReg(ops[0], Prov{});
            if (ops[0] == "xmm0") curXmm0Written = true;
            continue;
        }
        // xmm0'a deger yazan donusum / float aritmetik
        if (!ops.empty() && ops[0] == "xmm0" &&
            (mn == "cvtsi2ss" || mn == "cvtsi2sd" || mn == "cvtss2sd" ||
             mn == "cvtsd2ss" || mn == "divss" || mn == "divsd" ||
             mn == "mulss" || mn == "mulsd" || mn == "addss" || mn == "addsd" ||
             mn == "subss" || mn == "subsd")) {
            curXmm0Written = true;
            continue;
        }
        if ((mn == "imul" || mn == "and" || mn == "or" || mn == "shl" ||
             mn == "shr" || mn == "sar") && !ops.empty()) {
            const std::string& dst = ops[0];
            int ai = IsRegTok(dst) ? argRegIdx(CanonReg(dst)) : -1;
            if (ai >= 0) immArgs[ai] = 0;
            setReg(dst, Prov{});
            if (dst == "rax" || dst == "eax") curEaxWritten = true;
            continue;
        }

        // --- belleğe yazma ---
        if (!ops.empty() && ops[0].find('[') != std::string::npos &&
            (mn == "mov" || mn == "add" || mn == "sub" || mn == "or" ||
             mn == "and" || mn == "xor" || mn == "movss" || mn == "movsd" ||
             mn == "movaps" || mn == "movups" || mn == "movdqa" || mn == "movdqu")) {
            MemOp m = ParseMem(ops[0]);
            if (m.base == "rbp" && m.index.empty()) {
                if (mn == "mov" && ops.size() > 1 && IsRegTok(ops[1])) {
                    Prov pv = getReg(ops[1]);
                    if (pv.valid) slot[m.disp] = pv;
                }
            } else if ((m.base == "rbp" || m.base == "rsp") && !m.index.empty()) {
                handleFrameMem(m, true);
            } else if (!m.base.empty()) {
                Prov pv = getReg(m.base);
                if (pv.valid) {
                    u64 off = pv.off + (u64)m.disp;
                    if (m.size == 0) m.size = 4;
                    ArgKind kind = (mn == "movss" || mn == "movsd") ? ArgKind::Float
                                                                    : ArgKind::Int;
                    SiteData& sd = pv.isLocal ? bi.localSites[pv.disp]
                                              : bi.argSites[pv.arg];
                    sd.accesses.push_back({off, m.size, kind, true,
                                           !m.index.empty(), m.scale});
                }
            }
            continue;
        }
    }
    // arg canliligi: tanim-once-kullanim sonucunu aktar
    for (int i = 0; i < 6; i++) bi.argAlive[i] = (argState[i] == 1);
    return bi;
}

// ----------------------------------------------------------------------------
// union-find
// ----------------------------------------------------------------------------
int TypeInferer::Find(int x) {
    while (parent_[(size_t)x] != x) {
        parent_[(size_t)x] = parent_[(size_t)parent_[(size_t)x]];
        x = parent_[(size_t)x];
    }
    return x;
}
void TypeInferer::Unite(int a, int b) {
    a = Find(a); b = Find(b);
    if (a != b) parent_[(size_t)b] = a;
}

// ----------------------------------------------------------------------------
// Faz B: global yayılım + struct kurma
// ----------------------------------------------------------------------------
void TypeInferer::Run() {
    sigs_.clear(); structs_.clear(); nodeId_.clear(); parent_.clear();
    agg_.clear(); aggPtrTaken_.clear(); rootToStruct_.clear();
    const bool dbg = getenv("GODTIER_TI_DEBUG") != nullptr;

    // 1) gövdeleri tara
    std::map<u64, BodyInfo> bodies;
    for (auto& [va, f] : az_.Functions()) {
        if (!az_.InstructionsOf(va)) continue;
        bodies[va] = ScanBody(va);
    }
    if (dbg) {
        for (auto& [va, bi] : bodies) {
            std::printf("[TI] %s @0x%llx alive:", az_.NameFor(va).c_str(),
                        (unsigned long long)va);
            for (int i = 0; i < 6; i++) if (bi.argAlive[i]) std::printf(" %d", i);
            std::printf("  eax=%d xmm0=%d", (int)bi.writesEax, (int)bi.writesXmm0);
            for (auto& [a, sd] : bi.argSites) {
                std::printf("\n    arg%d:", a);
                for (auto& x : sd.accesses)
                    std::printf(" [+%llx sz%u %s%s s%u]", (unsigned long long)x.off,
                                x.size, x.kind == ArgKind::Float ? "f" : "i",
                                x.indexed ? "[]" : "", x.stride);
            }
            for (auto& [d, sd] : bi.localSites) {
                std::printf("\n    loc(%lld):", (long long)d);
                for (auto& x : sd.accesses)
                    std::printf(" [+%llx sz%u %s%s s%u]", (unsigned long long)x.off,
                                x.size, x.kind == ArgKind::Float ? "f" : "i",
                                x.indexed ? "[]" : "", x.stride);
            }
            for (auto& ce : bi.calls) {
                std::printf("\n    call 0x%llx:", (unsigned long long)ce.callee);
                for (size_t k = 0; k < ce.argProv.size(); k++) {
                    auto& p = ce.argProv[k];
                    if (p.valid)
                        std::printf(" a%zu=%s%lld+%llu", k, p.isLocal ? "L" : "A",
                                    (long long)(p.isLocal ? p.localDisp : p.srcArg),
                                    (unsigned long long)p.off);
                }
            }
            std::printf("\n");
        }
    }

    // 2) site düğümleri
    auto nodeIdOf = [&](const NodeKey& k) -> int {
        auto it = nodeId_.find(k);
        if (it != nodeId_.end()) return it->second;
        int id = (int)parent_.size();
        parent_.push_back(id);
        nodeId_[k] = id;
        return id;
    };
    for (auto& [va, bi] : bodies) {
        for (auto& [argIdx, sd] : bi.argSites)
            if (!sd.accesses.empty() || sd.ptrTaken)
                nodeIdOf({va, false, argIdx, 0});
        for (auto& [disp, sd] : bi.localSites)
            if (!sd.accesses.empty() || sd.ptrTaken)
                nodeIdOf({va, true, 0, disp});
    }

    // 3) çağrı kenarlarını işle
    for (auto& [va, bi] : bodies) {
        for (auto& ce : bi.calls) {
            std::string calleeName = ce.callee ? az_.NameFor(ce.callee) : "";
            if (calleeName.rfind("sub_", 0) == 0) {
                std::string plt = az_.Bin().PltName(ce.callee);
                if (!plt.empty()) calleeName = plt;
            }
            bool knownLibc = LibcSigs().count(calleeName) != 0;
            const LibcSig* L = knownLibc ? &LibcSigs().at(calleeName) : nullptr;

            for (size_t k = 0; k < ce.argProv.size(); k++) {
                auto& p = ce.argProv[k];
                if (!p.valid) continue;

                auto memberOn = [&](StructMember sm) {
                    int root = Find(p.isLocal ? nodeIdOf({va, true, 0, p.localDisp})
                                              : nodeIdOf({va, false, p.srcArg, 0}));
                    auto& mm = agg_[root];
                    auto e = mm.find(sm.offset);
                    if (e == mm.end()) mm[sm.offset] = sm;
                    else {
                        auto& t = e->second;
                        if (sm.size > t.size) t.size = sm.size;
                        if (sm.kind == ArgKind::Float) t.kind = ArgKind::Float;
                        if (sm.isString) t.isString = true;
                        if (sm.isArray) {
                            t.isArray = true;
                            if (sm.arrayLen > t.arrayLen) t.arrayLen = sm.arrayLen;
                        }
                    }
                };

                // memset(hedef+off, 0, boyut) -> char dizi üyesi
                if (calleeName == "memset" && k == 0 && ce.argImm.size() > 2) {
                    StructMember sm;
                    sm.offset = p.off; sm.size = 1;
                    sm.isString = (ce.argImm[1] == 0);
                    sm.isArray = true;
                    sm.arrayLen = ce.argImm[2];
                    memberOn(sm);
                    continue;
                }
                // bilinen libc ptr alanına alan adresi geçildi
                bool ptrSlot = false;
                if (L) {
                    if ((int)k < L->nArgs) ptrSlot = (L->kinds[k] == 'p');
                    else if (L->variadic) ptrSlot = true;   // printf %s gibi
                }
                if (ptrSlot && p.off > 0) {
                    StructMember sm;
                    sm.offset = p.off; sm.size = 8; sm.kind = ArgKind::Ptr;
                    sm.isString = (calleeName == "strcpy" || calleeName == "printf" ||
                                   calleeName == "puts" || calleeName == "strlen" ||
                                   calleeName == "sprintf" || calleeName == "fprintf");
                    memberOn(sm);
                    continue;
                }

                if (p.off == 0) {
                    // aynı nesne: çağıran <-> çağrılan arg'ı birleştir
                    int calleeArgNode = -1;
                    if (!knownLibc) {
                        auto bit = bodies.find(ce.callee);
                        if (bit != bodies.end() && bit->second.argSites.count((int)k))
                            calleeArgNode = nodeIdOf({ce.callee, false, (int)k, 0});
                    }
                    if (calleeArgNode >= 0) {
                        int callerNode = p.isLocal
                            ? nodeIdOf({va, true, 0, p.localDisp})
                            : nodeIdOf({va, false, p.srcArg, 0});
                        Unite(callerNode, calleeArgNode);
                    }
                } else {
                    // alan adresi: işaretçi alınmış üye
                    if (p.isLocal) {
                        bi.localSites[p.localDisp].ptrTaken = true;
                        aggPtrTaken_[Find(nodeIdOf({va, true, 0, p.localDisp}))] = true;
                    } else {
                        bi.argSites[p.srcArg].ptrTaken = true;
                        aggPtrTaken_[Find(nodeIdOf({va, false, p.srcArg, 0}))] = true;
                    }
                    StructMember sm;
                    sm.offset = p.off; sm.size = 8; sm.kind = ArgKind::Ptr;
                    memberOn(sm);
                    // (ptr, sabit) kalıbı -> dizi uzunluğu ipucu
                    if (k + 1 < ce.argProv.size() && ce.argImm[k + 1] > 0 &&
                        ce.argImm[k + 1] < 4096) {
                        int root = Find(p.isLocal ? nodeIdOf({va, true, 0, p.localDisp})
                                                  : nodeIdOf({va, false, p.srcArg, 0}));
                        auto e = agg_[root].find(p.off);
                        if (e != agg_[root].end()) {
                            e->second.isArray = true;
                            if (e->second.arrayLen < ce.argImm[k + 1])
                                e->second.arrayLen = ce.argImm[k + 1];
                        }
                    }
                }
            }
        }
    }

    // 4) site erişimlerini kümelere akıt
    for (auto& [va, bi] : bodies) {
        auto drain = [&](bool isLocal, int argIdx, i64 disp, SiteData& sd) {
            auto nit = nodeId_.find({va, isLocal, argIdx, disp});
            if (nit == nodeId_.end()) return;
            int root = Find(nit->second);
            auto& mm = agg_[root];
            if (sd.ptrTaken) aggPtrTaken_[root] = true;
            for (auto& a : sd.accesses) {
                auto e = mm.find(a.off);
                if (e == mm.end()) {
                    StructMember sm;
                    sm.offset = a.off; sm.size = a.size; sm.kind = a.kind;
                    sm.isArray = a.indexed; sm.stride = a.stride;
                    mm[a.off] = sm;
                } else {
                    auto& sm = e->second;
                    if (a.size > sm.size) sm.size = a.size;
                    if (a.kind == ArgKind::Float) sm.kind = ArgKind::Float;
                    if (a.indexed) { sm.isArray = true; sm.stride = a.stride; }
                }
            }
        };
        for (auto& [argIdx, sd] : bi.argSites)  drain(false, argIdx, 0, sd);
        for (auto& [disp, sd] : bi.localSites)  drain(true, 0, disp, sd);
    }

    if (dbg) {
        for (auto& [root, mm] : agg_) {
            std::printf("[TI-AGG] root %d:", root);
            for (auto& [off, m] : mm)
                std::printf(" [+%llx %s sz%u%s len%u]", (unsigned long long)off,
                            m.kind == ArgKind::Float ? "f" :
                            m.kind == ArgKind::Ptr ? "p" : "i",
                            m.size, m.isArray ? "[]" : "",
                            (unsigned)m.arrayLen);
            std::printf("\n");
        }
    }

    // 5) kümeleri struct/pointer olarak ayır
    std::map<int, std::map<u64, StructMember>> structGroups, ptrGroups;
    for (auto& [root, members] : agg_) {
        // sarmalamış (u64'e taşmış negatif) offset: işaret aritmetiği artığı,
        // gerçek struct üyesi olamaz — kümeyi çıkar
        bool bogus = false;
        for (auto& [off, mm2] : members)
            if (off > 0x10000) { bogus = true; break; }
        if (bogus) continue;
        if (members.size() >= 2) structGroups[root] = members;
        else if (members.size() == 1) ptrGroups[root] = members;
    }
    std::map<u64, int> rootOrder;
    for (auto& [k, id] : nodeId_) {
        int root = Find(id);
        if (!rootOrder.count(root) || k.func < (u64)rootOrder[root]) rootOrder[root] = (int)k.func;
    }
    std::vector<std::pair<u64, int>> ordered;
    for (auto& [root, _] : structGroups)
        ordered.push_back({rootOrder.count(root) ? (u64)rootOrder[root] : (u64)-1, root});
    std::sort(ordered.begin(), ordered.end());
    int sid = 0;
    for (auto& [orderVa, root] : ordered) {
        (void)orderVa;
        StructInfo si;
        si.id = ++sid;
        si.name = "struct_" + std::to_string(sid);
        si.members = structGroups[root];
        structs_.push_back(si);
        rootToStruct_[root] = si.id;
    }

    // 6) imzalar
    for (auto& [va, bi] : bodies) {
        FuncSig fs;
        fs.addr = va;
        fs.name = az_.NameFor(va);
        std::string nm = fs.name;
        if (nm.rfind("sub_", 0) == 0) {
            std::string plt = az_.Bin().PltName(va);
            if (!plt.empty()) nm = plt;
        }
        auto lit = LibcSigs().find(nm);
        if (lit != LibcSigs().end()) {
            auto& L = lit->second;
            fs.nArgs = L.nArgs;
            fs.variadic = L.variadic;
            fs.noreturn = L.noreturn;
            fs.retKind = L.ret;
            for (int i = 0; i < L.nArgs && i < 6; i++) {
                fs.argKinds[i] = L.kinds[i] == 'p' ? ArgKind::Ptr
                               : L.kinds[i] == 'f' ? ArgKind::Float : ArgKind::Int;
            }
            sigs_[va] = fs;
            continue;
        }
        int nAlive = 0;
        for (int i = 0; i < 6; i++) if (bi.argAlive[i]) nAlive = i + 1;
        fs.nArgs = nAlive;
        for (int i = 0; i < nAlive; i++) {
            auto nit = nodeId_.find({va, false, i, 0});
            if (nit == nodeId_.end()) { fs.argKinds[i] = ArgKind::Int; continue; }
            int root = Find(nit->second);
            auto sit = rootToStruct_.find(root);
            if (sit != rootToStruct_.end()) {
                fs.argKinds[i] = ArgKind::Ptr;
                fs.argStruct[i] = sit->second;
                for (auto& s2 : structs_)
                    if (s2.id == sit->second) fs.argStructNames[i] = s2.name;
                continue;
            }
            auto pit = ptrGroups.find(root);
            if (pit != ptrGroups.end()) {
                fs.argKinds[i] = ArgKind::Ptr;
                auto& m = pit->second.begin()->second;
                fs.argStride[i] = m.stride ? m.stride : (m.size ? m.size : 4);
            } else {
                fs.argKinds[i] = ArgKind::Int;
            }
        }
        if (bi.writesXmm0) fs.retKind = ArgKind::Float;
        else if (bi.writesEax) fs.retKind = ArgKind::Int;
        else fs.retKind = ArgKind::None;
        sigs_[va] = fs;
    }

    // 6.5) DWARF struct giydirme (imzalardan ÖNCE: gerçek adlar argStructNames'e
    //      doğru düşsün diye)
    ImportPdbStructs();      // PDB giydirme (öncelikli)
    ImportDwarfStructs();    // DWARF giydirme
    // 7) imzalar (Faz B sonucu + PDB/DWARF zenginleştirme)
    ImportPdbSigs();
    ImportDwarfSigs();
    // 8) vtable veritabanı + sanal çağrı tespiti
    BuildVTables();
    DetectVirtualCalls(bodies);
    // 9) v5: sınıf hiyerarşisi + kurucu vtable-saklama kanıtı (devirtualizasyon)
    BuildClassHierarchy();
}


// ----------------------------------------------------------------------------
// PDB kanalı: MSVC binarylerde struct giydirme + imza zenginleştirme
// (DWARF entegrasyonunun ayna görüntüsü; PDB önceliklidir)
// ----------------------------------------------------------------------------
void TypeInferer::ImportPdbStructs() {
    if (!pdb_) return;
    auto structs = pdb_->Structs();
    if (structs.empty()) return;
    for (auto& si : structs_) {
        if (si.members.empty()) continue;
        // PDB struct'ları: DWARF giydirmesi yapılmamışsa dene
        if (si.fromDwarf) continue;
        const PdbInfo::StructOut* best = nullptr;
        int bestScore = 0;
        for (auto& ps : structs) {
            int score = 0;
            for (auto& [off, m] : si.members)
                for (auto& pm : ps.members)
                    if (pm.offset == off) { score++; break; }
            if (score >= 2 && score >= (int)si.members.size() - 1 && score > bestScore) {
                best = &ps; bestScore = score;
            }
        }
        if (!best) continue;
        si.name = best->name;
        si.fromDwarf = true;   // aynı bayrak: giydirildi
        for (auto& [off, m] : si.members) {
            bool matched = false;
            for (auto& pm : best->members) {
                if (pm.offset != off) continue;
                matched = true;
                m.name = pm.name;
                m.typeName = pm.typeName;
                if (pm.isArray) {
                    m.isArray = true;
                    if (pm.arrayLen) m.arrayLen = pm.arrayLen;
                    if (!m.stride) {
                        const std::string& t = pm.typeName;
                        if (t.find("double") != std::string::npos) m.stride = 8;
                        else if (t.find("float") != std::string::npos) m.stride = 4;
                        else if (t.find("char") == 0) m.stride = 1;
                        else m.stride = 4;
                    }
                }
                if (pm.typeName.find("float") != std::string::npos ||
                    pm.typeName.find("double") != std::string::npos)
                    m.kind = ArgKind::Float;
                if (pm.typeName.find('*') != std::string::npos) m.kind = ArgKind::Ptr;
                if (pm.typeName.find("char") == 0 && pm.isArray) m.isString = true;
                break;
            }
            if (!matched && off == 0 && m.size == 8) {
                m.name = "__vftable";
                m.typeName = "void *";
            }
        }
    }
}

void TypeInferer::ImportPdbSigs() {
    if (!pdb_) return;
    if (getenv("GODTIER_TI_DEBUG"))
        std::printf("[PDB-SIG] calisti: nSigs=%zu nPdbFuncs=%zu\n",
                    sigs_.size(), pdb_->Funcs().size());
    for (auto& [va, fs] : sigs_) {
        const PdbFunc* pf = pdb_->FuncAt(va);
        if (getenv("GODTIER_TI_DEBUG"))
            std::printf("[PDB-SIG] va=%llx pf=%p tidx=%x\n",
                        (unsigned long long)va, (void*)pf, pf ? pf->tidx : 0);
        if (!pf) continue;
        const PdbTypeRec* t = pdb_->PdbTypeAt(pf->tidx);
        if (!t) continue;
        // dönüş tipi
        std::string rv = pdb_->TypeName(t->rvType);
        if (!rv.empty() && rv != "void") {
            fs.retTypeName = rv;
            if (rv.find("float") != std::string::npos || rv.find("double") != std::string::npos)
                fs.retKind = ArgKind::Float;
            else if (rv.find('*') != std::string::npos) fs.retKind = ArgKind::Ptr;
            else fs.retKind = ArgKind::Int;
        } else if (rv == "void") fs.retKind = ArgKind::None;
        // parametreler
        const PdbTypeRec* al = pdb_->PdbTypeAt(t->arglist);
        if (al && al->leaf == 0x1201 && !al->args.empty() && al->args.size() <= 6) {
            size_t start = (t->leaf == 0x1009 && al->args.size() == (size_t)t->nparams + 1) ? 1 : 0;
            int np = (int)(al->args.size() - start);
            if (np > 0 && np <= 6) {
                fs.nArgs = np;
                for (int i = 0; i < np; i++) {
                    std::string tn = pdb_->TypeName(al->args[start + (size_t)i]);
                    fs.argTypeNames[i] = tn;
                    if ((size_t)i < pf->argNames.size())
                        fs.argNames[i] = pf->argNames[i];
                    if (tn.find('*') != std::string::npos) {
                        fs.argKinds[i] = ArgKind::Ptr;
                        if (tn.find("int *") == 0) fs.argStride[i] = 4;
                        else if (tn.find("char *") == 0) fs.argStride[i] = 1;
                        else if (tn.find("double *") == 0) fs.argStride[i] = 8;
                        // struct ptr: geri kazanılan struct adıyla eşle
                        std::string base = tn;
                        size_t sp = base.rfind(" *");
                        if (sp != std::string::npos) {
                            base = base.substr(0, sp);
                            for (auto& s2 : structs_)
                                if (s2.name == base) {
                                    fs.argStruct[i] = s2.id;
                                    fs.argStructNames[i] = s2.name;
                                }
                        }
                    } else if (tn.find("float") != std::string::npos ||
                               tn.find("double") != std::string::npos) {
                        fs.argKinds[i] = ArgKind::Float;
                    } else {
                        fs.argKinds[i] = ArgKind::Int;
                    }
                }
                fs.fromDwarf = true;
            }
        } else if (!pf->argNames.empty()) {
            // tipi olmasa da adlar değerli
            for (size_t i = 0; i < pf->argNames.size() && i < 6; i++)
                if (!pf->argNames[i].empty()) fs.argNames[i] = pf->argNames[i];
        }
    }
}

const FuncSig* TypeInferer::SigOf(u64 funcVa) const {
    auto it = sigs_.find(funcVa);
    return it == sigs_.end() ? nullptr : &it->second;
}

const StructInfo* TypeInferer::StructOfArg(u64 funcVa, int argIdx) const {
    auto it = sigs_.find(funcVa);
    if (it == sigs_.end() || argIdx >= 6) return nullptr;
    int sid = it->second.argStruct[argIdx];
    if (sid <= 0) return nullptr;
    for (auto& s : structs_) if (s.id == sid) return &s;
    return nullptr;
}

const StructInfo* TypeInferer::StructOfLocal(u64 funcVa, i64 frameDisp) const {
    auto nit = nodeId_.find({funcVa, true, 0, frameDisp});
    if (nit == nodeId_.end()) return nullptr;
    int x = nit->second;
    while (parent_[(size_t)x] != x) x = parent_[(size_t)x];
    auto sit = rootToStruct_.find(x);
    if (sit == rootToStruct_.end()) return nullptr;
    for (auto& s : structs_) if (s.id == sit->second) return &s;
    return nullptr;
}

std::string TypeInferer::SignatureLine(u64 funcVa) const {
    auto it = sigs_.find(funcVa);
    if (it == sigs_.end()) return az_.NameFor(funcVa) + "()";
    return it->second.SignatureLine();
}

// ----------------------------------------------------------------------------
// DWARF kanıtıyla giydirme: geri kazanılan struct'lara gerçek üye adları,
// imzalara gerçek parametre adları + tipleri (IDA'nın PDB yüklemesi gibi)
// ----------------------------------------------------------------------------
void TypeInferer::ImportDwarfStructs() {
    if (!dwarfValid_) {
        dwarfValid_ = dwarf_.LoadFromBinary(az_.Bin());
    }
    if (!dwarfValid_) return;

    // --- struct giydirme: offset kümesi örtüşen DWARF struct'ını bul ---
    for (auto& si : structs_) {
        if (si.members.empty()) continue;
        const DwarfStruct* best = nullptr;
        int bestScore = 0;
        auto typeCompatible = [](const StructMember& m, const DwarfMember& dm) {
            // boyut uyumu (dizi üyelerinde serbest) + temel tip uyumu
            if (m.size && dm.byteSize && m.size != dm.byteSize && !dm.isArray) {
                // 8'lik float/double vs 8'lik int ayrımı tip metniyle
            }
            if (m.kind == ArgKind::Float)
                return dm.typeName.find("float") != std::string::npos ||
                       dm.typeName.find("double") != std::string::npos;
            if (m.kind == ArgKind::Ptr)
                return dm.typeName.find('*') != std::string::npos ||
                       dm.isArray;
            return dm.typeName.find('*') == std::string::npos ||
                   dm.isArray;
        };
        for (auto& ds : dwarf_.Structs()) {
            if (ds.members.empty()) continue;
            int score = 0;
            for (auto& [off, m] : si.members)
                for (auto& dm : ds.members)
                    if (dm.offset == off && typeCompatible(m, dm)) { score++; break; }
            // en az 2 ortak offset ve neredeyse tam örtüşme
            if (score >= 2 && score >= (int)si.members.size() - 1 && score > bestScore) {
                best = &ds; bestScore = score;
            }
        }
        // v6: BELİRSİZLİK KORUMASI — aynı skorla birden fazla aday eşitse
        // (ör. 2 üyeli küme hem _IO_FILE hem Ogrenci'ye uyuyorsa) giydirme:
        // dürüst struct_N kalır. Yanlış isim, isimsizlikten kötüdür.
        if (best) {
            int ties = 0;
            for (auto& ds : dwarf_.Structs()) {
                if (ds.members.empty()) continue;
                int score = 0;
                for (auto& [off, m] : si.members)
                    for (auto& dm : ds.members)
                        if (dm.offset == off && typeCompatible(m, dm)) { score++; break; }
                if (score == bestScore) ties++;
            }
            if (ties > 1) best = nullptr;
        }
        if (!best) continue;
        si.name = best->name;
        si.fromDwarf = true;
        for (auto& [off, m] : si.members) {
            bool matched = false;
            for (auto& dm : best->members) {
                if (dm.offset != off) continue;
                matched = true;
                m.name = dm.name;
                m.typeName = StripArraySuffix(dm.typeName);
                if (dm.isArray) {
                    m.isArray = true;
                    if (dm.arrayLen) m.arrayLen = dm.arrayLen;
                    // eleman boyu: tip metninden
                    if (!m.stride) {
                        const std::string& t = dm.typeName;
                        if (t.find("double") != std::string::npos) m.stride = 8;
                        else if (t.find("float") != std::string::npos) m.stride = 4;
                        else if (t.find("char") == 0) m.stride = 1;
                        else if (t.find("short") != std::string::npos) m.stride = 2;
                        else m.stride = 4;
                    }
                }
                if (dm.typeName.find("double") != std::string::npos ||
                    dm.typeName.find("float") != std::string::npos)
                    m.kind = ArgKind::Float;
                if (dm.typeName.find('*') != std::string::npos) m.kind = ArgKind::Ptr;
                if (dm.typeName.find("char") == 0 && dm.isArray) m.isString = true;
                break;
            }
            if (!matched && off == 0 && m.size == 8) {
                m.name = "__vftable";       // C++ sanal tablo işaretçisi
                m.typeName = "void *";
            }
        }
    }

}

// ----------------------------------------------------------------------------
// DWARF kanıtıyla imza zenginleştirme (Faz B imzalarından SONRA)
// ----------------------------------------------------------------------------
void TypeInferer::ImportDwarfSigs() {
    if (!dwarfValid_) return;
    // --- imza zenginleştirme ---
    for (auto& [va, fs] : sigs_) {
        const DwarfFunc* df = dwarf_.FuncCovering(va);
        if (!df) continue;
        // gerçek dönüş tipi
        if (!df->retType.empty()) {
            fs.retTypeName = df->retType;
            if (df->retType.find("float") != std::string::npos ||
                df->retType.find("double") != std::string::npos)
                fs.retKind = ArgKind::Float;
            else if (df->retType.find("void") == 0) fs.retKind = ArgKind::None;
            else if (df->retType.find('*') != std::string::npos) fs.retKind = ArgKind::Ptr;
            else fs.retKind = ArgKind::Int;
        }
        // parametre adları + tipleri
        int np = (int)df->params.size();
        if (np > 0 && np <= 6) {
            fs.nArgs = np;
            for (int i = 0; i < np; i++) {
                fs.argNames[i] = df->params[i].name;
                fs.argTypeNames[i] = df->params[i].typeName;
                // "const const X *" tekrarını temizle
                while (fs.argTypeNames[i].find("const const") != std::string::npos)
                    fs.argTypeNames[i].replace(fs.argTypeNames[i].find("const const"),
                                               11, "const");
                const std::string& t = fs.argTypeNames[i];
                if (t.find('*') != std::string::npos) {
                    fs.argKinds[i] = ArgKind::Ptr;
                    // işaretçi hedefi struct mı? (geri kazanılmış struct adıyla eşle)
                    std::string base = t;
                    size_t st = base.find_first_of(" *");
                    // "const Dikdortgen *" -> "Dikdortgen"
                    size_t sp = base.rfind(" *");
                    if (sp != std::string::npos) {
                        base = base.substr(0, sp);
                        size_t cs = base.rfind("const ");
                        if (cs != std::string::npos) base = base.substr(cs + 6);
                        // v6: AUTHORITATIVE bağlama — parametre tipi DWARF'ta
                        // biliniyorsa heuristik küme bağını DEVRAL. Yanlış FILE /
                        // eksik struct_1 giydirmesi burada biter.
                        if (const DwarfStruct* ds = dwarf_.StructByName(base)) {
                            int sid = EnsureDwarfStruct(ds);
                            if (sid > 0) {
                                fs.argStruct[i] = sid;
                                fs.argStructNames[i] = ds->name;
                            }
                        } else {
                            // v6: DWARF tipi struct-değil işaretçiyse ("const float *",
                            // "char *" ...) heuristik union-find'ın ürettiği sahte
                            // struct_N bağını TEMİZLE — dizi erişimi argStride ile
                            // çözülür (simd_dot'un a/b'si buna örnekti)
                            fs.argStruct[i] = -1;
                            fs.argStructNames[i].clear();
                            for (auto& s2 : structs_)
                                if (s2.name == base && s2.fromDwarf) {
                                    fs.argStruct[i] = s2.id;
                                    fs.argStructNames[i] = s2.name;
                                }
                        }
                    }
                    // v6: "const float *" gibi önekli tiplerde de stride çözülür
                    if (t.find("int *") != std::string::npos) fs.argStride[i] = 4;
                    else if (t.find("float *") != std::string::npos) fs.argStride[i] = 4;
                    else if (t.find("double *") != std::string::npos) fs.argStride[i] = 8;
                    else if (t.find("char *") != std::string::npos) fs.argStride[i] = 1;
                    else if (t.find("short *") != std::string::npos) fs.argStride[i] = 2;
                } else if (t.find("float") != std::string::npos ||
                           t.find("double") != std::string::npos) {
                    fs.argKinds[i] = ArgKind::Float;
                } else if (t.find('[') != std::string::npos) {
                    fs.argKinds[i] = ArgKind::Ptr;   // dizi -> işaretçi çürümesi
                } else {
                    fs.argKinds[i] = ArgKind::Int;
                }
            }
            fs.fromDwarf = true;
        }
    }
}

// ----------------------------------------------------------------------------
// v6: DWARF tanımından AUTHORITATIVE struct kur. Aynı adlı giydirilmiş struct
// varsa onu TAMAMLAR (eksik üyeleri DWARF tanımından doldurur), yoksa yeniden
// kurar. Heuristik kümelerin (struct_N / yanlış FILE) yerini alan kanal budur.
// ----------------------------------------------------------------------------
int TypeInferer::EnsureDwarfStruct(const DwarfStruct* ds) {
    if (!ds || ds->members.empty()) return -1;
    StructInfo* existing = nullptr;
    int maxId = 0;
    for (auto& s : structs_) {
        if (s.id > maxId) maxId = s.id;
        if (s.name == ds->name) existing = &s;
    }
    auto fillFrom = [&](StructMember& m, const DwarfMember& dm) {
        m.name = dm.name;
        m.typeName = StripArraySuffix(dm.typeName);
        if (dm.isArray) {
            m.isArray = true;
            if (dm.arrayLen) m.arrayLen = dm.arrayLen;
            const std::string& t2 = dm.typeName;
            if (!m.stride) {
                if (t2.find("double") != std::string::npos) m.stride = 8;
                else if (t2.find("float") != std::string::npos) m.stride = 4;
                else if (t2.find("char") == 0) m.stride = 1;
                else if (t2.find("short") != std::string::npos) m.stride = 2;
                else m.stride = 4;
            }
        }
        if (dm.typeName.find("double") != std::string::npos ||
            dm.typeName.find("float") != std::string::npos)
            m.kind = ArgKind::Float;
        else if (dm.typeName.find('*') != std::string::npos)
            m.kind = ArgKind::Ptr;
        if (dm.typeName.find("char") == 0 && dm.isArray) m.isString = true;
        if (!m.size) m.size = dm.byteSize ? dm.byteSize : 4;
    };
    if (existing) {
        existing->fromDwarf = true;
        // eksik üyeleri tamamla (tam DWARF tanımı kazanır)
        for (auto& dm : ds->members)
            if (!existing->members.count(dm.offset)) {
                StructMember m;
                m.offset = dm.offset;
                m.size = dm.byteSize ? dm.byteSize : 4;
                m.kind = ArgKind::Int;
                fillFrom(m, dm);
                existing->members[dm.offset] = m;
            } else {
                fillFrom(existing->members[dm.offset], dm);
            }
        return existing->id;
    }
    StructInfo si;
    si.id = maxId + 1;
    si.name = ds->name;
    si.fromDwarf = true;
    for (auto& dm : ds->members) {
        StructMember m;
        m.offset = dm.offset;
        m.size = dm.byteSize ? dm.byteSize : 4;
        m.kind = ArgKind::Int;
        fillFrom(m, dm);
        si.members[dm.offset] = m;
    }
    structs_.push_back(si);
    return si.id;
}

// ----------------------------------------------------------------------------
// vtable veritabanı: "vtable for X" sembolleri + slot okuma
// Itanium ABI: [0]=offset-to-top [1]=typeinfo* [2..]=metot işaretçileri
// ----------------------------------------------------------------------------
void TypeInferer::BuildVTables() {
    vtables_.clear();
    for (auto& sym : az_.Bin().Symbols()) {
        if (sym.name.rfind("vtable for ", 0) != 0) continue;
        VTable vt;
        vt.va = sym.va;
        vt.className = sym.name.substr(11);
        for (int i = 0; i < 24; i++) {
            u64 slotVa = sym.va + 16 + (u64)i * 8;
            u8 raw[8] = {};
            if (!az_.Image().ReadBytes(slotVa, raw, 8)) break;
            u64 target;
            memcpy(&target, raw, 8);
            // PIE: ham değer link-time VA'dir (RELATIVE addend) — geçerli mi?
            if (!az_.FunctionStart(target)) break;
            std::string nm = az_.NameFor(target);
            if (nm.empty()) break;
            vt.methods.push_back(target);
            vt.methodNames.push_back(nm);
        }
        if (!vt.methods.empty()) vtables_.push_back(std::move(vt));
    }
    if (!vtables_.empty())
        LogInfo("vtable: %zu tablo bulundu (Itanium ABI)", vtables_.size());
}

std::string TypeInferer::VirtSlotName(int slot) const {
    // çoğunluk oyu: tüm vtable'larda slot k'nın kısa metot adı
    std::map<std::string, int> votes;
    for (auto& vt : vtables_) {
        if ((size_t)slot >= vt.methodNames.size()) continue;
        std::string n = vt.methodNames[slot];
        size_t cc = n.rfind("::");
        if (cc != std::string::npos) n = n.substr(cc + 2);
        // yıkıcıları atla (D0/D1/D2 varyantları)
        if (!n.empty() && n[0] == '~') continue;
        votes[n]++;
    }
    std::string best; int bestC = 0;
    for (auto& [n, c] : votes) if (c > bestC) { best = n; bestC = c; }
    return best;
}

ArgKind TypeInferer::VirtSlotRet(int slot) const {
    std::string nm = VirtSlotName(slot);
    if (getenv("GODTIER_TI_DEBUG"))
        std::printf("[VRET] slot=%d nm=%s dwarfValid=%d nfuncs=%zu\n",
                    slot, nm.c_str(), (int)dwarfValid_, dwarf_.Funcs().size());
    if (nm.empty()) return ArgKind::Int;
    if (dwarfValid_) {
        for (auto& f : dwarf_.Funcs()) {
            std::string n = f.name;
            size_t cc = n.rfind("::");
            if (cc != std::string::npos) n = n.substr(cc + 2);
            if (n != nm) continue;
            const std::string& t = f.retType;
            if (getenv("GODTIER_TI_DEBUG"))
                std::printf("[VRET] aday f.name=%s ret=%s\n", f.name.c_str(), t.c_str());
            if (t.find("float") != std::string::npos ||
                t.find("double") != std::string::npos) return ArgKind::Float;
            if (t.find('*') != std::string::npos) return ArgKind::Ptr;
            if (t.find("void") == 0) return ArgKind::None;
            if (!t.empty()) return ArgKind::Int;
        }
    }
    return ArgKind::Int;
}

std::string TypeInferer::VirtSlotClasses(int slot) const {
    std::string out;
    for (auto& vt : vtables_) {
        if ((size_t)slot >= vt.methodNames.size()) continue;
        if (!out.empty()) out += ", ";
        out += vt.methodNames[slot];
    }
    return out;
}

// ----------------------------------------------------------------------------
// v5: Sınıf hiyerarşisi (CHA) + kurucu vtable-saklama kanıtı
// ----------------------------------------------------------------------------
void TypeInferer::BuildClassHierarchy() {
    // 1) DWARF kalıtım grafiği: taban -> alt sınıf kümesi
    children_.clear();
    if (dwarfValid_) {
        for (auto& s : dwarf_.Structs())
            for (auto& b : s.bases)
                children_[b].insert(s.name);
        if (!children_.empty())
            LogInfo("CHA: %zu taban sinifi kalitim grafigi kurdu",
                    children_.size());
    }
    // 2) Kurucu vtable-saklama kanıtı (stripped'te de çalışır):
    //    lea rX, [rip+off]  ; off = _ZTV<Class>+0x10
    //    mov [rbp-D], rX    ; yerel nesnenin vptr'si
    //    -> (caller, D) somut sınıf = Class
    vtableStores_.clear();
    std::map<u64, std::string> vptrStoreReg;   // funcVa:reg -> sınıf
    std::map<u64, std::map<std::string, std::pair<i64, std::string>>> pendingLea;
    for (auto& [va, f] : az_.Functions()) {
        auto* ins = az_.InstructionsOf(va);
        if (!ins) continue;
        for (auto& x : *ins) {
            if (x.mnemonic == "lea" && x.memRef) {
                // vtable + 0x10 (offset-to-top + RTTI atlanmış adres)
                const VTable* hit = nullptr;
                for (auto& vt : vtables_) {
                    if (x.memRef == vt.va + 16 || x.memRef == vt.va) { hit = &vt; break; }
                }
                if (!hit) continue;
                auto ops = SplitOps(x.opStr);
                if (ops.size() == 2 && IsRegTok(ops[0]))
                    pendingLea[va][CanonReg(ops[0])] = {0, hit->className};
            } else if (x.mnemonic == "mov") {
                auto ops = SplitOps(x.opStr);
                if (ops.size() != 2 || ops[0].find('[') == std::string::npos) continue;
                MemOp m = ParseMem(ops[0]);
                if (m.base != "rbp" || !m.index.empty() || !IsRegTok(ops[1])) continue;
                auto pit = pendingLea.find(va);
                if (pit == pendingLea.end()) continue;
                auto lit = pit->second.find(CanonReg(ops[1]));
                if (lit != pit->second.end())
                    vtableStores_[{va, m.disp}] = lit->second.second;
            }
        }
    }
    (void)vptrStoreReg;
    if (!vtableStores_.empty())
        LogInfo("devirt: %zu yerel nesnede somut sinif kaniti (vtable saklama)",
                vtableStores_.size());
}

void TypeInferer::CollectDescendants(const std::string& cls,
                                     std::set<std::string>& out) const {
    if (out.count(cls)) return;
    out.insert(cls);
    auto cit = children_.find(cls);
    if (cit == children_.end()) return;
    for (auto& c : cit->second) CollectDescendants(c, out);
}

const TypeInferer::VTable* TypeInferer::VTableOfClass(
    const std::string& className) const {
    for (auto& vt : vtables_)
        if (vt.className == className) return &vt;
    return nullptr;
}

TypeInferer::DevirtResult TypeInferer::TryDevirtualize(u64 callAddr) const {
    DevirtResult R;
    auto it = virtCalls_.find(callAddr);
    if (it == virtCalls_.end()) return R;
    const VirtCall& vc = it->second;
    int slot = vc.slot;

    // ---- Strateji 1: yerel nesne + kurucu vtable kanıtı (stripped dostu) ----
    if (!vc.isArg) {
        auto sit = vtableStores_.find({vc.callerVa, vc.localDisp});
        if (sit != vtableStores_.end()) {
            const VTable* vt = VTableOfClass(sit->second);
            if (vt && (size_t)slot < vt->methods.size()) {
                R.target = vt->methods[slot];
                R.why = "yerel nesne kurucuda vtable saklandi: somut sinif " +
                        sit->second;
                return R;
            }
        }
    }

    // ---- Strateji 2: DWARF CHA (statik tip + alt sınıflar) ----
    if (dwarfValid_ && vc.isArg && vc.callerVa) {
        const DwarfFunc* caller = nullptr;
        for (auto& f : dwarf_.Funcs())
            if (f.hasRange && f.lowPc == vc.callerVa) { caller = &f; break; }
        if (caller && (size_t)vc.argIdx < caller->params.size()) {
            std::string tn = caller->params[vc.argIdx].typeName;
            // "const Tek *" / "Tek *" -> "Tek"
            size_t s = tn.find_first_not_of(" \t");
            if (s == std::string::npos) s = 0;
            tn = tn.substr(s);
            if (tn.rfind("const ", 0) == 0) tn = tn.substr(6);
            size_t e = tn.find('*');
            if (e != std::string::npos) {
                tn = tn.substr(0, e);
                while (!tn.empty() && tn.back() == ' ') tn.pop_back();
            }
            if (!tn.empty()) {
                std::set<std::string> cand;
                CollectDescendants(tn, cand);
                std::set<u64> impls;
                for (auto& c : cand) {
                    const VTable* vt = VTableOfClass(c);
                    if (vt && (size_t)slot < vt->methods.size())
                        impls.insert(vt->methods[slot]);
                }
                if (impls.size() == 1) {
                    R.target = *impls.begin();
                    std::string clsList;
                    for (auto& c : cand) {
                        if (!clsList.empty()) clsList += ", ";
                        clsList += c;
                    }
                    R.why = "CHA: " + tn + "* statik tipi, aday siniflar {" +
                            clsList + "} slot " + std::to_string(slot) +
                            "'da tek impl";
                    return R;
                }
            }
        }
    }

    // ---- Strateji 3: slot tek impl (tüm vtable'lar) — spekülatif ----
    {
        std::set<u64> impls;
        for (auto& vt : vtables_)
            if ((size_t)slot < vt.methods.size())
                impls.insert(vt.methods[slot]);
        if (impls.size() == 1 && !vtables_.empty()) {
            R.target = *impls.begin();
            R.why = "slot " + std::to_string(slot) +
                    " binary capinda tek impl (spekulatif devirt)";
            return R;
        }
    }
    return R;   // çözülemedi: dürüst sanal çağrı kalır
}

// ----------------------------------------------------------------------------
// Sanal çağrı tespiti (gövde taramasında toplanan kalıp kanıtı):
//   mov rA, [obj]        ; vptr yükle
//   mov rC, [rA + K]     ; metot slotu (K = slot*8)
//   call rC              ; sanal çağrı
// ----------------------------------------------------------------------------
void TypeInferer::DetectVirtualCalls(const std::map<u64, BodyInfo>& bodies) {
    (void)bodies;
    // ScanBody zaten virtCalls_ doldurur (aşağıdaki kanıt toplama bloğuna bak);
    // burada yalnızca vtable kanıtıyla zenginleştirme yapılır: slot adı yoksa
    // tespit korunur (isimsiz dürüst gösterim "vfunc_N").
}

const TypeInferer::VirtCall* TypeInferer::VirtCallAt(u64 callAddr) const {
    auto it = virtCalls_.find(callAddr);
    return it == virtCalls_.end() ? nullptr : &it->second;
}

} // namespace gt
