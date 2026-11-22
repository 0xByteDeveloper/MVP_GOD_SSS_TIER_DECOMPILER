// ============================================================================
//  i4M GodTier Engine — decomp/pseudocode.cpp  (v2 — ifade katlama + yapılaştırma)
//
//  Katmanlar:
//   1) TypeInferer (TI) — global imza + struct veritabanı
//   2) FoldEngine    — register dataflow ile tek satır bileşik ifadeler
//   3) Structurer    — while / do-while / if-else / if / goto geri dönüşümleri
//   4) Idiom katlama — magic-number bölme, x - (x/d)*d -> x % d, imm string
// ============================================================================
#include "decomp/pseudocode.h"
#include "core/log.h"
#include "core/util.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <vector>

namespace gt {

namespace {

// ---- ortak operand araçları (types.cpp ile aynı kurallar) -----------------
const std::map<std::string, std::string>& RegParents() {
    static const std::map<std::string, std::string> m = {
        {"al","rax"},{"cl","rcx"},{"dl","rdx"},{"bl","rbx"},
        {"ax","rax"},{"cx","rcx"},{"dx","rdx"},{"bx","rbx"},
        {"eax","rax"},{"ecx","rcx"},{"edx","rdx"},{"ebx","rbx"},
        {"esp","rsp"},{"ebp","rbp"},{"esi","rsi"},{"edi","rdi"},
        {"spl","rsp"},{"bpl","rbp"},{"sil","rsi"},{"dil","rdi"},
        {"r8d","r8"},{"r9d","r9"},{"r10d","r10"},{"r11d","r11"},
        {"r12d","r12"},{"r13d","r13"},{"r14d","r14"},{"r15d","r15"},
        {"r8b","r8"},{"r9b","r9"},{"r10b","r10"},{"r11b","r11"},
        {"r12b","r12"},{"r13b","r13"},{"r14b","r14"},{"r15b","r15"},
    };
    return m;
}
std::string CanonReg(const std::string& r) {
    auto it = RegParents().find(r);
    return it != RegParents().end() ? it->second : r;
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
bool IsNumberTok(const std::string& t) {
    if (t.empty()) return false;
    if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0)
        return t.size() > 2 && t.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
    return isdigit((unsigned char)t[0]) &&
           t.find_first_not_of("0123456789") == std::string::npos;
}
struct MemOp {
    bool isMem = false;
    std::string base, index;
    u32 scale = 1;
    i64 disp = 0;
    u32 size = 0;
};
MemOp ParseMem(const std::string& op) {
    MemOp m;
    size_t lb = op.find('[');
    if (lb == std::string::npos) return m;
    m.isMem = true;
    std::string pre = Trim(op.substr(0, lb));
    if (pre.find("xmmword") != std::string::npos || pre.find("ymmword") != std::string::npos ||
        pre.find("tbyte") != std::string::npos) m.size = 16;
    else if (pre.find("qword") != std::string::npos) m.size = 8;
    else if (pre.find("dword") != std::string::npos) m.size = 4;
    else if (pre.find("word") != std::string::npos) m.size = 2;
    else if (pre.find("byte") != std::string::npos) m.size = 1;
    size_t rb = op.rfind(']');
    if (rb == std::string::npos) return m;
    std::string inner = op.substr(lb + 1, rb - lb - 1);
    std::vector<std::string> toks; std::string cur;
    for (char c : inner) {
        if (c == '+' || c == '-' || c == '*') {
            if (!cur.empty()) { toks.push_back(cur); cur.clear(); }
            toks.push_back(std::string(1, c));
        } else if (c == ' ') { if (!cur.empty()) { toks.push_back(cur); cur.clear(); } }
        else cur += c;
    }
    if (!cur.empty()) toks.push_back(cur);
    int sign = 1;
    std::string pendingIdx;
    for (size_t ti = 0; ti < toks.size(); ti++) {
        const std::string& t = toks[ti];
        if (t == "+") { sign = 1; continue; }
        if (t == "-") { sign = -1; continue; }
        if (t == "*") continue;
        if (IsNumberTok(t)) {
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
        bool starNext = (ti + 1 < toks.size() && toks[ti + 1] == "*");
        if (starNext) {
            if (m.index.empty() && pendingIdx.empty()) pendingIdx = CanonReg(t);
            continue;
        }
        if (m.base.empty() && pendingIdx.empty()) m.base = CanonReg(t);
        else if (m.index.empty() && pendingIdx.empty()) pendingIdx = CanonReg(t);
    }
    if (m.index.empty() && !pendingIdx.empty()) m.index = pendingIdx;
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
// "jl" -> "<" (devam koşulu: geri dönen jcc DOĞRU iken döngü sürer)
bool JccCond(const std::string& mn, const std::string& lhs, const std::string& rhs,
             std::string& out) {
    std::string op;
    if (mn == "je" || mn == "jz") op = "==";
    else if (mn == "jne" || mn == "jnz") op = "!=";
    else if (mn == "jl" || mn == "jnge") op = "<";
    else if (mn == "jle" || mn == "jng") op = "<=";
    else if (mn == "jg" || mn == "jnle") op = ">";
    else if (mn == "jge" || mn == "jnl") op = ">=";
    else if (mn == "ja" || mn == "jnbe") op = ">";
    else if (mn == "jae" || mn == "jnb" || mn == "jnc") op = ">=";
    else if (mn == "jb" || mn == "jnae" || mn == "jc") op = "<";
    else if (mn == "jbe" || mn == "jna") op = "<=";
    else if (mn == "js") { out = lhs + " < 0"; return true; }
    else if (mn == "jns") { out = lhs + " >= 0"; return true; }
    else return false;
    out = lhs + " " + op + " " + rhs;
    return true;
}
// "X + X" -> "2 * X";  "k * X + X" -> "(k+1) * X"
std::string CanonArith(const std::string& a, const std::string& b, const char* op) {
    std::string s = a + " " + op + " " + b;
    if (std::string(op) == "+") {
        if (a == b) return "2 * " + a;
        // "k * X + X"
        size_t p = a.find(" * ");
        if (p != std::string::npos && a.substr(0, p).find_first_not_of("0123456789") == std::string::npos &&
            a.substr(p + 3) == b) {
            int k = atoi(a.substr(0, p).c_str());
            return std::to_string(k + 1) + " * " + b;
        }
    }
    return s;
}
// parantez gerekiyorsa sarmala
std::string Paren(const std::string& e) {
    if (e.find_first_of("+-*/%&|^<>") != std::string::npos) return "(" + e + ")";
    return e;
}
// imm değerinin string'e benzemesi: 0x696c41 -> "Ali"
std::string ImmStringNote(u64 v) {
    if (v == 0 || v > 0xFFFFFFFFull) return "";
    u8 b[4] = {(u8)(v & 0xFF), (u8)((v >> 8) & 0xFF), (u8)((v >> 16) & 0xFF),
               (u8)((v >> 24) & 0xFF)};
    int n = 4;
    while (n > 0 && b[n - 1] == 0) n--;
    if (n < 2) return "";
    std::string s;
    for (int i = 0; i < n; i++) {
        if (b[i] < 0x20 || b[i] >= 0x7F) return "";
        s += (char)b[i];
    }
    return s;
}
// v6: işaretli pretty-print — kaynakta -1 yazılan sabit derleyicide 0xffffffff olur;
// Hex-Rays üslubuyla geri çevir. Yalnız "küçük negatif" görünümlü sabitler
// (0xffffffff -> -1, 0xfffffff5 -> -11); 0x51eb851f gibi büyük değerler ve
// 0x696c41 gibi pozitifler DOKUNULMAZ.
std::string PrettyImm(const std::string& op) {
    if (op.size() < 4 || op.size() > 18 || op[0] != '0' ||
        (op[1] != 'x' && op[1] != 'X')) return op;
    for (size_t i = 2; i < op.size(); i++)
        if (!isxdigit((unsigned char)op[i])) return op;
    // 32-bit görünüm: 0x + <=8 hane, yüksek bit set, |neg| <= 0x10000
    if (op.size() <= 10) {
        u32 v32 = (u32)strtoul(op.c_str(), nullptr, 0);
        if (v32 >= 0x80000000u) {
            i64 neg = (i64)v32 - 0x100000000LL;
            if (neg >= -0x10000LL) return std::to_string(neg);
        }
        return op;
    }
    // 64-bit görünüm (0xffffffffffffffff -> -1)
    u64 v = strtoull(op.c_str(), nullptr, 0);
    if (v > 0x7FFFFFFFFFFFFFFFull) {
        i64 sv = (i64)v;
        if (sv >= -0x10000LL) return std::to_string(sv);
    }
    return op;
}
// magic-number ile sabit böleni doğrula: q = (x*M)>>32>>s == x/d örneklerle
bool ValidateDivisor(u64 M, int s, u64 d) {
    if (d < 2 || d > 0x100000ull || M < 0x10000ull) return false;
    u64 samples[] = {1, 2, 3, 7, 100, 12345};
    for (u64 x : samples) {
        u64 q = ((x * M) >> 32) >> s;
        if (q != x / d) return false;
    }
    return true;
}

// ---- v4 yardımcıları -------------------------------------------------------
// jcc anlamsal tersini ver (koşul DEVRALINMADIĞINDA devam koşulu için)
std::string NegJcc(const std::string& mn) {
    static const std::map<std::string, std::string> neg = {
        {"je", "jne"}, {"jz", "jnz"}, {"jne", "je"}, {"jnz", "jz"},
        {"jl", "jge"}, {"jnge", "jge"}, {"jge", "jl"}, {"jnl", "jl"},
        {"jle", "jg"}, {"jng", "jg"}, {"jg", "jle"}, {"jnle", "jle"},
        {"jb", "jae"}, {"jnae", "jae"}, {"jc", "jnc"}, {"jae", "jb"},
        {"jnb", "jb"}, {"jnc", "jc"}, {"jbe", "ja"}, {"jna", "ja"},
        {"ja", "jbe"}, {"jnbe", "jbe"}, {"js", "jns"}, {"jns", "js"},
    };
    auto it = neg.find(mn);
    return it != neg.end() ? it->second : mn;
}
// koşul tamamen sayısal mı? "0 == 0", "5 != 7", "12 < 100" -> çöz
bool ParseConstCond(const std::string& c, long long& l, std::string& op, long long& r) {
    static const char* ops[] = {"==", "!=", "<=", ">=", "<", ">"};
    auto isNum = [](const std::string& s) {
        if (s.empty()) return false;
        size_t i = (s[0] == '-') ? 1 : 0;
        if (i >= s.size()) return false;
        if (s.compare(i, 2, "0x") == 0 || s.compare(i, 2, "0X") == 0)
            return s.size() > i + 2 &&
                   s.find_first_not_of("0123456789abcdefABCDEF", i + 2) == std::string::npos;
        return s.find_first_not_of("0123456789", i) == std::string::npos;
    };
    for (auto* o : ops) {
        std::string needle = std::string(" ") + o + " ";
        size_t p = c.find(needle);
        if (p == std::string::npos) continue;
        std::string L = c.substr(0, p), R = c.substr(p + needle.size());
        if (!isNum(L) || !isNum(R)) continue;
        l = strtoll(L.c_str(), 0, 0);
        r = strtoll(R.c_str(), 0, 0);
        op = o;
        return true;
    }
    return false;
}
// sabit koşulun değerini çöz (ParseConstCond sonrası)
bool EvalConstCond(long long l, const std::string& op, long long r) {
    if (op == "==") return l == r;
    if (op == "!=") return l != r;
    if (op == "<")  return l < r;
    if (op == "<=") return l <= r;
    if (op == ">")  return l > r;
    return l >= r;
}
// "v3 += N;" / "v3 = v3 + 1;" / "++v3;" / "v3 = 1 + v3;" -> indüksiyon artışı
bool ParseIncrement(const std::string& stmt, std::string& var, int& delta) {
    auto stripSemi = [](std::string s) {
        while (!s.empty() && (s.back() == ';' || s.back() == ' ')) s.pop_back();
        return s;
    };
    std::string s = stripSemi(stmt);
    // ++v3 / --v3
    if (s.size() > 3 && (s.compare(0, 2, "++") == 0 || s.compare(0, 2, "--") == 0)) {
        var = s.substr(2);
        delta = (s[0] == '+') ? 1 : -1;
        for (char c : var)
            if (!isalnum((unsigned char)c) && c != '_') return false;
        return true;
    }
    // v3 += N / v3 -= N  (yalnız sayısal N — ifade değil)
    {
        size_t p = s.find(" += ");
        if (p != std::string::npos) {
            std::string tail = s.substr(p + 4);
            if (!tail.empty() && tail.find_first_not_of("0123456789") == std::string::npos) {
                var = s.substr(0, p);
                delta = atoi(tail.c_str());
                if (var.find(' ') == std::string::npos) return true;
            }
        }
        p = s.find(" -= ");
        if (p != std::string::npos) {
            std::string tail = s.substr(p + 4);
            if (!tail.empty() && tail.find_first_not_of("0123456789") == std::string::npos) {
                var = s.substr(0, p);
                delta = -atoi(tail.c_str());
                if (var.find(' ') == std::string::npos) return true;
            }
        }
    }
    // v3 = v3 + 1 / v3 = 1 + v3 / v3 = v3 - 1
    {
        size_t eq = s.find(" = ");
        if (eq != std::string::npos) {
            std::string lhs = s.substr(0, eq), rhs = s.substr(eq + 3);
            if (rhs == lhs + " + 1" || rhs == "1 + " + lhs) { var = lhs; delta = 1; return true; }
            if (rhs == lhs + " - 1") { var = lhs; delta = -1; return true; }
        }
    }
    return false;
}

// ----------------------------------------------------------------------------
// v5: birikimli (accumulator) ifade çözümü
//   "((((v1) + (p0)) + (p1)) + (p2)) + (p3)"  ->  var=v1, tail="p0 + p1 + p2 + p3"
// Sol-bağımlı toplam zincirini sağdan sola soyar. Başarısızsa false.
// ----------------------------------------------------------------------------
bool UnwrapAccumulator(const std::string& e, const std::string& var,
                       std::string& tail) {
    std::vector<std::string> parts;
    std::string cur = e;
    for (int guard = 0; guard < 32; guard++) {
        if (cur == var && !parts.empty()) break;
        // derinlik-0 en sağdaki " + " konumu
        int d = 0; size_t plus = std::string::npos;
        for (size_t i = 0; i + 2 < cur.size(); i++) {
            char c = cur[i];
            if (c == '(') d++;
            else if (c == ')') d--;
            else if (c == '+' && d == 0 && cur[i - 1] == ' ' && cur[i + 1] == ' ')
                plus = i;
        }
        if (plus == std::string::npos) break;
        std::string lhs = cur.substr(0, plus - 1);
        std::string rhs = cur.substr(plus + 2);
        // lhs tümüyle parantezli mi?
        if (lhs.size() >= 2 && lhs.front() == '(' && lhs.back() == ')') {
            int dd = 0; bool whole = true;
            for (size_t i = 0; i < lhs.size(); i++) {
                if (lhs[i] == '(') dd++;
                else if (lhs[i] == ')') {
                    dd--;
                    if (dd == 0 && i + 1 != lhs.size()) { whole = false; break; }
                }
            }
            if (whole) lhs = lhs.substr(1, lhs.size() - 2);
        }
        parts.push_back(rhs);
        cur = lhs;
    }
    if (cur != var || parts.empty()) return false;
    std::reverse(parts.begin(), parts.end());
    tail.clear();
    for (size_t i = 0; i < parts.size(); i++) {
        if (i) tail += " + ";
        tail += parts[i];
    }
    return true;
}

} // anonim

// ----------------------------------------------------------------------------
// TypeInferer erişimi
// ----------------------------------------------------------------------------
TypeInferer& Pseudocoder::TI() {
    if (!ti_) {
        ti_ = std::make_unique<TypeInferer>(az_);
        if (pendingPdb_) ti_->SetPdb(std::move(pendingPdb_));
        ti_->Run();
    }
    return *ti_;
}

// ----------------------------------------------------------------------------
// Katlama motoru
// ----------------------------------------------------------------------------
namespace {

struct StackVar {
    std::string name;      // a1 / v1 ...
    std::string type;      // int / __int64 / float / struct_N
    bool isStructLocal = false;
    i64 objBase = 0;       // struct ise nesne tabanı (rbp-göreli / RSP anahtarı)
};

class Folder {
public:
    Folder(Analyzer& az, TypeInferer& ti, u64 funcVa, bool isElf)
        : az_(az), ti_(ti), funcVa_(funcVa), isElf_(isElf) {
        argRegs_ = FuncSig::ArgRegs(isElf);
        nArgRegs_ = isElf ? 6 : 4;
        // GİRİŞ değerleri: argüman register'ları aN olarak bilinir (O2'de spill
        // yokken bile ham rdi yerine a1 gösterilir; DWARF adlarıyla değişir).
        // pristine: henüz dokunulmamış — çağrı argümanı olarak GEÇİLMEZ
        for (int k = 0; k < nArgRegs_; k++) {
            RegState st; st.valid = true; st.pristine = true;
            st.expr = "a" + std::to_string(k + 1);
            regs_[CanonReg(argRegs_[k])] = st;
        }
    }

    // ---- yığın değişkenlerini keşfet (pass 0) ----
    void DiscoverLocals(const std::vector<Ins>& ins) {
        // spill: mov [rbp-D], argReg  -> a{k+1}
        for (auto& x : ins) {
            if (x.mnemonic != "mov") continue;
            auto ops = SplitOps(x.opStr);
            if (ops.size() != 2 || ops[0].find('[') == std::string::npos) continue;
            MemOp m = ParseMem(ops[0]);
            if (m.base != "rbp" || !m.index.empty() || !IsRegTok(ops[1])) continue;
            for (int k = 0; k < nArgRegs_; k++)
                if (CanonReg(ops[1]) == argRegs_[k] && !vars_.count(m.disp)) {
                    StackVar v;
                    v.name = "a" + std::to_string(k + 1);
                    v.type = "int";
                    vars_[m.disp] = v;
                }
        }
        // adresi alınan nesneler: lea r, [rbp-D]
        for (auto& x : ins) {
            if (x.mnemonic != "lea") continue;
            MemOp m = ParseMem(x.opStr);
            if (m.base == "rbp" && m.index.empty() && m.disp) objects_.insert(m.disp);
        }
        // RSP çerçevesi (O2): mov rdi, rsp varsa [rsp+D] erişimleri nesneye
        for (auto& x : ins) {
            if (x.mnemonic != "mov") continue;
            auto ops = SplitOps(x.opStr);
            if (ops.size() == 2 && ops[0] == "rdi" && ops[1] == "rsp")
                objects_.insert(RSP_OBJ_KEY);
        }
        // geri kalan [rbp-D] erişimleri: vN
        // mov ile YAZILAN yigin slotlari (callee-save push/restore degil)
        std::set<i64> slotsWritten;
        for (auto& x : ins) {
            if (x.mnemonic != "mov") continue;
            auto ops = SplitOps(x.opStr);
            if (ops.empty() || ops[0].find('[') == std::string::npos) continue;
            MemOp m = ParseMem(ops[0]);
            if (m.base == "rbp" && m.index.empty() && m.disp < 0)
                slotsWritten.insert(m.disp);
        }
        for (auto& x : ins) {
            auto mems = MemOperandsOf(x);
            for (auto& m : mems) {
                if (m.base != "rbp" || !m.index.empty()) continue;
                i64 d = m.disp;
                if (d >= 0) continue;
                if (!slotsWritten.count(d)) {
                    // hic mov ile yazilmamis: callee-save restore okumasi olabilir
                    bool calleeRestore = false;
                    for (auto& o : SplitOps(x.opStr))
                        if (IsRegTok(o) && (o == "rbx" || o == "rbp" ||
                                            o == "r12" || o == "r13" ||
                                            o == "r14" || o == "r15"))
                            calleeRestore = true;
                    if (calleeRestore) continue;
                }                  // arg alanı değil
                if (vars_.count(d)) continue;
                StackVar v;
                v.name = "v" + std::to_string(++nLocals_);
                v.type = "int";
                const StructInfo* siL = ti_.StructOfLocal(funcVa_, d);
                if (siL) {
                    v.type = siL->name;
                    v.isStructLocal = true;
                    v.objBase = d;
                }
                vars_[d] = v;
                order_.push_back(d);
            }
        }
        // struct yerelleri: nesne tabanlarını TypeInferer ile eşleştir
        for (i64 base : objects_) {
            if (base == RSP_OBJ_KEY) {
                const StructInfo* si = ti_.StructOfLocal(funcVa_, RSP_OBJ_KEY);
                if (si) {
                    StackVar v;
                    v.name = "v" + std::to_string(++nLocals_);
                    v.type = si->name;
                    v.isStructLocal = true;
                    v.objBase = RSP_OBJ_KEY;
                    vars_[RSP_OBJ_KEY] = v;
                    order_.push_back(RSP_OBJ_KEY);
                }
                continue;
            }
            const StructInfo* si = ti_.StructOfLocal(funcVa_, base);
            if (si && !vars_.count(base)) {
                StackVar v;
                v.name = "v" + std::to_string(++nLocals_);
                v.type = si->name;
                v.isStructLocal = true;
                v.objBase = base;
                vars_[base] = v;
                order_.push_back(base);
            }
        }
        // tipler: float/qword kullanımı
        for (auto& x : ins) {
            auto mems = MemOperandsOf(x);
            bool isFloat = (x.mnemonic == "movss" || x.mnemonic == "movsd");
            for (auto& m : mems) {
                if (m.base != "rbp" || !m.index.empty()) continue;
                auto it = vars_.find(m.disp);
                if (it == vars_.end() || it->second.isStructLocal) continue;
                if (isFloat) it->second.type = "double";
                else if (m.size == 8) it->second.type = "__int64";
                else if (m.size == 2) it->second.type = "short";
                else if (m.size == 1) it->second.type = "char";
            }
        }
        (void)funcVa_;
    }

    std::vector<MemOp> MemOperandsOf(const Ins& x) {
        std::vector<MemOp> out;
        for (auto& o : SplitOps(x.opStr))
            if (o.find('[') != std::string::npos) out.push_back(ParseMem(o));
        return out;
    }

    // ---- ifade üretimi ----
    std::string RegExpr(const std::string& r) {
        auto it = regs_.find(CanonReg(r));
        if (it != regs_.end() && it->second.valid) return it->second.expr;
        return CanonReg(r);   // ham isim (dürüst geri dönüş)
    }
    void SetReg(const std::string& r, const std::string& expr) {
        if (!IsRegTok(r)) return;
        RegState st; st.valid = true; st.expr = expr;
        regs_[CanonReg(r)] = st;
    }
    bool RegPristine(const std::string& r) const {
        auto it = regs_.find(CanonReg(r));
        return it != regs_.end() && it->second.valid && it->second.pristine;
    }
    void KillReg(const std::string& r) { regs_[CanonReg(r)] = RegState{}; }

    // [rbp-D] hedef adı (değişken/üye)
    std::string StackRef(i64 disp) {
        auto it = vars_.find(disp);
        if (it != vars_.end()) return it->second.name;
        return "[rbp" + (disp < 0 ? std::string(" - ") + ToHex((u64)(-disp))
                                  : std::string(" + ") + ToHex((u64)disp)) + "]";
    }

    // bellek operandı -> ifade (okuma)
    std::string MemExpr(const MemOp& m, bool floatAccess, bool asAddress) {
        // yığın
        if (m.base == "rbp" && m.index.empty()) {
            // struct tabanina DOGRUDAN erisim: yalnizca tam eslesme
            if (objects_.count(m.disp)) {
                auto it = vars_.find(m.disp);
                if (it != vars_.end() && it->second.isStructLocal) {
                    const StructInfo* si = ti_.StructOfLocal(funcVa_, m.disp);
                    if (si) return MemberExpr(si, it->second.name, false, 0,
                                              m.size, floatAccess, asAddress);
                }
            }
            return StackRef(m.disp);
        }
        if (m.base == "rsp") {
            auto it = vars_.find(RSP_OBJ_KEY);
            if (it != vars_.end() && it->second.isStructLocal) {
                const StructInfo* si = ti_.StructOfLocal(funcVa_, RSP_OBJ_KEY);
                if (si) return MemberExpr(si, it->second.name, false, (u64)m.disp,
                                          m.size, floatAccess, asAddress);
            }
            return StackRef(m.disp);
        }
        // rip-goreli: string / float sabiti / sembol
        if (m.base == "rip") {
            std::string str;
            if (az_.IsStringAt(ripTarget_, &str)) return "\"" + str + "\"";
            if (m.size == 4) {
                u8 raw[4];
                if (az_.Image().ReadBytes(ripTarget_, raw, 4)) {
                    float f;
                    memcpy(&f, raw, 4);
                    char buf[48];
                    snprintf(buf, sizeof(buf), "%g", (double)f);
                    return buf;
                }
            }
            return "0x" + ToHex(ripTarget_);
        }
        // register tabanlı
        std::string baseE = RegExpr(m.base);
        std::string idxE = m.index.empty() ? "" : RegExpr(m.index);
        // kalıp: baseE == "aP" veya "aP + K2" ve P struct* ise üye erişimi
        int argIdx = -1; u64 constOff = 0; std::string baseName;
        {
            for (int p = 0; p < 6; p++) {
                std::string an = "a" + std::to_string(p + 1);
                if (baseE == an) { argIdx = p; constOff = 0; baseName = an; break; }
                std::string pre = an + " + ";
                if (baseE.rfind(pre, 0) == 0 && baseE.size() > pre.size()) {
                    std::string rest = baseE.substr(pre.size());
                    if (IsNumberTok(rest))
                        constOff = strtoull(rest.c_str(), 0, 0);
                    // sayisal degilse indeks ifadesidir (a1 + v2*4) —
                    // asagidaki gomulu-indeks kalibi halleder
                    argIdx = p;
                    baseName = an;
                    break;
                }
            }
        }
        if (argIdx >= 0) {
            const StructInfo* si = ti_.StructOfArg(funcVa_, argIdx);
            u64 off = constOff + (u64)m.disp;
            if (si) return MemberExpr(si, baseName, true, off, m.size, floatAccess, asAddress);
            // int* arg: aP[i + K/S] kalıbı
            const FuncSig* fs = ti_.SigOf(funcVa_);
            u32 stride = fs ? fs->argStride[argIdx] : 0;
            if (!m.index.empty() && stride == m.scale) {
                u64 k = off;
                if (k % stride == 0 && k / stride <= 1024) {
                    u64 ki = k / stride;
                    std::string idx = idxE;
                    if (ki == 0) {}
                    else if (IsNumberTok(idxE) && idxE.find("0x") != 0) {
                        idx = std::to_string(atoll(idxE.c_str()) + (i64)ki);
                    } else if (ki == 1) idx = idxE + " + 1";
                    else idx = idxE + " + " + std::to_string(ki);
                    return baseName + "[" + idx + "]";
                }
            }
            // "a1 + v2 * 4" kalibi: taban ifadeye gomulu indeks
            {
                std::string pre = baseName + " + ";
                if (baseE.rfind(pre, 0) == 0 && m.index.empty()) {
                    std::string rest = baseE.substr(pre.size());
                    std::string sfx = " * " + std::to_string(stride);
                    if (stride && rest.size() > sfx.size() &&
                        rest.substr(rest.size() - sfx.size()) == sfx) {
                        std::string idx = rest.substr(0, rest.size() - sfx.size());
                        if (!idx.empty() && idx.front() == '(' && idx.back() == ')')
                            idx = idx.substr(1, idx.size() - 2);
                        u64 k = off;
                        if (k % stride == 0 && k / stride > 0 && k / stride <= 1024)
                            idx += " + " + std::to_string(k / stride);
                        return baseName + "[" + idx + "]";
                    }
                }
            }
            if (m.index.empty() && off == 0 && asAddress) return "&" + baseName;
            std::string addr = baseName;
            if (off) addr += " + " + ToHex(off);
            if (!m.index.empty()) addr += " + " + Paren(idxE) + " * " + std::to_string(m.scale);
            return "*(int *)(" + addr + ")";
        }
        // yerel struct: baseE == "vN" veya "vN + K"
        {
            for (auto& [d, v] : vars_) {
                if (!v.isStructLocal) continue;
                std::string pre = v.name + " + ";
                u64 k2 = 0;
                bool matched = (baseE == v.name);
                if (!matched && baseE.rfind(pre, 0) == 0 &&
                    IsNumberTok(baseE.substr(pre.size()))) {
                    k2 = strtoull(baseE.substr(pre.size()).c_str(), 0, 0);
                    matched = true;
                }
                if (!matched) continue;
                const StructInfo* si = ti_.StructOfLocal(funcVa_, v.objBase);
                if (!si) continue;
                u64 off = k2 + (u64)m.disp;
                if (!m.index.empty()) {
                    const StructMember* mem = si->MemberAt(off);
                    if (mem && mem->isArray && mem->stride == m.scale)
                        return v.name + "." + MemberFieldName(si, off) + "[" + idxE + "]";
                }
                return MemberExpr(si, v.name, false, off, m.size, floatAccess, asAddress);
            }
        }
        // rbp-INDEX'li erisim: yerel struct nesnesinin dizi uyesi
        // (mov [rbp + rdx*4 - 0x4c], eax -> ali.notlar[i])
        if (m.base == "rbp" && !m.index.empty()) {
            i64 D = m.disp;
            for (auto& [d, v] : vars_) {
                if (!v.isStructLocal || v.objBase == RSP_OBJ_KEY) continue;
                i64 B = v.objBase;
                if (B <= D && D - B < 256) {
                    const StructInfo* si = ti_.StructOfLocal(funcVa_, B);
                    if (!si) continue;
                    u64 off = (u64)(D - B);
                    const StructMember* mem = si->MemberAt(off);
                    if (mem && mem->isArray && mem->stride == m.scale)
                        return v.name + "." + MemberFieldName(si, off) + "[" + idxE + "]";
                }
            }
        }
        // genel
        std::string addr = Paren(baseE);
        if (m.disp) addr += (m.disp > 0 ? " + " : " - ") + ToHex((u64)(m.disp > 0 ? m.disp : -m.disp));
        if (!m.index.empty()) addr += " + " + Paren(idxE) + " * " + std::to_string(m.scale);
        if (asAddress) return addr;
        return "*(" + std::string(floatAccess ? "float" : "int") + " *)&" + Paren(addr);
    }

    // struct üyesi erişim metni (DWARF gerçek adlarıyla)
    std::string MemberFieldName(const StructInfo* si, u64 off) const {
        const StructMember* mem = si ? si->MemberAt(off) : nullptr;
        if (mem && !mem->name.empty()) return mem->name;
        return "field_" + ToHex(off);
    }

    // struct üyesi erişim metni
    std::string MemberExpr(const StructInfo* si, const std::string& base, bool isPtr,
                           u64 off, u32 size, bool floatAccess, bool asAddress) {
        // v6: aralık çözümü — dizi üyesinin içine düşen ofset
        // (o+0xc, notlar@+4 int[8]) -> o->notlar[2]
        u64 elemIdx = 0;
        const StructMember* mem = si->MemberContaining(off, &elemIdx);
        std::string arrow = isPtr ? "->" : ".";
        std::string fldName = mem
            ? (mem->name.empty() ? "field_" + ToHex(mem->offset) : mem->name)
            : ("field_" + ToHex(off));
        std::string fld = base + arrow + fldName;
        if (mem && elemIdx) fld += "[" + std::to_string(elemIdx) + "]";
        if (!mem) {
            return fld;   // tanimsiz uye: adla goster (DWARF'siz field_XX)
        }
        if (asAddress) {
            if (elemIdx) return "&" + fld;          // &o->notlar[2]
            if (mem->isArray || mem->isString) return fld;   // dizi & gerektirmez
            return "&" + fld;
        }
        if (floatAccess && mem->kind != ArgKind::Float) return "(float)" + fld;
        return fld;
    }

    // "aN + K" / "vN + K" ifadelerini struct uye erisimine cevirir;
    // "aN + IDX*S" -> aN[IDX]. (cagri argumanlari icin)
    std::string ArgValueExpr(const std::string& e) {
        for (int p = 0; p < 6; p++) {
            std::string an = "a" + std::to_string(p + 1);
            if (e == an) return e;
            std::string pre = an + " + ";
            if (e.rfind(pre, 0) != 0) continue;
            std::string rest = e.substr(pre.size());
            const StructInfo* si = ti_.StructOfArg(funcVa_, p);
            if (si) {
                if (IsNumberTok(rest)) {
                    u64 off = strtoull(rest.c_str(), 0, 0);
                    const StructMember* mem = si->MemberAt(off);
                    if (mem && (mem->isArray || mem->isString))
                        return an + "->" + MemberFieldName(si, off);
                    return "&" + an + "->" + MemberFieldName(si, off);
                }
                // aN + IDX*S: dizi uyesi endeksi
                for (u64 S = 1; S <= 16; S *= 2) {
                    std::string sfx = " * " + std::to_string(S);
                    if (rest.size() > sfx.size() &&
                        rest.substr(rest.size() - sfx.size()) == sfx) {
                        std::string idx = rest.substr(0, rest.size() - sfx.size());
                        if (!idx.empty() && idx.front() == '(' && idx.back() == ')')
                            idx = idx.substr(1, idx.size() - 2);
                        // uye tabanini bul: S adimli dizi uyesi (ilk eslesen)
                        for (auto& [off, mem] : si->members)
                            if (mem.isArray && mem.stride == S)
                                return an + "->" + MemberFieldName(si, off) + "[" + idx + "]";
                    }
                }
            }
            return e;   // struct degil: oldugu gibi
        }
        // yerel struct: "vX + K"
        for (auto& [d, v] : vars_) {
            if (!v.isStructLocal) continue;
            std::string pre = v.name + " + ";
            if (e.rfind(pre, 0) != 0) continue;
            std::string rest = e.substr(pre.size());
            if (!IsNumberTok(rest)) return e;
            u64 off = strtoull(rest.c_str(), 0, 0);
            const StructInfo* si = ti_.StructOfLocal(funcVa_, v.objBase);
            if (!si) return e;
            const StructMember* mem = si->MemberAt(off);
            if (mem && (mem->isArray || mem->isString))
                return v.name + "." + MemberFieldName(si, off);
            return "&" + v.name + "." + MemberFieldName(si, off);
        }
        return e;
    }

    // operand -> ifade
    std::string OpExpr(const std::string& op, bool floatAccess = false) {
        if (op.find('[') != std::string::npos) {
            MemOp m = ParseMem(op);
            return MemExpr(m, floatAccess, false);
        }
        if (IsRegTok(op)) return RegExpr(op);
        return PrettyImm(op);   // v6: 0xffffffff -> -1
    }

    // ---- tek komutu katla; ifade listesine ekle ----
    // statement: geri dönen string boş değilse satır olarak basılır
    std::string Fold(const Ins& x, size_t nextIdx, const std::vector<Ins>& ins) {
        // idiom penceresi icindekiler yutuldu
        if (pendingDiv_.endIdx != (size_t)-1) {
            if (nextIdx <= pendingDiv_.endIdx) {
                if (nextIdx == pendingDiv_.endIdx) ClearPendingDiv();
                return "";
            }
            ClearPendingDiv();
        }
        const std::string& mn = x.mnemonic;
        auto ops = SplitOps(x.opStr);
        if (ops.empty()) return "";

        ripTarget_ = x.memRef;

        // --- atlanacaklar ---
        if (mn == "endbr64" || mn == "nop" || mn == "leave") return "";
        if (mn == "push" || mn == "pop") {
            // callee-saved push/pop sessiz
            return "";
        }
        if (mn == "cdq" || mn == "cdqe" || mn == "cqo") {
            // işaret genişletme: ifadeyi koru (rax)
            // (eax -> rax aynı kök)
            return "";
        }

        // --- imza: dönüş değeri için ---
        // (ret anında regExpr rax kullanılır)

        // --- çağrı ---
        if (mn == "call") {
            // --- sanal çağrı (vtable dispatch): a1->alan() üslubu ---
            const TypeInferer::VirtCall* vc = ti_.VirtCallAt(x.addr);
            if (vc) {
                // ---- v5: DEVIRTUALİZASYON — sanal çağrıyı statik hedefe çöz ---
                TypeInferer::DevirtResult dv = ti_.TryDevirtualize(x.addr);
                if (dv.target) {
                    std::string callee = az_.NameFor(dv.target);
                    size_t dp = callee.find("(...)");
                    if (dp != std::string::npos) callee.resize(dp);
                    if (callee.size() > 2 && callee.substr(callee.size() - 2) == "()")
                        callee.resize(callee.size() - 2);
                    std::string objE;
                    if (vc->isArg) objE = "a" + std::to_string(vc->argIdx + 1);
                    else {
                        for (auto& [d, v] : vars_)
                            if (d == vc->localDisp) { objE = "&" + v.name; break; }
                        if (objE.empty())
                            objE = "vobj_" + ToHex((u64)(vc->localDisp < 0
                                                           ? -vc->localDisp : vc->localDisp));
                    }
                    // metot işaretçisi ve this dışı argümanlar (sanal yoldaki gibi)
                    std::vector<std::string> margs;
                    for (int k = 1; k < nArgRegs_; k++) {
                        if (!vc->callReg.empty() && CanonReg(argRegs_[k]) == vc->callReg)
                            continue;
                        if (RegPristine(argRegs_[k])) continue;
                        std::string e = RegExpr(argRegs_[k]);
                        if (e == CanonReg(argRegs_[k])) {
                            if (k < (int)lastImm_.size() && !lastImm_[k].empty())
                                e = lastImm_[k];
                            else continue;
                        }
                        margs.push_back(ArgValueExpr(e));
                    }
                    std::string call2 = callee + "(" + objE;
                    for (auto& a : margs) call2 += ", " + a;
                    call2 += ")";
                    ArgKind rk = ti_.VirtSlotRet(vc->slot);
                    for (int k = 0; k < nArgRegs_; k++) KillReg(argRegs_[k]);
                    for (int r = 0; r < 8; r++) KillReg("xmm" + std::to_string(r));
                    std::fill(lastImm_.begin(), lastImm_.end(), "");
                    if (rk == ArgKind::Float) SetReg("xmm0", call2);
                    else if (rk != ArgKind::None) SetReg("rax", call2);
                    return call2 + ";   // v5 devirtualize: " + dv.why;
                }
                std::string objE;
                if (vc->isArg) objE = "a" + std::to_string(vc->argIdx + 1);
                else {
                    for (auto& [d, v] : vars_)
                        if (d == vc->localDisp) { objE = v.name; break; }
                    if (objE.empty())
                        objE = "vobj_" + ToHex((u64)(vc->localDisp < 0
                                                       ? -vc->localDisp : vc->localDisp));
                }
                std::string mname = ti_.VirtSlotName(vc->slot);
                if (mname.empty()) mname = "vfunc_" + std::to_string(vc->slot);
                // argümanlar: this register'ı (ilk arg reg) atlanır
                std::vector<std::string> margs;
                for (int k = 1; k < nArgRegs_; k++) {
                    if (!vc->callReg.empty() && CanonReg(argRegs_[k]) == vc->callReg)
                        continue;   // metot işaretçisi: argüman değil
                    if (RegPristine(argRegs_[k])) continue;   // dokunulmamış: arg değil
                    std::string e = RegExpr(argRegs_[k]);
                    if (e == CanonReg(argRegs_[k])) {
                        if (k < (int)lastImm_.size() && !lastImm_[k].empty())
                            e = lastImm_[k];
                        else continue;
                    }
                    margs.push_back(ArgValueExpr(e));
                }
                std::string call2 = objE + "->" + mname + "(";
                for (size_t i = 0; i < margs.size(); i++) {
                    if (i) call2 += ", ";
                    call2 += margs[i];
                }
                call2 += ")";
                ArgKind rk = ti_.VirtSlotRet(vc->slot);
                for (int k = 0; k < nArgRegs_; k++) KillReg(argRegs_[k]);
                for (int r = 0; r < 8; r++) KillReg("xmm" + std::to_string(r));
                std::fill(lastImm_.begin(), lastImm_.end(), "");
                if (rk == ArgKind::Float) SetReg("xmm0", call2);
                else if (rk != ArgKind::None) SetReg("rax", call2);
                std::string note = "   // sanal cagri: vtable[";
                note += std::to_string(vc->slot) + "] (" +
                        ti_.VirtSlotClasses(vc->slot) + ")";
                return call2 + ";" + note;
            }
            std::string callee = x.isIndirect ? "" : az_.NameFor(x.target);
            if (x.isIndirect && x.memRef) {
                std::string g = az_.Bin().GotName(x.memRef);
                if (!g.empty()) callee = g;
            }
            if (callee.empty() || callee.rfind("sub_", 0) == 0) {
                std::string plt = az_.Bin().PltName(x.target);
                if (!plt.empty()) callee = plt;
            }
            if (callee.empty()) callee = "sub_" + ToHex(x.target, 8);
            {   // demangle artigi "(...)" sonekini kaldir
                size_t dp = callee.find("(...)");
                if (dp != std::string::npos) callee.resize(dp);
            }
            const FuncSig* fs = ti_.SigOf(x.target);
            bool variadic = fs && fs->variadic;

            std::vector<std::string> args;
            int nFixed = fs ? fs->nArgs : nArgRegs_;
            for (int k = 0; k < nArgRegs_; k++) {
                if (k > 0 && RegPristine(argRegs_[k])) continue;   // dokunulmamış: arg değil
                std::string e = RegExpr(argRegs_[k]);
                if (e == CanonReg(argRegs_[k])) {
                    if (k < (int)lastImm_.size() && !lastImm_[k].empty())
                        e = lastImm_[k];
                    else continue;
                }
                std::string ae = ArgValueExpr(e);
                // ptr beklenen arg'a struct yereli ADRES olarak gecilir
                if (fs && k < fs->nArgs && fs->argKinds[k] == ArgKind::Ptr &&
                    ae.size() > 1 && ae[0] == 'v') {
                    bool isLocalStruct = false;
                    for (auto& [dd, vv] : vars_)
                        if (vv.isStructLocal && vv.name == ae) isLocalStruct = true;
                    if (isLocalStruct) ae = "&" + ae;
                }
                args.push_back(ae);
            }
            // variadic: xmm0..3 de argüman (printf %f vb.)
            if (variadic) {
                for (int r = 0; r < 4; r++) {
                    std::string rn = "xmm" + std::to_string(r);
                    std::string e = RegExpr(rn);
                    if (e != rn) args.push_back(e);
                }
                // birebir ayni ifade tekrarlarini ele (olcu register artigi)
                std::vector<std::string> uniq;
                for (auto& a : args) {
                    bool dup = false;
                    for (auto& u : uniq) if (u == a) { dup = true; break; }
                    if (!dup) uniq.push_back(a);
                }
                args = uniq;
            }
            // eax = 1 (vararg xmm sayacı) gizle
            std::string call = callee + "(";
            for (size_t i = 0; i < args.size(); i++) {
                if (i) call += ", ";
                call += args[i];
            }
            call += ")";
            // once volatile'lar temizlenir, sonra donus yazilir
            for (int k = 0; k < nArgRegs_; k++) KillReg(argRegs_[k]);
            for (int r = 0; r < 8; r++) KillReg("xmm" + std::to_string(r));
            if (fs && fs->retKind == ArgKind::Float) {
                SetReg("xmm0", call);
            } else {
                SetReg("rax", call);
                // rdx yayilimi YOK: bayat donus degeri sonraki cagrinin
                // argumani saniliyor (printf -> faktoriyel kimerasi)
            }
            std::fill(lastImm_.begin(), lastImm_.end(), "");
            return call + ";";
        }

        // --- koşul hazırlığı ---
        if (mn == "cmp" || mn == "test") {
            std::string lhs = OpExpr(ops[0]);
            std::string rhs = ops.size() > 1 ? OpExpr(ops[1]) : "0";
            if (mn == "test") {
                // test a,a == a & a == a: karşılaştırma için 0'a düşür
                // (je/jne doğru çözülsün: "sum == sum" değil "sum == 0")
                if (ops.size() > 1 && CanonReg(ops[0]) == CanonReg(ops[1]) &&
                    IsRegTok(ops[0]))
                    rhs = "0";
            }
            lastCmpLhs_ = lhs; lastCmpRhs_ = rhs;
            return "";
        }

        // --- data hareketleri ---
        if (mn == "mov" || mn == "movsx" || mn == "movzx" || mn == "movsxd") {
            const std::string& dst = ops[0];
            const std::string& src = ops.size() > 1 ? ops[1] : "";
            if (dst.find('[') != std::string::npos) {
                // belleğe yaz
                MemOp m = ParseMem(dst);
                std::string val = OpExpr(src);
                std::string note;
                if (IsRegTok(src) == false && src.find("0x") == 0) {
                    std::string s = ImmStringNote(strtoull(src.c_str(), 0, 0));
                    if (!s.empty()) note = "   // \"" + s + "\"";
                }
                // arg spill'i sessizgecir: mov [rbp-D], rdi (a1 = rdi gereksiz)
                if (m.base == "rbp" && m.index.empty() && vars_.count(m.disp)) {
                    auto& sv = vars_.at(m.disp);
                    if (sv.name.size() > 1 && sv.name[0] == 'a' &&
                        IsRegTok(src) && val == CanonReg(src))
                        return "";
                }
                                // callee-save geri yükleme atla
                if (m.base == "rbp" && m.index.empty() && !vars_.count(m.disp) &&
                    (src == "rbx" || src == "rbp" || src.rfind("r1", 0) == 0))
                    return "";
                return MemWriteStmt(m, val) + note;
            }
            if (IsRegTok(src)) {
                SetReg(dst, RegExpr(src));
            } else if (src.find('[') != std::string::npos) {
                SetReg(dst, OpExpr(src));
            } else {
                std::string psrc = PrettyImm(src);   // v6: mov $0xffffffff -> -1
                SetReg(dst, psrc);
                // arg register'a sabit: çağrı argümanı olarak hatırla
                for (int k = 0; k < nArgRegs_; k++)
                    if (CanonReg(dst) == argRegs_[k] && k < (int)lastImm_.size())
                        lastImm_[k] = psrc;
            }
            return "";
        }
        if (mn == "movss" || mn == "movsd") {
            const std::string& dst = ops[0];
            const std::string& src = ops.size() > 1 ? ops[1] : "";
            bool fa = (mn == "movss" || mn == "movsd");
            if (dst.find('[') != std::string::npos) {
                MemOp m = ParseMem(dst);
                // v5: kayn vektörse lane0'ı sakla (yatay indirme sonucu)
                std::string v = OpExpr(src, fa);
                if (v == CanonReg(src)) {
                    std::string l0 = LaneOf(src, 0);
                    if (!l0.empty()) v = l0;
                }
                return MemWriteStmt(m, v);
            }
            // v5: vektör yazmaçtan skaler kopya -> lane0 (geri açma)
            if (IsRegTok(src)) {
                std::string l0 = LaneOf(src, 0);
                if (!l0.empty()) { SetReg(dst, l0); return ""; }
            }
            SetReg(dst, OpExpr(src, fa));
            return "";
        }
        if (mn == "movq" || mn == "movd") {
            // xmm <-> gpr: ifadeyi taşı; v5: vektör kaynağıysa lane0 (indirme)
            if (IsRegTok(ops[0]) && ops.size() > 1 && IsRegTok(ops[1])) {
                std::string l0 = LaneOf(ops[1], 0);
                if (!l0.empty()) { SetReg(ops[0], l0); return ""; }
            }
            SetReg(ops[0], OpExpr(ops.size() > 1 ? ops[1] : ""));
            return "";
        }
        if (mn == "cvtss2sd" || mn == "cvtsd2ss") {
            std::string e;
            std::string l0 = ops.size() > 1 ? LaneOf(ops[1], 0) : "";
            if (!l0.empty()) e = l0;
            else e = OpExpr(ops.size() > 1 ? ops[1] : "", true);
            SetReg(ops[0], "(double)" + Paren(e));
            return "";
        }
        if (mn == "cvtsi2ss" || mn == "cvtsi2sd") {
            std::string e = OpExpr(ops.size() > 1 ? ops[1] : "");
            SetReg(ops[0], std::string(mn == "cvtsi2ss" ? "(float)" : "(double)") + Paren(e));
            return "";
        }
        if (mn == "mulss" || mn == "divss" || mn == "addss" || mn == "subss" ||
            mn == "mulsd" || mn == "divsd" || mn == "addsd" || mn == "subsd") {
            std::string a = RegExpr(ops[0]);
            // v5: kaynak vektör yazmaçsa SADECE lane0 skaler katlanır
            // (addss xmm0, xmm1: xmm1'in tüm lane'leri değil ilk elemanı)
            std::string b;
            {
                const std::string& src = ops.size() > 1 ? ops[1] : "";
                std::string l0 = LaneOf(src, 0);
                if (!l0.empty()) b = l0;
                else b = OpExpr(src, true);
            }
            bool isAdd = (mn == "addss" || mn == "addsd");
            bool isSub = (mn == "subss" || mn == "subsd");
            bool isMul = (mn == "mulss" || mn == "mulsd");
            bool isDiv = (mn == "divss" || mn == "divsd");
            const char* op = isMul ? "*" : isDiv ? "/" : isAdd ? "+" : "-";
            // ikinci operand bellekse: xmm0 = expr op [mem] birleşimi
            SetReg(ops[0], Paren(a) + " " + op + " " + Paren(b));
            return "";
        }
        if (mn == "pxor" && ops.size() == 2 && ops[0] == ops[1]) {
            SetReg(ops[0], "0");
            return "";
        }
        if (mn == "xorps" && ops.size() == 2 && ops[0] == ops[1]) {
            SetReg(ops[0], "0");
            return "";
        }

        // ---- v5: PAKETLİ SIMD -> lane bazlı skaler geri açma -------------
        // mulps/addps/subps/divps: lane-wise işlem; addss+shufps zinciriyle
        // birleşince vektörleştirilmiş kod SKALER ifadeye geri açılır.
        if (mn == "addps" || mn == "mulps" || mn == "subps" || mn == "divps" ||
            mn == "addpd" || mn == "mulpd" || mn == "subpd" || mn == "divpd") {
            if (ops.size() == 2) {
                std::string l1[4], l2[4];
                bool v1ok = VecOperand(ops[0], false, l1);
                bool v2ok = VecOperand(ops[1], false, l2);
                if (v1ok && v2ok) {
                    const char* op = (mn[0] == 'a') ? "+" : (mn[0] == 'm') ? "*"
                               : (mn[0] == 's') ? "-" : "/";
                    std::string res[4];
                    for (int k = 0; k < 4; k++)
                        res[k] = Paren(l1[k]) + " " + op + " " + Paren(l2[k]);
                    SetVec(ops[0], res, false);
                    return "";
                }
            }
            // dürüst SIMD gösterimi
            std::string e = "simd_add(" + RegExpr(ops[0]) + ", " +
                            (ops.size() > 1 ? RegExpr(ops[1]) : "?") + ")";
            SetReg(ops[0], e);
            return "";
        }
        // ---- v5: lane permütasyonları (yatay indirme kanıtları) ----------
        if (mn == "shufps" || mn == "shufpd") {
            // Intel: shufps dst, src, imm8
            if (ops.size() == 3) {
                u64 imm = strtoull(ops[2].c_str() + (ops[2][0] == '$' ? 1 : 0), 0, 0);
                if (ops[2].find("0x") == std::string::npos &&
                    ops[2].find_first_of("0123456789") != std::string::npos)
                    imm = strtoull(ops[2].c_str(), 0, 0);
                auto& D = RegStateOf(ops[0]);
                std::string l2[4];
                bool s2ok = VecOperand(ops[1], false, l2);
                if (D.valid && D.vec && s2ok) {
                    std::string res[4];
                    res[0] = D.lane[imm & 3];
                    res[1] = D.lane[(imm >> 2) & 3];
                    res[2] = l2[(imm >> 4) & 3];
                    res[3] = l2[(imm >> 6) & 3];
                    if (!res[0].empty() && !res[1].empty() &&
                        !res[2].empty() && !res[3].empty()) {
                        SetVec(ops[0], res, D.vecInt);
                        return "";
                    }
                }
            }
            KillReg(ops[0]);
            return "";
        }
        if (mn == "unpckhps" || mn == "unpcklps" || mn == "movhlps" ||
            mn == "movlhps" || mn == "movshdup" || mn == "movsldup" ||
            mn == "haddps") {
            if (ops.size() == 2) {
                auto& D = RegStateOf(ops[0]);
                std::string s2[4];
                bool s2ok = VecOperand(ops[1], false, s2);
                if (D.valid && D.vec && s2ok) {
                    std::string d0 = D.lane[0], d1 = D.lane[1],
                                d2 = D.lane[2], d3 = D.lane[3];
                    std::string res[4];
                    if (mn == "unpckhps") {
                        res[0] = d2; res[1] = s2[2]; res[2] = d3; res[3] = s2[3];
                    } else if (mn == "unpcklps") {
                        res[0] = d0; res[1] = s2[0]; res[2] = d1; res[3] = s2[1];
                    } else if (mn == "movhlps") {
                        res[0] = s2[2]; res[1] = s2[3]; res[2] = d2; res[3] = d3;
                    } else if (mn == "movlhps") {
                        res[0] = d0; res[1] = d1; res[2] = s2[0]; res[3] = s2[1];
                    } else if (mn == "movshdup") {
                        res[0] = s2[1]; res[1] = s2[1]; res[2] = s2[3]; res[3] = s2[3];
                    } else if (mn == "movsldup") {
                        res[0] = s2[0]; res[1] = s2[0]; res[2] = s2[2]; res[3] = s2[2];
                    } else {    // haddps: {d0+d1, d2+d3, s0+s1, s2+s3}
                        res[0] = Paren(d0) + " + " + Paren(d1);
                        res[1] = Paren(d2) + " + " + Paren(d3);
                        res[2] = Paren(s2[0]) + " + " + Paren(s2[1]);
                        res[3] = Paren(s2[2]) + " + " + Paren(s2[3]);
                    }
                    if (!res[0].empty() && !res[1].empty() &&
                        !res[2].empty() && !res[3].empty()) {
                        SetVec(ops[0], res, D.vecInt);
                        return "";
                    }
                }
            }
            KillReg(ops[0]);
            return "";
        }
        if (mn == "lea") {
            const std::string& dst = ops[0];
            MemOp m = ParseMem(ops.size() > 1 ? ops[1] : "");
            if (m.base == "rbp" && m.index.empty()) {
                // yerel nesnenin adresi
                auto it = vars_.find(m.disp);
                if (it != vars_.end() && it->second.isStructLocal)
                    SetReg(dst, it->second.name);
                else if (it != vars_.end())
                    SetReg(dst, "&" + it->second.name);
                else SetReg(dst, "&" + StackRef(m.disp));
                return "";
            }
            if (m.base == "rip") {
                std::string s;
                if (az_.IsStringAt(x.memRef, &s)) {
                    std::string shown = s.size() > 48 ? s.substr(0, 48) + "..." : s;
                    SetReg(dst, "\"" + shown + "\"");
                } else {
                    std::string nm = az_.SymbolOrLabel(x.memRef);
                    SetReg(dst, nm.empty() ? ("0x" + ToHex(x.memRef)) : nm);
                }
                return "";
            }
            if (m.base == "rsp") {
                // RSP çerçevesi nesnesi
                auto it = vars_.find(RSP_OBJ_KEY);
                if (it != vars_.end()) SetReg(dst, it->second.name);
                else SetReg(dst, "rsp");
                if (m.disp) SetReg(dst, RegExpr(dst) + " + " + std::to_string((i64)m.disp));
                return "";
            }
            if (!m.index.empty()) {
                // lea r, [base + idx*S [+K]]
                std::string e = Paren(RegExpr(m.index)) + " * " + std::to_string(m.scale);
                if (m.base.empty() || RegExpr(m.base) == "0") {
                    SetReg(dst, m.disp ? e + " + " + std::to_string((i64)m.disp) : e);
                } else {
                    std::string b = RegExpr(m.base);
                    // a1 + i*4 kalıbı
                    SetReg(dst, b + " + " + e + (m.disp ? " + " + std::to_string((i64)m.disp) : ""));
                }
                return "";
            }
            std::string b = RegExpr(m.base);
            SetReg(dst, b + (m.disp ? " + " + std::to_string((i64)m.disp) : ""));
            return "";
        }
        if (mn == "add" || mn == "sub" || mn == "and" || mn == "or" || mn == "xor" ||
            mn == "shl" || mn == "shr" || mn == "sar") {
            const std::string& dst = ops[0];
            const std::string& src = ops.size() > 1 ? ops[1] : "";
            if (dst.find('[') != std::string::npos) {
                MemOp m = ParseMem(dst);
                std::string e = OpExpr(src);
                std::string cur = MemExpr(m, false, false);
                if (mn == "add" && e == "1") return "++" + cur + ";";
                if (mn == "sub" && e == "1") return "--" + cur + ";";
                const char* op = mn == "add" ? "+=" : mn == "sub" ? "-=" :
                                 mn == "and" ? "&=" : mn == "or" ? "|=" :
                                 mn == "xor" ? "^=" : mn == "shl" ? "<<=" :
                                 mn == "shr" ? ">>=" : ">>=";
                return cur + " " + op + " " + e + ";";
            }
            std::string a = RegExpr(dst), b = OpExpr(src);
            if (mn == "add") {
                if (a == dst && CanonReg(dst) == a) { /* ham */ }
                SetReg(dst, CanonArith(a, b, "+"));
            }
            else if (mn == "sub") {
                // X - ((X / N) * N)  ->  X % N   (sarmali formda kontrol)
                std::string e = a + " - " + Paren(b);
                std::string w = Paren(b);
                if (w.size() > 2 && w.front() == '(' && w.back() == ')' &&
                    b.find(" * ") != std::string::npos) {
                    std::string inner = w.substr(1, w.size() - 2);
                    size_t sp = inner.rfind(") * ");
                    if (sp != std::string::npos) {
                        std::string lhsFull = inner.substr(0, sp + 1);
                        std::string rhs = inner.substr(sp + 4);
                        if (IsNumberTok(rhs)) {
                            size_t ds = lhsFull.rfind(" / ");
                            if (ds != std::string::npos) {
                                std::string lnum = lhsFull.substr(ds + 3);
                                // kapanis parantezini kirp: "100)" -> "100"
                                while (!lnum.empty() && lnum.back() == ')')
                                    lnum.pop_back();
                                std::string lbase = lhsFull.substr(0, ds);
                                if (IsNumberTok(lnum) &&
                                    strtoull(lnum.c_str(), 0, 0) ==
                                        strtoull(rhs.c_str(), 0, 0) &&
                                    lbase == "(" + Paren(a))
                                    e = Paren(a) + " % " + lnum;
                            }
                        }
                    }
                }
                SetReg(dst, e);
            }
            else if (mn == "and") {
                // v4: R & 0 -> daima 0 (opak öncül katlaması)
                if (b == "0") SetReg(dst, "0");
                else SetReg(dst, a + " & " + Paren(b));
            }
            else if (mn == "or")  SetReg(dst, a + " | " + Paren(b));
            else if (mn == "xor") {
                // v4: X ^ X -> daima 0 (klasik opak öncül: xor r12d,r12d)
                if (a == b) SetReg(dst, "0");
                else SetReg(dst, a + " ^ " + Paren(b));
            }
            else if (mn == "shl") SetReg(dst, Paren(a) + " << " + b);
            else if (mn == "shr") SetReg(dst, Paren(a) + " >> " + b);
            else SetReg(dst, Paren(a) + " >> " + b);   // sar
            // shl k*X -> (k<<s)*X sadeleştirmesi
            SimplifyShiftMul(dst);
            return "";
        }
        if (mn == "imul") {
            if (ops.size() == 3) {
                // idiom penceresi: imul rA, rB, MAGIC (+ shr 32 + sar s) -> bölme
                if (nextIdx + 2 < ins.size()) {
                    const Ins& i1 = ins[nextIdx + 1];
                    const Ins& i2 = ins[nextIdx + 2];
                    auto o1 = SplitOps(i1.opStr);
                    auto o2 = SplitOps(i2.opStr);
                    // rax/eax gibi ayni kokun farkli genislikleri eslesir
                    auto sameReg = [](const std::string& a, const std::string& b) {
                        return CanonReg(a) == CanonReg(b);
                    };
                    if (i1.mnemonic == "shr" && o1.size() == 2 && sameReg(o1[0], ops[0]) &&
                        IsNumberTok(o1[1]) && strtoull(o1[1].c_str(), 0, 0) == 32 &&
                        (i2.mnemonic == "sar" || i2.mnemonic == "shr") && o2.size() == 2 &&
                        sameReg(o2[0], ops[0]) && IsNumberTok(o2[1])) {
                        int s = atoi(o2[1].c_str());
                        u64 M = strtoull(ops[2].c_str(), 0, 0);
                        // M = ceil(2^(32+s)/d) oldugundan d, floor(2^(32+s)/M)
                        // veya bir fazlasi olabilir — ornekle dogrulanani sec
                        u64 d = 0;
                        if (s < 32 && M >= 0x10000ull) {
                            u64 d1 = ((u64)1 << (32 + s)) / M;
                            u64 cand[2] = {d1, d1 + 1};
                            for (int ci = 0; ci < 2; ci++)
                                if (cand[ci] >= 2 && ValidateDivisor(M, s, cand[ci])) {
                                    d = cand[ci];
                                    break;
                                }
                        }
                        if (d) {
                            std::string num = RegExpr(ops[1]);
                            // imzalı düzeltme: mov rC, eB; sar rC, 31; sub eA, rC
                            if (i2.mnemonic == "sar" && nextIdx + 5 < ins.size()) {
                                const Ins& i3 = ins[nextIdx + 3];
                                const Ins& i4 = ins[nextIdx + 4];
                                const Ins& i5 = ins[nextIdx + 5];
                                auto o3 = SplitOps(i3.opStr);
                                auto o4 = SplitOps(i4.opStr);
                                auto o5 = SplitOps(i5.opStr);
                                std::string numE = RegExpr(ops[1]);
                                if (i3.mnemonic == "mov" && o3.size() == 2 &&
                                    IsRegTok(o3[1]) &&
                                    (sameReg(o3[1], ops[1]) || RegExpr(o3[1]) == numE) &&
                                    i4.mnemonic == "sar" && o4.size() == 2 &&
                                    o4[1] == "0x1f" &&
                                    i5.mnemonic == "sub" && o5.size() == 2 &&
                                    sameReg(o5[0], ops[0]) && sameReg(o5[1], o3[0])) {
                                    pendingDiv_ = {num, d, nextIdx + 5};
                                    SetReg(ops[0], Paren(num) + " / " + std::to_string(d));
                                    return "";   // 6 komut yutuldu (pending ile)
                                }
                            }
                            SetReg(ops[0], Paren(num) + " / " + std::to_string(d));
                            pendingDiv_ = {num, d, nextIdx + 2};
                            return "";
                        }
                    }
                }
                std::string e = Paren(RegExpr(ops[1])) + " * " + OpExpr(ops[2]);
                SetReg(ops[0], e);
                return "";
            }
            if (ops.size() == 2) {
                SetReg(ops[0], Paren(RegExpr(ops[0])) + " * " + Paren(OpExpr(ops[1])));
                return "";
            }
            SetReg("rax", Paren(RegExpr("rax")) + " * " + Paren(OpExpr(ops[0])));
            return "";
        }
        if (mn == "inc" || mn == "dec") {
            if (ops[0].find('[') != std::string::npos) {
                MemOp m = ParseMem(ops[0]);
                return (mn == "inc" ? "++" : "--") + MemExpr(m, false, false) + ";";
            }
            SetReg(ops[0], (mn == "inc" ? "++" : "--") + RegExpr(ops[0]));
            return "";
        }

        // ---- v5: neg/not (cmov zincirlerinde kritik: -x kaybı olmasın) ----
        if ((mn == "neg" || mn == "not") && ops.size() == 1) {
            std::string e = RegExpr(ops[0]);
            SetReg(ops[0], (mn == "neg" ? "-" : "~") + Paren(e));
            return "";
        }

        // ---- v5: CMOV katlaması (donanım phi'si) --------------------------
        // cmovCC dst, src  ->  dst = ( kosul ) ? src : dst
        // (motor Intel sırası: ops[0] = hedef, ops[1] = kaynak)
        if (mn.rfind("cmov", 0) == 0 && ops.size() == 2) {
            std::string jccName = "j" + mn.substr(4);   // cmovge -> jge
            std::string cond = CondFor(jccName);
            std::string dstE = RegExpr(ops[0]);
            std::string srcE = OpExpr(ops[1]);
            if (cond.find('(') != std::string::npos || cond.find('<') != std::string::npos ||
                cond.find('>') != std::string::npos || cond.find("==") != std::string::npos ||
                cond.find("!=") != std::string::npos) {
                SetReg(ops[0], "( " + cond + " ) ? " + srcE + " : " + dstE);
                return "";
            }
            // koşul çözülemedi: dürüst ham gösterim
            SetReg(ops[0], dstE);
            return "";
        }

        // SIMD: dürüst geri dönüş — ham satır
        if (mn == "paddd" || mn == "psrldq" || mn == "movdqa" || mn == "movdqu" ||
            mn == "movaps" || mn == "movups") {
            if (mn == "movdqa" || mn == "movdqu" || mn == "movaps" || mn == "movups") {
                const std::string& dst = ops[0];
                const std::string& src = ops.size() > 1 ? ops[1] : "";
                if (dst.find('[') != std::string::npos) {
                    MemOp m = ParseMem(dst);
                    // SIMD kaydı -> bellek: ifade katlanamayan ham durum;
                    // ÖZEL DURUM: pxor ile sıfırlanan kayıt = 16 bayt sıfır yazma
                    std::string srcE = ops.size() > 1 ? RegExpr(src) : "";
                    if (srcE == "0")
                        return MemExpr(m, false, false) +
                               " = 0;   // 16 bayt sifir (" + x.mnemonic + ")";
                    // v6: VEKTÖR KAYNAKLI STORE — 4 lane üye atamasına açılır.
                    // -O2'nin rodata sabitli dizi gömmesini (movdqa [rip+X] +
                    // movups [rsp+K]) 4 skaler atamaya geri çevirir.
                    {
                        auto& st = RegStateOf(src);
                        if (st.valid && st.vec && !st.lane[0].empty() &&
                            !st.lane[1].empty() && !st.lane[2].empty() &&
                            !st.lane[3].empty()) {
                            bool facc = !st.vecInt;
                            std::string out2;
                            for (int k = 0; k < 4; k++) {
                                MemOp mk = m;
                                mk.disp = m.disp + 4 * (i64)k;
                                if (k) out2 += " ";
                                out2 += MemExpr(mk, facc, false) + " = " +
                                        st.lane[k] + ";";
                            }
                            return out2;
                        }
                    }
                    return x.mnemonic + " " + x.opStr + ";   // SIMD";
                }
                if (src.find('[') != std::string::npos) {
                    MemOp m = ParseMem(src);
                    // v5: dizi yüklemesi -> 4 lane'li vektör modeli
                    // (movups/movaps: float lane'ler, movdqu/movdqa: int lane'ler)
                    bool isInt = (mn == "movdqu" || mn == "movdqa");
                    std::string l[4];
                    // v6: rip-göreli yükleme = .rodata'daki 4 SABİT lane
                    // (derleyicinin döngü-çözülmesi dizi gömmesi: {0,13,26,39})
                    bool fromConst = false;
                    if (m.base == "rip" && ripTarget_) {
                        u8 raw[16];
                        if (az_.Image().ReadBytes(ripTarget_, raw, 16)) {
                            fromConst = true;
                            for (int k = 0; k < 4; k++) {
                                char b[48];
                                if (isInt) {
                                    u32 v; memcpy(&v, raw + 4 * k, 4);
                                    snprintf(b, sizeof b, "%d", (i32)v);
                                } else {
                                    float f; memcpy(&f, raw + 4 * k, 4);
                                    snprintf(b, sizeof b, "%g", (double)f);
                                }
                                l[k] = b;
                            }
                        }
                    }
                    if (!fromConst)
                        for (int k = 0; k < 4; k++) l[k] = VecLaneExpr(m, k, !isInt);
                    SetVec(dst, l, isInt);
                    return "";
                }
                // v5: yazmaç-yazmaç kopya: skaler VEYA vektör durumu aynen taşınır
                // (movaps xmm0, xmm1 -> skaler float kopyası olarak geri açılır)
                {
                    auto& st = RegStateOf(src);
                    if (st.valid) {
                        RegState ns = st;
                        ns.pristine = false;
                        regs_[CanonReg(dst)] = ns;
                    } else {
                        KillReg(dst);
                    }
                }
                return "";
            }
            // v5: paddd/psrldq — INT lane modeli varsa skaler geri aç
            if (mn == "paddd" || mn == "psrldq") {
                std::string l1[4], l2[4];
                bool v1ok = VecOperand(ops[0], true, l1);
                bool v2ok = (mn == "paddd" && ops.size() > 1)
                            ? VecOperand(ops[1], true, l2) : false;
                if (v1ok) {
                    if (mn == "paddd" && v2ok) {
                        std::string res[4];
                        for (int k = 0; k < 4; k++)
                            res[k] = Paren(l1[k]) + " + " + Paren(l2[k]);
                        SetVec(ops[0], res, true);
                        return "";
                    }
                    if (mn == "psrldq" && ops.size() > 1) {
                        // bayt kaydırma: lane'ler N/4 kadar ötele (giren lane = 0)
                        u64 sh = strtoull(ops[1].c_str() + (ops[1][0] == '$' ? 1 : 0), 0, 0);
                        u64 ln = sh / 4;
                        std::string res[4];
                        for (int k = 0; k < 4; k++)
                            res[k] = (k + ln < 4) ? l1[k + ln] : "0";
                        SetVec(ops[0], res, true);
                        return "";
                    }
                }
            }
            // paddd xmm0, xmm1 -> simd_add(...)  (dürüst geri dönüş)
            std::string e = "simd_add(" + RegExpr(ops[0]) + ", " +
                            (ops.size() > 1 ? RegExpr(ops[1]) : "?") + ")";
            if (mn == "psrldq") e = "simd_shr(" + RegExpr(ops[0]) + ", " +
                                     (ops.size() > 1 ? ops[1] : "?") + ")";
            SetReg(ops[0], e);
            return "";
        }

        return "";   // tanınmayan: sessiz (adres notu sürücüde)
    }

    void SimplifyShiftMul(const std::string& dst) {
        auto it = regs_.find(CanonReg(dst));
        if (it == regs_.end() || !it->second.valid) return;
        std::string& e = it->second.expr;
        // "(k * X) << S" -> "(k<<S) * X"
        size_t p = e.rfind(" << ");
        if (p == std::string::npos) return;
        std::string lhs = e.substr(0, p), rhs = e.substr(p + 4);
        if (lhs.size() < 2 || lhs.front() != '(' || lhs.back() != ')') return;
        lhs = lhs.substr(1, lhs.size() - 2);
        size_t q = lhs.find(" * ");
        if (q == std::string::npos) return;
        std::string k = lhs.substr(0, q);
        if (k.empty() || k.find_first_not_of("0123456789") != std::string::npos) return;
        if (rhs.empty() || rhs.find_first_not_of("0123456789") != std::string::npos) return;
        long long nk = atoll(k.c_str()) << atoll(rhs.c_str());
        e = std::to_string(nk) + " *" + lhs.substr(q + 2);
    }

    // yığına/üye'ye yazım cümlesi
    std::string MemWriteStmt(const MemOp& m, const std::string& val) {
        std::string target = MemExpr(m, false, false);
        return target + " = " + val + ";";
    }

    // ---- v5: SIMD lane yardımcıları -----------------------------------
    // movups/movdqu [base + idx*S + D] yüklemesinin k. eleman lane'i.
    // elemFloat: float dizisi (movups/movaps) mı, int dizisi (movdqu/movdqa) mı
    //   - struct üyesi dizi     -> o->notlar[k] / ali.notlar[k]
    //   - arg işaretçi (stride) -> a1[idx/4 + k]
    //   - değilse dürüst gösterim: *(float|int *)(base + idx + 4k)
    std::string VecLaneExpr(const MemOp& m, int k, bool elemFloat) {
        std::string baseE = RegExpr(m.base);
        std::string idxB;                     // bayt indeks ifadesi
        if (!m.index.empty()) {
            std::string e = RegExpr(m.index);
            idxB = (m.scale > 1) ? (Paren(e) + " * " + std::to_string(m.scale)) : e;
        }
        i64 disp = (i64)m.disp + 4 * (i64)k;
        // aN tabanlı erişim: argüman işaretçisi / struct işaretçisi
        const FuncSig* fsSelf = ti_.SigOf(funcVa_);
        for (int p = 0; p < 6; p++) {
            std::string an = "a" + std::to_string(p + 1);
            // v5: DWARF gerçek param adı da taban olabilir ("o", "dizi" ...)
            std::string pn = (fsSelf && p < 6) ? fsSelf->argNames[p] : "";
            if (!pn.empty()) {
                if (baseE == pn) an = pn;
                else if (baseE != an) continue;
            } else if (baseE != an) continue;
            // struct üyesi dizisi: o->notlar[k] üslubu
            if (const StructInfo* si = ti_.StructOfArg(funcVa_, p)) {
                u64 off = (u64)(disp < 0 ? 0 : disp);
                // v6: aralık çözümü — lane 1-3 dizi İÇİNE düşer (o+8 -> notlar[1])
                u64 elemIdx2 = 0;
                const StructMember* mem = si->MemberContaining(off, &elemIdx2);
                if (mem && mem->isArray && mem->stride == 4) {
                    u64 rel = off - mem->offset;
                    std::string idx;
                    if (idxB.empty()) {
                        idx = std::to_string(rel / 4);
                    } else {
                        // sabit + değişken indeks: (idx/4 + rel/4)
                        std::string bi = idxB;
                        if (rel) bi += " + " + std::to_string(rel);
                        idx = Paren(bi) + " / 4";
                    }
                    return an + "->" + MemberFieldName(si, mem->offset) +
                           "[" + idx + "]";
                }
            }
            const FuncSig* fs = ti_.SigOf(funcVa_);
            u32 stride = fs ? fs->argStride[p] : 0;
            // 4 = float*/int*, 16 = üzerinden SIMD okuması -> eleman 4 bayt
            if (stride == 4 || stride == 16) {
                std::string byteE = idxB;
                if (disp > 0) byteE += (byteE.empty() ? "" : " + ") + std::to_string(disp);
                else if (disp < 0) byteE += " - " + std::to_string(-disp);
                std::string idx;
                if (byteE.empty()) idx = "0";
                else if (IsNumberTok(byteE) && byteE.find("0x") != 0 &&
                         atoll(byteE.c_str()) % 4 == 0)
                    idx = std::to_string(atoll(byteE.c_str()) / 4);
                else idx = Paren(byteE) + " / 4";
                return an + "[" + idx + "]";
            }
        }
        // dürüst genel form
        std::string addr = baseE;
        if (!idxB.empty()) addr += " + " + idxB;
        if (disp > 0) addr += " + " + std::to_string(disp);
        else if (disp < 0) addr += " - " + std::to_string(-disp);
        return std::string("*( ") + (elemFloat ? "float" : "int") + " *)(" + addr + ")";
    }
    // vec yazmacın k. lane'i (yoksa boş)
    std::string LaneOf(const std::string& r, int k) {
        auto& st = RegStateOf(r);
        return (st.valid && st.vec && !st.lane[k].empty()) ? st.lane[k] : "";
    }
    // operandın lane'li vektör değeri: [mem] ise yükle (tür istenenden), değilse yazmaç
    bool VecOperand(const std::string& op, bool wantInt, std::string lane[4]) {
        if (op.find('[') != std::string::npos) {
            MemOp m = ParseMem(op);
            for (int k = 0; k < 4; k++) lane[k] = VecLaneExpr(m, k, !wantInt);
            return !lane[0].empty() && !lane[1].empty() &&
                   !lane[2].empty() && !lane[3].empty();
        }
        auto& st = RegStateOf(op);
        if (st.valid && st.vec && st.vecInt == wantInt) {
            for (int k = 0; k < 4; k++) lane[k] = st.lane[k];
            return !st.lane[0].empty() && !st.lane[1].empty() &&
                   !st.lane[2].empty() && !st.lane[3].empty();
        }
        return false;
    }
    void SetVec(const std::string& r, const std::string l[4], bool isInt) {
        RegState st; st.valid = true; st.vec = true; st.vecInt = isInt;
        for (int k = 0; k < 4; k++) st.lane[k] = l[k];
        regs_[CanonReg(r)] = st;
    }
    // koşul (son cmp/test + jcc)
    std::string CondFor(const std::string& jccMn) {
        std::string out;
        if (JccCond(jccMn, lastCmpLhs_, lastCmpRhs_, out)) return out;
        return jccMn + "(...)";
    }

    struct RegState { 
        bool valid = false; 
        std::string expr; 
        bool pristine = false; 
        // v5 SIMD lane modeli: yazmaç 4 paketli lane tutuyorsa vec=true
        // vecInt=true -> int lane'leri (movdqu/paddd), false -> float (movups/mulps)
        bool vec = false; 
        bool vecInt = false; 
        std::string lane[4]; 
    };
    std::map<std::string, RegState> regs_;
    std::string lastCmpLhs_, lastCmpRhs_;
    u64 ripTarget_ = 0;
    struct PendDiv { std::string num; u64 d; size_t endIdx; } ;
    std::vector<PendDiv> dummy_;   // (kullanılmıyor; pendingDiv_ tekil)
    PendDiv pendingDiv_ = {"", 0, (size_t)-1};

    std::map<i64, StackVar> vars_;
    std::set<i64> objects_;
    std::vector<i64> order_;
    int nLocals_ = 0;
    std::vector<std::string> lastImm_ = {"", "", "", "", "", ""};

    Analyzer& az_;
    TypeInferer& ti_;
    u64 funcVa_;
    bool isElf_;
    const char** argRegs_;
    int nArgRegs_;

public:
    static constexpr i64 RSP_OBJ_KEY = 0x1000000ll;
    const std::map<i64, StackVar>& Vars() const { return vars_; }
    const std::vector<i64>& VarOrder() const { return order_; }
    const RegState& RegStateOf(const std::string& r) const {
        static RegState invalid;
        auto it = regs_.find(CanonReg(r));
        return it == regs_.end() ? invalid : it->second;
    }
    // SSA artığı aktarımı: register durumunun kopyalanabilir anlık görüntüsü
    struct RegSnapshot { bool valid = false; std::string expr; bool vec = false;
                         bool vecInt = false; bool pristine = false;
                         std::string lane[4]; };
    void ExportRegs(std::map<std::string, RegSnapshot>& out) const {
        out.clear();
        for (auto& [k, v] : regs_) {
            RegSnapshot s; s.valid = v.valid; s.expr = v.expr; s.vec = v.vec;
            s.vecInt = v.vecInt; s.pristine = v.pristine;
            for (int i = 0; i < 4; i++) s.lane[i] = v.lane[i];
            out[k] = s;
        }
    }
    void ImportRegs(const std::map<std::string, RegSnapshot>& in) {
        regs_.clear();
        for (auto& [k, v] : in) {
            RegState st; st.valid = v.valid; st.expr = v.expr; st.vec = v.vec;
            st.vecInt = v.vecInt; st.pristine = v.pristine;
            for (int i = 0; i < 4; i++) st.lane[i] = v.lane[i];
            regs_[k] = st;
        }
    }
    void InheritFrom(const Folder& prev) { regs_ = prev.regs_; }
    void KillAllRegs() { regs_.clear(); }
    const PendDiv& PendingDiv() const { return pendingDiv_; }
    void ClearPendingDiv() { pendingDiv_ = PendDiv{"", 0, (size_t)-1}; }
};

} // anonim

// ----------------------------------------------------------------------------
// Ana decompile
// ----------------------------------------------------------------------------
std::string Pseudocoder::DecompileFunction(u64 start) {
    // v6: decompiler çekirdeği x86-64/32 içindir — ARM'da dürüst bilgi ver
    // (dis/funcs/xref/strings ARM'da tam çalışır; analiz-yoğun decomp v7 hedefi)
    Arch arch = az_.Engine().GetArch();
    if (arch == Arch::ARM64 || arch == Arch::ARM32) {
        const FuncInfo* fi = az_.FunctionStart(start);
        return std::string("// ============================================================\n") +
               "// " + (fi ? fi->name : "sub") + " — ARM" +
               (arch == Arch::ARM64 ? "64 (AArch64)" : "32") + " hedefi\n" +
               "// decompiler çekirdeği bu sürümde x86-64/x86-32 içindir.\n" +
               "// dis/funcs/xref/strings komutları bu mimaride TAM çalışır.\n" +
               "// ============================================================\n";
    }
    std::vector<Ins> ins = az_.DisassembleFunction(start, (size_t)opt_.maxInsPerFunc);
    if (ins.empty()) return "// bos fonksiyon\n";
    CFG cfg;
    if (!cfg.Build(ins)) return "// CFG kurulamadi\n";
    cfg.ResolveJumpTables(az_);   // jump table (switch) çözümü + kenarlar
    if (cfg.HasSwitches()) {
        // Case blokları dolaylı jmp hedefi olduğundan recursive disasm'de
        // çözülmemiş olabilir + leader de değillerdir: eksik komutları çöz,
        // ekstra leader ile CFG'yi yeniden kur, çözümü tekrarla.
        std::set<u64> swLeaders;
        bool added = false;
        const u64 funcEnd = ins.back().addr + ins.back().len;   // sabit: push'lar sıralı değil
        for (auto& sw : cfg.Switches()) {
            for (u64 t : sw.targets) {
                if (t < ins.front().addr || t >= funcEnd) continue;
                swLeaders.insert(t);
                bool exists = false;
                for (auto& x : ins) if (x.addr == t) { exists = true; break; }
                if (exists) continue;
                // t'den itibaren çöz; yalnız bilinen bir sonraki adrese kadarki
                // YENİ komutları ekle (case bloğu gövdesi)
                u64 nextKnown = (u64)-1;
                for (auto& x : ins)
                    if (x.addr > t && x.addr < nextKnown) nextKnown = x.addr;
                u64 endEx = (nextKnown != (u64)-1) ? nextKnown
                            : ins.back().addr + ins.back().len;
                auto more = az_.DisassembleLinear(t, endEx, 64);
                for (auto& x : more) {
                    bool dup = false;
                    for (auto& y : ins) if (y.addr == x.addr) { dup = true; break; }
                    if (!dup) { ins.push_back(x); added = true; }
                }
            }
            if (sw.defaultTarget) swLeaders.insert(sw.defaultTarget);
        }
        if (added)
            std::sort(ins.begin(), ins.end(),
                      [](const Ins& a, const Ins& b) { return a.addr < b.addr; });
        cfg.Build(ins, swLeaders);
        cfg.ResolveJumpTables(az_);
    }
    auto loops = cfg.DetectLoops();

    TypeInferer& ti = TI();
    const FuncSig* sig = ti.SigOf(start);
    const DwarfInfo* dwarf = ti.Dwarf();
    const bool isElf = az_.Bin().FormatName().find("ELF") != std::string::npos;

    // v7: x86-32 (PE32 cdecl/thiscall) kendi pseudocode yolunu kullanır —
    // 64-bit Folder SysV/Win64 register argümanlıdır; 32-bit yığın argütları
    // + devirt-pro sonuçlarıyla Hex-Rays üslubu üretir.
    if (az_.Engine().GetArch() == Arch::X86_32) {
        std::string r = Decompile32(start);
        if (!r.empty()) return r;
        // (düşme: 32-bit yol başarısızsa dürüst mesaj)
        return std::string("// ============================================================\n") +
               "// " + az_.NameFor(start) + "\n// x86-32 pseudocode kurulamadi\n";
    }

    // ---- başlık ----
    std::string fname = az_.NameFor(start);
    std::string sigLine;
    if (sig) {
        sigLine = sig->SignatureLine();
        // isim aynı mı (demangle "...(...)" olabilir)
        if (sigLine.find(fname) == std::string::npos) {
            // imzadaki adı koru, bizim adla değiştir
            size_t sp = sigLine.find(' ');
            sigLine = sigLine.substr(0, sp + 1) + fname +
                      sigLine.substr(sigLine.find('('));
        }
    } else {
        sigLine = "void " + fname + "(void)";
    }

    std::string out;
    out += "// ============================================================\n";
    out += "// " + fname + "  (" + std::to_string(ins.size()) + " komut, " +
           std::to_string(cfg.BlockCount()) + " blok" +
           (loops.empty() ? "" : ", " + std::to_string(loops.size()) + " dongu") + ")\n";
    out += "// kapsam: 0x" + ToHex(start) + " - 0x" +
           ToHex(ins.back().addr + ins.back().len) + "\n";
    out += "// ============================================================\n";
    out += sigLine + "\n";

    // ---- katlama altyapısı ----
    Folder folder(az_, ti, start, isElf);
    folder.DiscoverLocals(ins);

    // tanım blokları: kullanılan struct'lar
    std::set<int> usedStructs;
    {
        // arg struct'ları
        for (int i = 0; i < 6; i++)
            if (const StructInfo* si = ti.StructOfArg(start, i)) usedStructs.insert(si->id);
        for (auto& [d, v] : folder.Vars())
            if (v.isStructLocal) {
                const StructInfo* si = ti.StructOfLocal(start, v.objBase);
                if (si) usedStructs.insert(si->id);
            }
    }
    for (auto& s : ti.Structs())
        if (usedStructs.count(s.id)) {
            std::string d = s.Decl();
            for (auto& ch : d)
                if (ch == '\n') ch = ' ';
            out += "// " + d + "\n";
        }

    out += "{\n";
    // yerel tanımları
    for (auto& d : folder.VarOrder()) {
        auto it = folder.Vars().find(d);
        if (it == folder.Vars().end()) continue;
        auto& v = it->second;
        if (v.name.empty() || v.name.rfind("a", 0) == 0) continue;   // arg alias tanimsiz
        std::string dispTxt = (d == Folder::RSP_OBJ_KEY)
            ? std::string("[rsp+0]") : ("[rbp" + (d < 0 ? std::string(" - 0x") : std::string(" + 0x")) +
                           ToHex((u64)(d < 0 ? -d : d)) + "]");
        out += "    " + v.type + " " + v.name + ";   // " + dispTxt + "\n";
    }
    if (!folder.VarOrder().empty()) out += "\n";

    // ---- yapılaştırılmış emisyon ----
    auto& blocks = cfg.Blocks();
    std::set<u64> consumed;
    int indent = 1;
    struct Line { int ind; std::string text; };
    std::vector<Line> lines;
    auto emit = [&](const std::string& s2) { lines.push_back({indent, s2}); };

    // döngü bölgeleri
    struct LoopRegion { u64 head, latch; bool isDo; };
    std::map<u64, LoopRegion> loopAtHead;   // head -> region
    std::set<u64> regionBlocks;             // herhangi bir döngü içindeki bloklar
    for (auto& lp : loops) {
        LoopRegion r{lp.head, lp.latch, false};
        // giriş incelemesi: head'e DIŞTAN gelen öncü var mı?
        const BasicBlock* hb = cfg.BlockAt(lp.head);
        bool externalToHead = false;
        if (hb)
            for (u64 p : hb->pred)
                if (p < lp.head || p > lp.latch) { externalToHead = true; break; }
        r.isDo = externalToHead;   // giriş doğrudan bloğun başına -> do-while
        loopAtHead[lp.head] = r;
        for (auto& b : blocks)
            if (b.start >= lp.head && b.start <= lp.latch) regionBlocks.insert(b.start);
    }

    // ==== v4: OPAQUE PREDICATE katlaması ====================================
    // Blok-bazlı sabit koşul kanıtı: blok içi katlama sonrası sondaki jcc'in
    // koşulu iki sabitse dallanmanın sonucu bellidir (opak öncül).
    std::map<u64, int> constBranch;      // blok başı -> +1 daima doğru / -1 daima yanlış
    {
        std::set<u64> latchSet;
        for (auto& [h, rg] : loopAtHead) latchSet.insert(rg.latch);
        for (auto& b : blocks) {
            if (b.insIdx.empty()) continue;
            const Ins& li = ins[b.insIdx.back()];
            if (!li.isJcc || li.isIndirect) continue;
            if (loopAtHead.count(b.start) || latchSet.count(b.start)) continue;
            Folder pf(az_, ti, start, isElf);
            pf.DiscoverLocals(ins);
            for (size_t k = 0; k + 1 < b.insIdx.size(); k++) {
                const Ins& xi = ins[b.insIdx[k]];
                if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                pf.Fold(xi, b.insIdx[k], ins);
            }
            std::string condS = pf.CondFor(li.mnemonic);
            long long lv, rv; std::string op;
            if (ParseConstCond(condS, lv, op, rv))
                constBranch[b.start] = EvalConstCond(lv, op, rv) ? 1 : -1;
        }
    }
    // ==== v4: ÖLÜ KOD eleme =================================================
    // Sabit dallanmalar tek kenara inince erişilemez kalan bloklar:
    // (yalnız katlama ÖNCESİ erişilebilir olup SONRASI erişilemez olanlar)
    std::set<u64> deadBlocks;
    if (!constBranch.empty()) {
        auto reachability = [&](bool foldConst) {
            std::set<u64> reach;
            std::vector<u64> work{blocks.front().start};
            reach.insert(blocks.front().start);
            while (!work.empty()) {
                u64 cur = work.back(); work.pop_back();
                const BasicBlock* bb = cfg.BlockAt(cur);
                if (!bb) continue;
                std::vector<u64> succs;
                for (auto& [t, et] : bb->succ) succs.push_back(t);
                if (foldConst) {
                    auto cb = constBranch.find(cur);
                    if (cb != constBranch.end()) {
                        const Ins& li = ins[bb->insIdx.back()];
                        succs.clear();
                        succs.push_back(cb->second > 0 ? li.target
                                                       : li.addr + li.len);
                    }
                }
                for (u64 t : succs)
                    if (t && !reach.count(t)) { reach.insert(t); work.push_back(t); }
            }
            return reach;
        };
        auto pre = reachability(false);
        auto post = reachability(true);
        for (u64 v : pre)
            if (!post.count(v)) deadBlocks.insert(v);
    }

    // ---- v4: koşul bloğu mu? (yükleme/adres-aritmetiği/cmp + jcc) — kısa devre adayı
    // O0'da dizi koşulları 8-9 komut sürer: mov,cltq(cdqe),lea,add,mov,test,jcc
    auto isCondBlock = [&](const BasicBlock* cb, u64 target) {
        if (!cb || cb->insIdx.empty()) return false;
        const Ins& j = ins[cb->insIdx.back()];
        if (!j.isJcc || j.isIndirect || j.target != target) return false;
        if (cb->insIdx.size() > 12) return false;
        for (size_t k = 0; k + 1 < cb->insIdx.size(); k++) {
            const Ins& yi = ins[cb->insIdx[k]];
            const std::string& m = yi.mnemonic;
            if (m != "mov" && m != "movsxd" && m != "movzx" && m != "movsx" &&
                m != "lea" && m != "cmp" && m != "test" && m != "cdqe" &&
                m != "cdq" && m != "add" && m != "sub")
                return false;
            // bellek YAZIMI olmasın (yalnız yük/okuma serbest)
            auto ops = SplitOps(yi.opStr);
            if (!ops.empty() && ops[0].find('[') != std::string::npos &&
                (m == "mov" || m == "add" || m == "sub")) {
                // mov [mem], reg formu yazım — koşul bloğu değildir
                if (ops.size() == 2 && ops[1].find('[') == std::string::npos &&
                    (IsRegTok(ops[1]) || IsNumberTok(ops[1])))
                    return false;
            }
        }
        return true;
    };

    // ==== v5: ÖZYİNELEMELİ ÜST-DÜZEY yapılaştırıcı (iç içe else-if) ========
    // Döngü gövdesindeki emitRegion/tryDia ikilisinin üst-düzey muadili:
    // iç içe elmas zincirleri (if / else if / else) blok-blok değil
    // ÖZYİNELEMELİ yapılaştırılır — phi_ucyol deseni.
    std::function<void(u64, u64, Folder&)> emitTopRegion;
    std::function<bool(const BasicBlock&, u64, Folder&,
                       std::vector<std::string>&)> tryDiaTop;
    tryDiaTop = [&](const BasicBlock& bb, u64 hi, Folder& tf,
                    std::vector<std::string>& preStmts) -> bool {
        const Ins* l2 = bb.insIdx.empty() ? nullptr : &ins[bb.insIdx.back()];
        if (!l2 || !l2->isJcc || l2->isIndirect) return false;
        u64 B = l2->target, F = l2->addr + l2->len;
        const BasicBlock* bB = cfg.BlockAt(B);
        const BasicBlock* bF = cfg.BlockAt(F);
        if (!bB || !bF || B == F) return false;
        auto inRegion = [&](u64 v) { return v >= bb.start && v < hi; };
        if (!inRegion(B) || consumed.count(B)) return false;
        // --- yapısal kontroller ---
        const Ins* fLastJ = bF->insIdx.empty() ? nullptr : &ins[bF->insIdx.back()];
        bool fIsCond = isCondBlock(bF, B) && inRegion(fLastJ->addr);
        u64 thenLo = 0, thenHi = 0;
        bool shortCircuit = fIsCond;
        u64 scFall = 0;
        if (fIsCond) {
            u64 fFall = fLastJ->addr + fLastJ->len;
            scFall = fFall;
            thenLo = (B < fFall) ? B : fFall;
            thenHi = (B < fFall) ? fFall : B;
        } else {
            // düz elmas: birleşim J (F jmp J) veya F (else'siz)
            // v5: birleşim bölge SINIRI olabilir (thenHi == hi) — else-if zinciri
            if (fLastJ && fLastJ->isJmp && !fLastJ->isIndirect &&
                fLastJ->target >= bb.start && fLastJ->target <= hi &&
                !consumed.count(fLastJ->target))
                thenHi = fLastJ->target;
            else
                thenHi = F;
            thenLo = B;
        }
        if (thenHi <= thenLo) return false;
        std::vector<const BasicBlock*> thenB;
        for (auto& tb : blocks)
            if (tb.start >= thenLo && tb.start < thenHi && tb.start != F &&
                tb.start != bb.start && !consumed.count(tb.start))
                thenB.push_back(&tb);
        if (thenB.empty()) return false;
        // --- katlama (geri dönüş yok) ---
        for (auto& s : preStmts) emit(s);
        std::string condA = tf.CondFor(l2->mnemonic);
        std::string condAneg = tf.CondFor(NegJcc(l2->mnemonic));
        std::string cond2 = condA;
        bool scJoin = false;
        if (shortCircuit) {
            for (size_t k = 0; k < bF->insIdx.size(); k++) {
                const Ins& xi = ins[bF->insIdx[k]];
                if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                std::string st = tf.Fold(xi, bF->insIdx[k], ins);
                if (!st.empty()) emit(st);
            }
            std::string condF = tf.CondFor(fLastJ->mnemonic);
            std::string condFneg = tf.CondFor(NegJcc(fLastJ->mnemonic));
            if (B < scFall) {
                cond2 = condA + " || " + condF;
            } else {
                cond2 = condAneg + " && " + condFneg;
                scJoin = true;
            }
        }
        // else tarafı (yalnız düz elmas + F jmp J)
        std::vector<std::string> elseStmts;
        if (!shortCircuit && fLastJ && fLastJ->isJmp && !fLastJ->isIndirect &&
            fLastJ->target != F) {
            Folder ef2(az_, ti, start, isElf);
            ef2.DiscoverLocals(ins);
            for (size_t k = 0; k + 1 < bF->insIdx.size(); k++) {
                const Ins& xi = ins[bF->insIdx[k]];
                if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                std::string s = ef2.Fold(xi, bF->insIdx[k], ins);
                if (!s.empty()) elseStmts.push_back(s);
            }
        }
        // return yükseltme (v5): birleşim J saf epilogue ise kollar return alır
        const BasicBlock* bJ2 = cfg.BlockAt(thenHi);
        bool pureEpi = false;
        if (bJ2 && !bJ2->insIdx.empty()) {
            pureEpi = true;
            for (size_t k = 0; k < bJ2->insIdx.size(); k++) {
                const Ins& xi = ins[bJ2->insIdx[k]];
                if (xi.mnemonic != "leave" && xi.mnemonic != "ret" &&
                    xi.mnemonic != "pop" && xi.mnemonic != "nop") {
                    pureEpi = false; break;
                }
            }
        }
        auto armRet = [&](const Folder& f) -> std::string {
            if (!sig || sig->retKind == ArgKind::None) return "";
            if (sig->retKind == ArgKind::Float) {
                auto& xs = f.RegStateOf("xmm0");
                return (xs.valid && !xs.expr.empty()) ? xs.expr : "";
            }
            auto& rs = f.RegStateOf("rax");
            return (rs.valid && !rs.expr.empty()) ? rs.expr : "";
        };
        // ternary: iki taraf da tek atama VE aynı hedef
        {
            std::vector<std::string> thenDirect;
            bool thenSimple = true;
            for (auto* tb : thenB) {
                const Ins* t2 = !tb->insIdx.empty() ? &ins[tb->insIdx.back()] : nullptr;
                bool simpleTail = !t2 || (!t2->isJcc && !t2->isRet &&
                                          !(t2->isJmp && !t2->isIndirect &&
                                            t2->target != thenHi));
                if (tb->insIdx.size() > 8 || !simpleTail) thenSimple = false;
            }
            if (thenSimple) {
                Folder f2(az_, ti, start, isElf);
                f2.DiscoverLocals(ins);
                for (auto* tb : thenB) {
                    size_t skipTail = 0;
                    const Ins* t2 = !tb->insIdx.empty() ? &ins[tb->insIdx.back()] : nullptr;
                    if (t2 && t2->isJmp && !t2->isIndirect && t2->target == thenHi)
                        skipTail = 1;
                    for (size_t k = 0; k + skipTail < tb->insIdx.size(); k++) {
                        const Ins& xi = ins[tb->insIdx[k]];
                        if (xi.isJcc || xi.isRet) continue;
                        std::string s = f2.Fold(xi, tb->insIdx[k], ins);
                        if (!s.empty()) thenDirect.push_back(s);
                    }
                }
                if (thenDirect.size() == 1 && elseStmts.size() == 1) {
                    auto assignOf = [](const std::string& st, std::string& lhs,
                                       std::string& rhs) {
                        size_t eq = st.find(" = ");
                        if (eq == std::string::npos || st.size() < eq + 5) return false;
                        if (st.back() != ';') return false;
                        lhs = st.substr(0, eq);
                        rhs = st.substr(eq + 3, st.size() - eq - 4);
                        return !lhs.empty() && !rhs.empty() &&
                               lhs.find(' ') == std::string::npos;
                    };
                    std::string l1, r1, l2b, r2;
                    if (assignOf(thenDirect[0], l1, r1) &&
                        assignOf(elseStmts[0], l2b, r2) && l1 == l2b) {
                        emit(l1 + " = ( " + cond2 + " ) ? " + r1 + " : " + r2 + ";");
                        consumed.insert(F);
                        if (!scJoin) consumed.insert(B);
                        for (auto* tb : thenB) consumed.insert(tb->start);
                        return true;
                    }
                }
                // v5: İKİ KOL DA SAF RETURN ise ternary return (erken dönüş zinciri)
                if (pureEpi && thenDirect.empty() && elseStmts.empty()) {
                    // kolların ifadeleri ayrı katlayıcılardan alınmalı:
                    // thenDirect boş ≠ değer yok — katla:
                    Folder f3(az_, ti, start, isElf);
                    f3.DiscoverLocals(ins);
                    for (auto* tb : thenB) {
                        size_t skipTail = 0;
                        const Ins* t3 = !tb->insIdx.empty() ? &ins[tb->insIdx.back()] : nullptr;
                        if (t3 && t3->isJmp && !t3->isIndirect && t3->target == thenHi)
                            skipTail = 1;
                        for (size_t k = 0; k + skipTail < tb->insIdx.size(); k++) {
                            const Ins& xi = ins[tb->insIdx[k]];
                            if (xi.isJcc || xi.isRet) continue;
                            f3.Fold(xi, tb->insIdx[k], ins);
                        }
                    }
                    Folder f4(az_, ti, start, isElf);
                    f4.DiscoverLocals(ins);
                    if (!shortCircuit && fLastJ && fLastJ->isJmp && !fLastJ->isIndirect &&
                        fLastJ->target != F) {
                        for (size_t k = 0; k + 1 < bF->insIdx.size(); k++) {
                            const Ins& xi = ins[bF->insIdx[k]];
                            if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                            f4.Fold(xi, bF->insIdx[k], ins);
                        }
                    }
                    std::string rT = armRet(f3), rE = armRet(f4);
                    if (!rT.empty() && !rE.empty() && rT != rE) {
                        emit("return ( " + cond2 + " ) ? " + rT + " : " + rE + ";");
                        consumed.insert(F);
                        if (!scJoin) consumed.insert(B);
                        for (auto* tb : thenB) consumed.insert(tb->start);
                        consumed.insert(thenHi);   // epilogue yutuldu
                        return true;
                    }
                }
                // v5: genel durum — basit bölge DÜZ (+ return yükseltme)
                emit("if ( " + cond2 + " ) {");
                indent++;
                for (auto& s : thenDirect) emit(s);
                if (pureEpi) {
                    Folder f3(az_, ti, start, isElf);
                    f3.DiscoverLocals(ins);
                    for (auto* tb : thenB) {
                        size_t skipTail = 0;
                        const Ins* t3 = !tb->insIdx.empty() ? &ins[tb->insIdx.back()] : nullptr;
                        if (t3 && t3->isJmp && !t3->isIndirect && t3->target == thenHi)
                            skipTail = 1;
                        for (size_t k = 0; k + skipTail < tb->insIdx.size(); k++) {
                            const Ins& xi = ins[tb->insIdx[k]];
                            if (xi.isJcc || xi.isRet) continue;
                            f3.Fold(xi, tb->insIdx[k], ins);
                        }
                    }
                    std::string rT = armRet(f3);
                    if (!rT.empty()) emit("return " + rT + ";");
                }
                indent--;
                if (!elseStmts.empty() || pureEpi) {
                    emit("} else {");
                    indent++;
                    for (auto& s : elseStmts) emit(s);
                    if (pureEpi) {
                        Folder f4(az_, ti, start, isElf);
                        f4.DiscoverLocals(ins);
                        if (!shortCircuit && fLastJ && fLastJ->isJmp && !fLastJ->isIndirect &&
                            fLastJ->target != F) {
                            for (size_t k = 0; k + 1 < bF->insIdx.size(); k++) {
                                const Ins& xi = ins[bF->insIdx[k]];
                                if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                                f4.Fold(xi, bF->insIdx[k], ins);
                            }
                        }
                        std::string rE = armRet(f4);
                        if (!rE.empty()) emit("return " + rE + ";");
                    }
                    indent--;
                }
                emit("}");
                if (pureEpi) consumed.insert(thenHi);
                consumed.insert(F);
                if (!scJoin) consumed.insert(B);
                for (auto* tb : thenB) consumed.insert(tb->start);
                return true;
            }
            // karmaşık then: özyinelemeli bölge (+ else return yükseltme)
            emit("if ( " + cond2 + " ) {");
            indent++;
            {
                Folder tf2(az_, ti, start, isElf);
                tf2.DiscoverLocals(ins);
                emitTopRegion(thenLo, thenHi, tf2);
            }
            indent--;
            {
                // else tarafı: yalnız F'nin komutları (jmp hariç)
                Folder ef3(az_, ti, start, isElf);
                ef3.DiscoverLocals(ins);
                std::vector<std::string> es3;
                for (size_t k = 0; k + 1 < bF->insIdx.size(); k++) {
                    const Ins& xi = ins[bF->insIdx[k]];
                    if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                    std::string s = ef3.Fold(xi, bF->insIdx[k], ins);
                    if (!s.empty()) es3.push_back(s);
                }
                std::string rE = armRet(ef3);
                if (!es3.empty() || (pureEpi && !rE.empty())) {
                    emit("} else {");
                    indent++;
                    for (auto& s : es3) emit(s);
                    if (pureEpi && !rE.empty()) emit("return " + rE + ";");
                    indent--;
                }
            }
            emit("}");
            if (pureEpi) consumed.insert(thenHi);
            consumed.insert(F);
            if (!scJoin) consumed.insert(B);
            for (auto* tb : thenB) consumed.insert(tb->start);
            return true;
        }
        return false;
    };
    emitTopRegion = [&](u64 lo, u64 hi, Folder& tf) {
        for (auto& bb : blocks) {
            if (bb.start < lo || bb.start >= hi) continue;
            if (consumed.count(bb.start)) continue;
            const Ins* l2 = bb.insIdx.empty() ? nullptr : &ins[bb.insIdx.back()];
            bool tailCtrl = l2 && (l2->isJmp || l2->isJcc) && !l2->isIndirect;
            std::vector<std::string> stmts;
            size_t nFold = tailCtrl ? bb.insIdx.size() - 1 : bb.insIdx.size();
            for (size_t k = 0; k < nFold; k++) {
                const Ins& xi = ins[bb.insIdx[k]];
                if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                if (dwarf) {
                    const DwarfInline* di = dwarf->InlineAt(xi.addr);
                    if (di && !di->funcName.empty() && xi.addr == di->low)
                        emit("// >>> " + di->funcName +
                             "() buraya inline edilmis (DWARF kaniti)");
                }
                std::string stmt = tf.Fold(xi, bb.insIdx[k], ins);
                if (!stmt.empty()) stmts.push_back(stmt);
            }
            if (tailCtrl && l2->isJcc && tryDiaTop(bb, hi, tf, stmts)) {
                consumed.insert(bb.start);
                continue;
            }
            for (auto& s : stmts) emit(s);
            if (!tailCtrl) {
                if (l2 && l2->isRet) {
                    auto& rs = tf.RegStateOf("rax");
                    if (sig && sig->retKind == ArgKind::Float) {
                        auto& xs = tf.RegStateOf("xmm0");
                        if (xs.valid) { emit("return " + xs.expr + ";"); }
                        else emit("return;");
                    } else if (sig && sig->retKind != ArgKind::None && rs.valid)
                        emit("return " + rs.expr + ";");
                    else emit("return;");
                }
            } else if (l2->isJmp) {
                u64 T = l2->target;
                if (T == hi) {
                    // bölge sonu (birleşim): sessiz — kontrol if/else sonrasına akar
                } else if (T >= lo && T < hi) {
                    // bölge içine düşen akış: hedef sıradaki blok olarak işlenir
                } else {
                    emit("goto 0x" + ToHex(T) + ";");
                }
            } else {
                u64 T = l2->target;
                if (T >= lo && T < hi) {
                    // iç elmas tryDiaTop çözemedi: koşullu goto dürüstçe
                    std::string c2 = tf.CondFor(l2->mnemonic);
                    emit("if ( " + c2 + " ) goto 0x" + ToHex(T) + ";");
                } else {
                    std::string c2 = tf.CondFor(l2->mnemonic);
                    emit("if ( " + c2 + " ) goto 0x" + ToHex(T) + ";");
                }
            }
            consumed.insert(bb.start);
        }
    };

    // blok başına Folder durumu (koşul için latch'i ayrı katla)
    // SSA artığı temizliği: tek öncülü bloklar öncülün register durumunu miras alır
    std::map<u64, std::map<std::string, Folder::RegSnapshot>> exitState_;
    // v6: blok durumu ice aktarma — tek oncul: dogrudan; COK oncul:
    // onceden emit edilmis (consumed) ve durumu bilinen onculden al.
    // Derleyicinin init-trambolinli kuyruklarinda (simd_dot n%4) phi
    // isimleri (v1/v2) döngü sonrasi birlesim bloklarına böyle akar;
    // aksi halde ham rax/xmm0 kalıyordu.
    auto importExitState = [&](Folder& f, const BasicBlock& bb) {
        if (bb.pred.size() == 1) {
            auto pit = exitState_.find(bb.pred[0]);
            if (pit != exitState_.end()) f.ImportRegs(pit->second);
            return;
        }
        const std::map<std::string, Folder::RegSnapshot>* best = nullptr;
        for (u64 pr : bb.pred) {
            if (!consumed.count(pr)) continue;      // henüz emit edilmemis öncül
            auto pit = exitState_.find(pr);
            if (pit != exitState_.end() && !pit->second.empty()) best = &pit->second;
        }
        if (best) f.ImportRegs(*best);
    };
    for (auto& b : blocks) {
        if (consumed.count(b.start)) continue;
        // v4: ölü kod — sabit dallanma katlaması sonrası erişilemez
        if (deadBlocks.count(b.start)) { consumed.insert(b.start); continue; }

        // döngü başı?
        auto lit = loopAtHead.find(b.start);
        if (lit != loopAtHead.end()) {
            LoopRegion& r = lit->second;
            // latch bloğunu bul
            const BasicBlock* L = cfg.BlockAt(r.latch);
            const BasicBlock* H = cfg.BlockAt(r.head);
            if (!L || !H) { consumed.insert(b.start); continue; }

            // gövde: [head .. latch) + latch'in cmp öncesi komutları
            // latch koşulu: latch bloğunun sondan cmp/test + jcc'si
            const std::vector<Ins>& fi = ins;
            // latch jcc ve cmp indekslerini bul
            auto& lidx = L->insIdx;
            if (lidx.size() < 2) { consumed.insert(b.start); continue; }
            size_t jccPos = lidx.size() - 1;
            // jcc sonda olmayabilir (jmp sonra gelebilir) — sondan ilk jcc/jmp bul
            while (jccPos > 0 && !fi[lidx[jccPos]].isJcc && !fi[lidx[jccPos]].isJmp)
                jccPos--;
            const Ins& jccI = fi[lidx[jccPos]];
            if (!jccI.isJcc) {  // koşulsuz geri dönüş -> sonsuz döngü
                emit("while (true) {");
                indent++;
                consumed.insert(b.start);
                continue;
            }
            size_t cmpPos = jccPos > 0 ? jccPos - 1 : 0;
            bool hasCmp = cmpPos != jccPos &&
                          (fi[lidx[cmpPos]].mnemonic == "cmp" ||
                           fi[lidx[cmpPos]].mnemonic == "test");

            // koşulu katlamak için latch'e kadar olan akışı katla:
            // (gövde katlanırken durum taşınır; latch'in cmp öncesi komutları da
            //  gövdenin sonuna ait)
            // ---- v5: PHI-SSA — döngü-taşıyıcı yazmaç analizi ----------------
            // 1) GİRİŞ durumu: döngü öncesi akışı katla (rax/rdi/xmm0 değerleri)
            Folder entryF(az_, ti, start, isElf);
            entryF.DiscoverLocals(ins);
            for (auto& bb : blocks) {
                if (bb.start >= r.head) break;      // döngü başına kadarki bloklar
                for (size_t k = 0; k < bb.insIdx.size(); k++) {
                    const Ins& xi = fi[bb.insIdx[k]];
                    if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                    entryF.Fold(xi, bb.insIdx[k], fi);
                }
            }
            Folder condFolder(az_, ti, start, isElf);
            condFolder.DiscoverLocals(ins);
            // head..latch arası + latch cmp öncesi katla
            for (auto& bb : blocks) {
                if (bb.start < r.head || bb.start > r.latch) continue;
                size_t upto = (bb.start == r.latch) ? (hasCmp ? cmpPos + 1 : jccPos)
                                                    : bb.insIdx.size();
                for (size_t k = 0; k < upto; k++) {
                    const Ins& xi = fi[bb.insIdx[k]];
                    if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                    condFolder.Fold(xi, bb.insIdx[k], fi);
                }
            }
            std::string cond = condFolder.CondFor(jccI.mnemonic);
            // 2) döngü-taşıyıcı yazmaçlar: giriş != gövde çıkışı -> phi değişkeni
            struct PhiVar { std::string reg, name, type, init; };
            std::vector<PhiVar> phis;
            std::map<std::string, Folder::RegSnapshot> seeded;
            {
                std::map<std::string, Folder::RegSnapshot> entrySnap, exitSnap;
                entryF.ExportRegs(entrySnap);
                condFolder.ExportRegs(exitSnap);
                // sonraki vN adı (stack vN'lerle çakışmasın)
                int maxV = 0;
                for (auto& [d, v] : folder.Vars())
                    if (v.name.size() > 1 && v.name[0] == 'v')
                        maxV = std::max(maxV, atoi(v.name.c_str() + 1));
                int nextV = maxV + 1;
                // döngü SONRASI kullanım taraması (yalnız kullanılacak yazmaçlara phi)
                auto regUsedAfter = [&](const std::string& root) {
                    std::string n32;
                    if (root.size() == 3 && root[0] == 'r')
                        n32 = "e" + root.substr(1);      // rax -> eax
                    for (auto& bb : blocks) {
                        if (bb.start <= r.latch) continue;
                        if (loopAtHead.count(bb.start)) continue;   // iç içe döngü
                        for (size_t k : bb.insIdx) {
                            const Ins& xi = fi[k];
                            if (xi.opStr.find(root) != std::string::npos) return true;
                            if (!n32.empty() &&
                                xi.opStr.find(n32) != std::string::npos) return true;
                        }
                    }
                    return false;
                };
                for (auto& [rg, es] : exitSnap) {
                    if (!es.valid || es.vec) continue;
                    // v5: pristine argüman yazmacı = döngü DOKUNMADI
                    // (taze katlayıcının aN varsayılanı) — sahte phi üretmez:
                    // giriş değeri aynen akar
                    if (es.pristine) continue;
                    auto eit = entrySnap.find(rg);
                    bool entryValid = eit != entrySnap.end() && eit->second.valid &&
                                      !eit->second.vec;
                    if (entryValid && eit->second.expr != es.expr) {
                        // döngü-taşıyıcı aday
                        bool isXmm = rg.size() > 3 && rg.rfind("xmm", 0) == 0;
                        if (!regUsedAfter(rg) && rg != "rax" && rg != "xmm0") continue;
                        PhiVar pv;
                        pv.reg = rg;
                        pv.name = "v" + std::to_string(nextV++);
                        pv.type = isXmm ? "float" : "__int64";
                        pv.init = eit->second.expr;
                        phis.push_back(pv);
                    }
                }
                // tohum durumu: giriş değerleri + phi yazmaçları kendi adlarıyla
                seeded = entrySnap;
                for (auto& pv : phis) {
                    Folder::RegSnapshot s;
                    s.valid = true;
                    s.expr = pv.name;
                    seeded[pv.reg] = s;
                }
            }
            // 3) koşulu tohumlanmış durumla YENİDEN katla (phi adları görünsün)
            if (!phis.empty()) {
                Folder cf2(az_, ti, start, isElf);
                cf2.DiscoverLocals(ins);
                cf2.ImportRegs(seeded);
                for (auto& bb : blocks) {
                    if (bb.start < r.head || bb.start > r.latch) continue;
                    size_t upto = (bb.start == r.latch) ? (hasCmp ? cmpPos + 1 : jccPos)
                                                        : bb.insIdx.size();
                    for (size_t k = 0; k < upto; k++) {
                        const Ins& xi = fi[bb.insIdx[k]];
                        if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                        cf2.Fold(xi, bb.insIdx[k], fi);
                    }
                }
                std::string cond2 = cf2.CondFor(jccI.mnemonic);
                if (cond2 != cond) cond = cond2;
            }

            // ---- v4: yapılaştırılmış gövde emisyonu ------------------------
            // break/continue kurtarma + iç içe if/else + kısa devre + ternary
            // v5: phi başlangıçları (birikimli değişken tanımları) döngüden önce
            for (auto& pv : phis)
                emit(pv.type + " " + pv.name + " = " + pv.init + ";   // phi: " +
                     pv.reg + " döngü-taşıyıcı");
            size_t headerLineIdx = lines.size();
            if (r.isDo) {
                emit("do {");
            } else {
                emit("while ( " + cond + " ) {");
            }
            indent++;
            Folder body(az_, ti, start, isElf);
            body.DiscoverLocals(ins);
            if (!seeded.empty()) body.ImportRegs(seeded);   // v5: phi tohumlaması

            // bölgeden dışarı çıkan hedefler (break hedefleri)
            std::set<u64> exitTargets;
            for (auto& bb : blocks) {
                if (bb.start < r.head || bb.start > r.latch) continue;
                for (auto& [t, et] : bb.succ)
                    if (t < r.head || t > r.latch) exitTargets.insert(t);
            }
            // döngü çıkışı: latch jcc'inin düşen akışı (while yanlış yolu)
            u64 loopExit = jccI.addr + jccI.len;

            // ---- v4: ÖZYİNELEMELİ gövde yapılaştırıcı -----------------------
            // emitRegion(lo, hi): [lo, hi) bloklarını sırayla yapılaştırır;
            // iç elmaslar (tryDia) kendi then/else bölgelerini yine
            // emitRegion ile çözer — iç içe if/&&/||/ternary/break/continue.
            std::function<void(u64, u64)> emitRegion;
            std::function<bool(const BasicBlock&, std::vector<std::string>&)> tryDia;

            tryDia = [&](const BasicBlock& bb,
                         std::vector<std::string>& preStmts) -> bool {
                const Ins* l2 = bb.insIdx.empty() ? nullptr : &ins[bb.insIdx.back()];
                if (!l2 || !l2->isJcc || l2->isIndirect) return false;
                u64 B = l2->target, F = l2->addr + l2->len;
                const BasicBlock* bB = cfg.BlockAt(B);
                const BasicBlock* bF = cfg.BlockAt(F);
                if (!bB || !bF || B == F) return false;
                auto inRegion = [&](u64 v) { return v >= r.head && v <= r.latch; };
                if (!inRegion(B) || consumed.count(B)) return false;
                if (B == r.latch || F == r.latch) return false;
                if (loopAtHead.count(B)) return false;      // iç içe döngü başı
                // --- yapısal kontroller (katlamadan önce: geri dönüş güvenli) ---
                const Ins* fLastJ = bF->insIdx.empty() ? nullptr : &ins[bF->insIdx.back()];
                bool fIsCond = isCondBlock(bF, B) && inRegion(fLastJ->addr);
                std::vector<const BasicBlock*> thenB;
                bool shortCircuit = fIsCond;
                u64 scFall = 0;                    // kısa devre: F'in düşen akışı
                u64 thenLo = 0, thenHi = 0;        // then bölge sınırları
                bool thenSimple = true;            // tek blok + kontrol akışsız → ternary adayı
                if (fIsCond) {
                    u64 fFall = fLastJ->addr + fLastJ->len;
                    scFall = fFall;
                    thenLo = (B < fFall) ? B : fFall;    // || : then B..fFall | && : gövde fFall..B
                    thenHi = (B < fFall) ? fFall : B;
                } else {
                    // düz elmas: birleşim J (F jmp J) veya F (else'siz)
                    if (fLastJ && fLastJ->isJmp && !fLastJ->isIndirect &&
                        inRegion(fLastJ->target) && !consumed.count(fLastJ->target))
                        thenHi = fLastJ->target;
                    else
                        thenHi = F;
                    thenLo = B;
                }
                for (auto& tb : blocks)
                    if (tb.start >= thenLo && tb.start < thenHi && tb.start != F &&
                        tb.start != bb.start && !consumed.count(tb.start)) {
                        thenB.push_back(&tb);
                        const Ins* t2 = !tb.insIdx.empty() ? &ins[tb.insIdx.back()] : nullptr;
                        bool simpleTail = !t2 || (!t2->isJcc && !t2->isRet &&
                                                  !(t2->isJmp && !t2->isIndirect &&
                                                    t2->target != thenHi));
                        if (tb.insIdx.size() > 8 || !simpleTail) thenSimple = false;
                    }
                if (thenB.empty()) return false;
                // --- nokta: katlama başlıyor (geri dönüş yok) ---
                for (auto& s : preStmts) emit(s);
                std::string condA   = body.CondFor(l2->mnemonic);
                std::string condAneg= body.CondFor(NegJcc(l2->mnemonic));
                std::string cond2 = condA;
                bool scJoin = false;        // && düzeni: B birleşim (tüketilmez)
                if (shortCircuit) {
                    for (size_t k = 0; k < bF->insIdx.size(); k++) {
                        const Ins& xi = ins[bF->insIdx[k]];
                        if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                        std::string st = body.Fold(xi, bF->insIdx[k], ins);
                        if (!st.empty()) emit(st);
                    }
                    std::string condF    = body.CondFor(fLastJ->mnemonic);
                    std::string condFneg = body.CondFor(NegJcc(fLastJ->mnemonic));
                    if (B < scFall) {
                        // || : ortak hedef önce — then = [B, fFall)
                        cond2 = condA + " || " + condF;
                    } else {
                        // ortak hedef B SONDA — iki alt düzen:
                        // (a) B = continue trambolünü -> if (A || F) continue;
                        const BasicBlock* bB2 = cfg.BlockAt(B);
                        const Ins* bJ = (bB2 && !bB2->insIdx.empty())
                            ? &ins[bB2->insIdx.back()] : nullptr;
                        bool bIsTramp = bJ && bJ->isJmp && !bJ->isIndirect &&
                                        bB2->insIdx.size() == 1 &&
                                        (bJ->target == r.latch || bJ->target == r.head);
                        if (bIsTramp) {
                            emit("if ( " + condA + " || " + condF + " ) continue;");
                            consumed.insert(F); consumed.insert(B);
                            return true;
                        }
                        // (b) B = birleşim -> if (!A && !F) { gövde [fFall, B) }
                        cond2 = condAneg + " && " + condFneg;
                        scJoin = true;
                    }
                }
                // else tarafı (yalnız düz elmas + F jmp J durumu)
                std::vector<std::string> elseStmts;
                bool elseSimple = true;
                if (!shortCircuit && fLastJ && fLastJ->isJmp && !fLastJ->isIndirect &&
                    fLastJ->target != F) {
                    Folder ef2(az_, ti, start, isElf);
                    ef2.DiscoverLocals(ins);
                    for (size_t k = 0; k + 1 < bF->insIdx.size(); k++) {
                        const Ins& xi = ins[bF->insIdx[k]];
                        if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                        std::string s = ef2.Fold(xi, bF->insIdx[k], ins);
                        if (!s.empty()) elseStmts.push_back(s);
                    }
                }
                // ternary (v4): iki taraf da tek atama VE aynı hedef VE bölgeler basit
                {
                    // then bölgesini katla (basitse direkt, değilse özyinelemeli)
                    // basit = her blok kontrol akışsız → tekil atama listesi alınabilir
                    auto foldSimple = [&](const std::vector<const BasicBlock*>& bl,
                                          std::vector<std::string>& out) {
                        Folder f2(az_, ti, start, isElf);
                        f2.DiscoverLocals(ins);
                        for (auto* tb : bl) {
                            size_t skipTail = 0;
                            const Ins* t2 = !tb->insIdx.empty()
                                ? &ins[tb->insIdx.back()] : nullptr;
                            if (t2 && t2->isJmp && !t2->isIndirect &&
                                t2->target == thenHi) skipTail = 1;
                            for (size_t k = 0; k + skipTail < tb->insIdx.size(); k++) {
                                const Ins& xi = ins[tb->insIdx[k]];
                                if (xi.isJcc || xi.isRet) continue;
                                std::string s = f2.Fold(xi, tb->insIdx[k], ins);
                                if (!s.empty()) out.push_back(s);
                            }
                        }
                    };
                    // ---- v4: REGISTER-TERNARY (O0 deseni) ----
                    // Kollar yalnız REGISTER'e hesap yapıyorsa (cümle üretmiyorsa)
                    // sonuç ? : ifadesine katlanıp body durumuna phi gibi yazılır;
                    // birleşim bloğundaki kullanım (v1 += ...) buna erir.
                    if (thenSimple && !shortCircuit && !scJoin &&
                        thenB.size() == 1 && thenB[0]->insIdx.size() <= 8) {
                        const BasicBlock* tb = thenB[0];
                        const Ins* t2 = !tb->insIdx.empty() ? &ins[tb->insIdx.back()] : nullptr;
                        bool thenEndsOk = !t2 || !t2->isRet;
                        bool elseEndsOk = true;
                        const Ins* f2Last = !bF->insIdx.empty() ? &ins[bF->insIdx.back()] : nullptr;
                        if (f2Last && f2Last->isRet) elseEndsOk = false;
                        if (f2Last && f2Last->isJcc && !f2Last->isIndirect &&
                            f2Last->target != thenHi)
                            elseEndsOk = false;   // F kendi içinde dallanıyor
                        if (thenEndsOk && elseEndsOk) {
                            auto foldArm = [&](const BasicBlock* ab, u64 skipTarget,
                                               std::string& expr, bool& pure) {
                                Folder af(az_, ti, start, isElf);
                                af.DiscoverLocals(ins);
                                pure = true;
                                size_t last = ab->insIdx.size();
                                if (skipTarget) {
                                    const Ins* aLast = &ins[ab->insIdx.back()];
                                    if (aLast->isJmp && !aLast->isIndirect &&
                                        aLast->target == skipTarget) last--;
                                }
                                for (size_t k = 0; k < last; k++) {
                                    const Ins& xi = ins[ab->insIdx[k]];
                                    if (xi.isJcc || xi.isRet) { pure = false; continue; }
                                    std::string s = af.Fold(xi, ab->insIdx[k], ins);
                                    if (!s.empty()) pure = false;
                                }
                                auto& rs = af.RegStateOf("rax");
                                expr = rs.valid ? rs.expr : "";
                            };
                            std::string eB, eF;
                            bool pB = false, pF = false;
                            foldArm(tb, thenHi, eB, pB);
                            foldArm(bF, thenHi, eF, pF);
                            if (pB && pF && !eB.empty() && !eF.empty() && eB != eF) {
                                body.SetReg("rax",
                                    "( " + cond2 + " ) ? " + eB + " : " + eF);
                                consumed.insert(F);
                                consumed.insert(B);
                                for (auto* t3 : thenB) consumed.insert(t3->start);
                                return true;
                            }
                        }
                    }
                    std::vector<std::string> thenDirect;
                    if (thenSimple) foldSimple(thenB, thenDirect);
                    // ternary denemesi
                    if (thenSimple && elseSimple && thenDirect.size() == 1 &&
                        elseStmts.size() == 1) {
                        auto assignOf = [](const std::string& st, std::string& lhs,
                                           std::string& rhs) {
                            size_t eq = st.find(" = ");
                            if (eq == std::string::npos || st.size() < eq + 5) return false;
                            if (st.back() != ';') return false;
                            lhs = st.substr(0, eq);
                            rhs = st.substr(eq + 3, st.size() - eq - 4);
                            return !lhs.empty() && !rhs.empty() &&
                                   lhs.find(' ') == std::string::npos;
                        };
                        std::string l1, r1, l2b, r2;
                        if (assignOf(thenDirect[0], l1, r1) &&
                            assignOf(elseStmts[0], l2b, r2) && l1 == l2b) {
                            emit(l1 + " = ( " + cond2 + " ) ? " + r1 + " : " + r2 + ";");
                            consumed.insert(F);
                            if (!scJoin) consumed.insert(B);
                            for (auto* tb : thenB) consumed.insert(tb->start);
                            return true;
                        }
                    }
                    // genel yapılaştırma: if / else
                    emit("if ( " + cond2 + " ) {");
                    indent++;
                    if (thenSimple) {
                        for (auto& s : thenDirect) emit(s);
                    } else {
                        // karmaşık then: özyinelemeli yapılaştır
                        for (auto* tb : thenB) {
                            if (consumed.count(tb->start)) continue;
                            emitRegion(tb->start, thenHi);
                        }
                    }
                    indent--;
                    if (!elseStmts.empty()) {
                        emit("} else {");
                        indent++;
                        for (auto& s : elseStmts) emit(s);
                        indent--;
                    }
                    emit("}");
                }
                consumed.insert(F);
                if (!scJoin) consumed.insert(B);   // && düzeninde B birleşimdir
                for (auto* tb : thenB) consumed.insert(tb->start);
                return true;
            };

            emitRegion = [&](u64 lo, u64 hi) {
                for (auto& bb : blocks) {
                    if (bb.start < lo || bb.start >= hi) continue;
                    if (consumed.count(bb.start)) continue;
                    const Ins* l2 = bb.insIdx.empty() ? nullptr : &ins[bb.insIdx.back()];
                    bool tailCtrl = l2 && (l2->isJmp || l2->isJcc) && !l2->isIndirect;
                    std::vector<std::string> stmts;
                    size_t nFold = tailCtrl ? bb.insIdx.size() - 1 : bb.insIdx.size();
                    for (size_t k = 0; k < nFold; k++) {
                        const Ins& xi = ins[bb.insIdx[k]];
                        if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                        std::string stmt = body.Fold(xi, bb.insIdx[k], ins);
                        if (!stmt.empty()) stmts.push_back(stmt);
                    }
                    if (tailCtrl && l2->isJcc && tryDia(bb, stmts)) {
                        consumed.insert(bb.start);
                        continue;
                    }
                    for (auto& s : stmts) emit(s);
                    if (!tailCtrl) {
                        if (l2 && l2->isRet) {
                            auto& rs = body.RegStateOf("rax");
                            if (sig && sig->retKind != ArgKind::None && rs.valid)
                                emit("return " + rs.expr + ";");
                            else
                                emit("return;");
                        }
                    } else if (l2->isJmp) {
                        u64 T = l2->target;
                        if (T == r.head || T == r.latch) emit("continue;");
                        else if (exitTargets.count(T)) emit("break;");
                        else {
                            // yalnız latch'e akan ön-blok (artış bloğu) -> continue
                            const BasicBlock* tb2 = cfg.BlockAt(T);
                            bool toLatchOnly = tb2 && tb2->succ.size() == 1 &&
                                               tb2->succ[0].first == r.latch;
                            if (toLatchOnly) emit("continue;");
                            else emit("goto 0x" + ToHex(T) + ";");
                        }
                    } else {
                        u64 T = l2->target;
                        std::string c2 = body.CondFor(l2->mnemonic);
                        if (exitTargets.count(T)) emit("if ( " + c2 + " ) break;");
                        else if (T == r.head || T == r.latch)
                            emit("if ( " + c2 + " ) continue;");
                        else {
                            const BasicBlock* tb2 = cfg.BlockAt(T);
                            bool toLatchOnly = tb2 && tb2->succ.size() == 1 &&
                                               tb2->succ[0].first == r.latch;
                            if (toLatchOnly) emit("if ( " + c2 + " ) continue;");
                            else emit("if ( " + c2 + " ) goto 0x" + ToHex(T) + ";");
                        }
                    }
                    consumed.insert(bb.start);
                }
            };

            // ---- gövde: [head, latch) özyinelemeli + latch katlaması ----
            emitRegion(r.head, r.latch);
            {
                const BasicBlock* L2 = cfg.BlockAt(r.latch);
                if (L2) {
                    size_t upto = hasCmp ? cmpPos : jccPos;
                    for (size_t k = 0; k < upto; k++) {
                        const Ins& xi = fi[L2->insIdx[k]];
                        if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                        std::string stmt = body.Fold(xi, L2->insIdx[k], fi);
                        if (!stmt.empty()) emit(stmt);
                    }
                    consumed.insert(r.latch);
                }
            }
            // ---- v5: PHI güncellemeleri — döngü sonunda birikimli atamalar ----
            // "((((v1) + p0) + p1) + p2) + p3" -> "v1 += p0 + p1 + p2 + p3;"
            // "v2 + 16"                          -> "v2 += 16;"
            for (auto& pv : phis) {
                auto& st = body.RegStateOf(pv.reg);
                if (!st.valid || st.expr.empty() || st.expr == pv.name) continue;
                std::string tail;
                if (UnwrapAccumulator(st.expr, pv.name, tail))
                    emit(pv.name + " += " + tail + ";");
                else
                    emit(pv.name + " = " + st.expr + ";");
            }
            // v5: latch çıkış durumu -> döngü SONRASI bloklar phi adlarını miras alır
            {
                std::map<std::string, Folder::RegSnapshot> snap;
                body.ExportRegs(snap);
                for (auto& pv : phis) {
                    Folder::RegSnapshot s;
                    s.valid = true;
                    s.expr = pv.name;
                    snap[pv.reg] = s;
                }
                exitState_[r.latch] = snap;
            }
            indent--;
            // ---- v4: for döngüsüne yükseltme ----
            // koşul "V (<|<=|>|>=) X" + gövdenin son cümlesi "V artışı" ise
            if (!r.isDo) {
                std::string cv;
                size_t p = cond.find(" < ");
                if (p == std::string::npos) p = cond.find(" <= ");
                if (p == std::string::npos) p = cond.find(" > ");
                if (p == std::string::npos) p = cond.find(" >= ");
                if (p != std::string::npos) cv = cond.substr(0, p);
                if (!cv.empty() && cv.find(' ') == std::string::npos) {
                    for (size_t i = lines.size(); i-- > headerLineIdx + 1;) {
                        std::string iv; int d = 0;
                        if (ParseIncrement(lines[i].text, iv, d) && iv == cv) {
                            // init: while öncesi son "V = <sayi>;" satırını çek
                            std::string init;
                            for (size_t j = headerLineIdx; j-- > 0;) {
                                const std::string& t = lines[j].text;
                                if (t.rfind(cv + " = ", 0) == 0 && t.back() == ';') {
                                    std::string val = t.substr(cv.size() + 3);
                                    val.pop_back();
                                    if (IsNumberTok(val)) {
                                        init = cv + " = " + val;
                                        lines[j].ind = -1;
                                        break;
                                    }
                                }
                            }
                            lines[i].ind = -1;
                            // v5: artış adımı ±1 değilse "v += N" biçiminde yaz
                            std::string step;
                            if (d == 1) step = "++" + cv;
                            else if (d == -1) step = "--" + cv;
                            else step = cv + (d > 0 ? " += " : " -= ") + std::to_string(d < 0 ? -d : d);
                            lines[headerLineIdx].text =
                                "for ( " + (init.empty() ? std::string() : init + "; ") +
                                cond + "; " + step + " ) {";
                            break;
                        }
                    }
                }
            }
            if (r.isDo) emit("} while ( " + cond + " );");
            else emit("}");
            continue;
        }

    // ---- normal blok ----
        // elmas (if/else) tespiti: son komut jcc ise
        const Ins* last = nullptr;
        if (!b.insIdx.empty()) last = &ins[b.insIdx.back()];
        bool handled = false;

        // ---- v4: sabit koşullu blok (opak öncül katlaması) ----
        // katlama kanıtladı: dallanma daima alınır ya da hiç alınmaz
        auto cbIt = constBranch.find(b.start);
        if (cbIt != constBranch.end() && last && last->isJcc && !last->isIndirect) {
            Folder bf(az_, ti, start, isElf);
            bf.DiscoverLocals(ins);
            importExitState(bf, b);
            for (size_t k = 0; k + 1 < b.insIdx.size(); k++) {
                const Ins& xi = ins[b.insIdx[k]];
                if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                std::string st = bf.Fold(xi, b.insIdx[k], ins);
                if (!st.empty()) emit(st);
            }
            if (cbIt->second > 0) {
                emit("// v4: kosul daima DOGRU (opak oncul katlandi) -> 0x" +
                     ToHex(last->target));
                if (!regionBlocks.count(last->target) &&
                    !consumed.count(last->target)) {
                    // hedef sıradaki CANLI blok mu? (ölü kod atlandıktan sonra
                    // doğal düşen akışla aynı yere gelirsek goto gereksiz)
                    bool nextNatural = false;
                    for (auto& nb : blocks)
                        if (nb.start > b.start && !deadBlocks.count(nb.start)) {
                            nextNatural = (nb.start == last->target);
                            break;
                        }
                    if (!nextNatural)
                        emit("goto 0x" + ToHex(last->target) + ";   // sabit dallanma");
                }
            } else {
                emit("// v4: kosul daima YANLIS (opak oncul katlandi) — dallanma budandi");
            }
            bf.ExportRegs(exitState_[b.start]);
            consumed.insert(b.start);
            continue;
        }

        if (last && last->isJcc && !last->isIndirect) {
            u64 B = last->target;                       // dallanılan (then)
            u64 F = last->addr + last->len;             // düşen akış (else adayı)
            const BasicBlock* bB = cfg.BlockAt(B);
            const BasicBlock* bF = cfg.BlockAt(F);
            if (bB && bF && B != F && !consumed.count(B) && !consumed.count(F) &&
                regionBlocks.find(B) == regionBlocks.end() &&
                regionBlocks.find(F) == regionBlocks.end()) {
                // ---- v5: KOŞULLU DÖNÜŞ DEĞERİ (branch-over-compute) --------
                // test/cmp + jcc RET + düşen akışta saf hesaplama:
                //   test eax,eax; je .ret; pxor; cvtsi2ss; mulss; .ret: ret
                // -> return ( kosul ) ? dallanma_degeri : hesap_degeri;
                {
                    bool pureRet = bB && !bB->insIdx.empty();
                    if (pureRet) {
                        for (size_t k = 0; k < bB->insIdx.size(); k++) {
                            const Ins& xi = ins[bB->insIdx[k]];
                            if (xi.mnemonic != "ret" && xi.mnemonic != "leave" &&
                                xi.mnemonic != "pop" && xi.mnemonic != "nop") {
                                pureRet = false; break;
                            }
                        }
                    }
                    const Ins* fL5 = !bF->insIdx.empty() ? &ins[bF->insIdx.back()] : nullptr;
                    bool fStraight = fL5 && !fL5->isJcc && !fL5->isJmp && !fL5->isRet;
                    if (pureRet && fStraight && !consumed.count(F)) {
                        Folder arf(az_, ti, start, isElf);
                        arf.DiscoverLocals(ins);
                        importExitState(arf, b);
                        for (size_t k = 0; k + 1 < b.insIdx.size(); k++) {
                            const Ins& xi = ins[b.insIdx[k]];
                            if (dwarf) {
                                const DwarfInline* di = dwarf->InlineAt(xi.addr);
                                if (di && !di->funcName.empty() && xi.addr == di->low)
                                    emit("// >>> " + di->funcName +
                                         "() buraya inline edilmis (DWARF kaniti)");
                            }
                            if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                            std::string st = arf.Fold(xi, b.insIdx[k], ins);
                            if (!st.empty()) emit(st);
                        }
                        std::string condA = arf.CondFor(last->mnemonic);
                        Folder frf(az_, ti, start, isElf);
                        frf.DiscoverLocals(ins);
                        // v5: F'ye A'nın durumu akar (düşen akış) — aksi halde
                        // cvtsi2ss eax gibi komutlar ham rax görür
                        {
                            std::map<std::string, Folder::RegSnapshot> asnap;
                            arf.ExportRegs(asnap);
                            frf.ImportRegs(asnap);
                        }
                        std::vector<std::string> fStmts;
                        for (size_t k = 0; k < bF->insIdx.size(); k++) {
                            const Ins& xi = ins[bF->insIdx[k]];
                            if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                            std::string st = frf.Fold(xi, bF->insIdx[k], ins);
                            if (!st.empty()) fStmts.push_back(st);
                        }
                        auto valOf = [&](const Folder& f) -> std::string {
                            if (sig && sig->retKind == ArgKind::Float) {
                                auto& xs = f.RegStateOf("xmm0");
                                if (xs.valid && !xs.expr.empty()) return xs.expr;
                                return "";
                            }
                            auto& rs = f.RegStateOf("rax");
                            if (rs.valid && !rs.expr.empty()) return rs.expr;
                            return "";
                        };
                        std::string vB = valOf(arf), vF = valOf(frf);
                        if (sig && sig->retKind != ArgKind::None &&
                            !vB.empty() && !vF.empty() && vB != vF &&
                            fStmts.empty() &&
                            condA.find('(') != std::string::npos) {
                            emit("return ( " + condA + " ) ? " + vB + " : " + vF + ";");
                            consumed.insert(F);
                            consumed.insert(B);
                            consumed.insert(b.start);
                            handled = true;
                        } else {
                            // değerler çözülemedi: if/return ikilisi dürüstçe
                            arf.ExportRegs(exitState_[b.start]);
                        }
                    }
                }
                // ---- v5: DÖNÜŞLE BİTEN elmas (erken dönüş) --------------------
                // B ve F ikisi de ret ile bitiyorsa:
                //   if ( cond ) { B-gövdesi; return ...; }   + F düz akışta
                if (!handled) {
                    const Ins* bL6 = !bB->insIdx.empty() ? &ins[bB->insIdx.back()] : nullptr;
                    const Ins* fL6 = !bF->insIdx.empty() ? &ins[bF->insIdx.back()] : nullptr;
                    bool bothRet = bL6 && bL6->isRet && fL6 && fL6->isRet &&
                                   !consumed.count(B);
                    if (bothRet) {
                        Folder arf(az_, ti, start, isElf);
                        arf.DiscoverLocals(ins);
                        importExitState(arf, b);
                        std::vector<std::string> aStmts;
                        for (size_t k = 0; k + 1 < b.insIdx.size(); k++) {
                            const Ins& xi = ins[b.insIdx[k]];
                            if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                            std::string st = arf.Fold(xi, b.insIdx[k], ins);
                            if (!st.empty()) aStmts.push_back(st);
                        }
                        std::string condA = arf.CondFor(last->mnemonic);
                        Folder brf(az_, ti, start, isElf);
                        brf.DiscoverLocals(ins);
                        {
                            std::map<std::string, Folder::RegSnapshot> asnap;
                            arf.ExportRegs(asnap);
                            brf.ImportRegs(asnap);
                        }
                        for (size_t k = 0; k + 1 < bB->insIdx.size(); k++) {
                            const Ins& xi = ins[bB->insIdx[k]];
                            if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                            std::string st = brf.Fold(xi, bB->insIdx[k], ins);
                            if (!st.empty()) aStmts.push_back(st);
                        }
                        auto retValOf = [&](const Folder& f) -> std::string {
                            if (sig && sig->retKind == ArgKind::Float) {
                                auto& xs = f.RegStateOf("xmm0");
                                if (xs.valid && !xs.expr.empty()) return xs.expr;
                                return ";";
                            }
                            auto& rs = f.RegStateOf("rax");
                            if (rs.valid && !rs.expr.empty()) return rs.expr;
                            return ";";
                        };
                        std::string bRet = retValOf(brf);
                        bool condReal = condA.find('<') != std::string::npos ||
                                        condA.find('>') != std::string::npos ||
                                        condA.find("==") != std::string::npos ||
                                        condA.find("!=") != std::string::npos ||
                                        condA.find("&&") != std::string::npos ||
                                        condA.find("||") != std::string::npos;
                        if (condReal) {
                            for (auto& st : aStmts) emit(st);
                            emit("if ( " + condA + " ) {");
                            indent++;
                            if (bRet != ";") emit("return " + bRet + ";");
                            else emit("return;");
                            indent--;
                            emit("}");
                            // F (düşen akış) doğal olarak sıradaki blokta işlenir
                            consumed.insert(B);
                            consumed.insert(b.start);
                            arf.ExportRegs(exitState_[b.start]);
                            handled = true;
                        }
                    }
                }
                // ---- v4: KISA DEVRE (short-circuit) birleştirme ----
                // F yalnız cmp/test + jcc->B ise: || (B önce) veya && (B sonra)
                if (!handled) {
                    const Ins* fJ = !bF->insIdx.empty() ? &ins[bF->insIdx.back()] : nullptr;
                    if (isCondBlock(bF, B)) {
                        u64 fFall = fJ->addr + fJ->len;
                        u64 lo = (B < fFall) ? B : fFall;
                        u64 hi = (B < fFall) ? fFall : B;
                        std::vector<const BasicBlock*> scThen;
                        for (auto& tb : blocks)
                            if (tb.start >= lo && tb.start < hi && tb.start != F &&
                                !consumed.count(tb.start) &&
                                regionBlocks.find(tb.start) == regionBlocks.end())
                                scThen.push_back(&tb);
                        if (!scThen.empty()) {
                            Folder cf(az_, ti, start, isElf);
                            cf.DiscoverLocals(ins);
                            for (size_t k = 0; k + 1 < b.insIdx.size(); k++) {
                                const Ins& xi = ins[b.insIdx[k]];
                                if (xi.isJcc || xi.isJmp) continue;
                                std::string st = cf.Fold(xi, b.insIdx[k], ins);
                                if (!st.empty()) emit(st);
                            }
                            std::string condA    = cf.CondFor(last->mnemonic);
                            std::string condAneg = cf.CondFor(NegJcc(last->mnemonic));
                            for (size_t k = 0; k < bF->insIdx.size(); k++) {
                                const Ins& xi = ins[bF->insIdx[k]];
                                if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                                std::string st = cf.Fold(xi, bF->insIdx[k], ins);
                                if (!st.empty()) emit(st);
                            }
                            std::string condFneg = cf.CondFor(NegJcc(fJ->mnemonic));
                            std::string condF    = cf.CondFor(fJ->mnemonic);
                            std::string sc = (B < fFall)
                                ? (condA + " || " + condF)
                                : (condAneg + " && " + condFneg);
                            u64 joinT = (B < fFall) ? fFall : B;
                            Folder tf0(az_, ti, start, isElf);
                            tf0.DiscoverLocals(ins);
                            std::vector<std::string> stmts0;
                            for (auto* tb : scThen) {
                                size_t skipTail = 0;
                                const Ins* t2 = !tb->insIdx.empty()
                                    ? &ins[tb->insIdx.back()] : nullptr;
                                if (t2 && t2->isJmp && !t2->isIndirect &&
                                    t2->target == joinT) skipTail = 1;
                                for (size_t k = 0; k + skipTail < tb->insIdx.size(); k++) {
                                    const Ins& xi = ins[tb->insIdx[k]];
                                    if (xi.isJcc || xi.isRet) continue;
                                    std::string s = tf0.Fold(xi, tb->insIdx[k], ins);
                                    if (!s.empty()) stmts0.push_back(s);
                                }
                            }
                            emit("if ( " + sc + " ) {");
                            indent++;
                            for (auto& s : stmts0) emit(s);
                            indent--;
                            emit("}");
                            consumed.insert(F);
                            if (B < fFall) consumed.insert(B);   // && düzeninde B birleşim
                            for (auto* tb : scThen) consumed.insert(tb->start);
                            handled = true;
                        }
                    }
                }   // if (!handled): kısa devre sonu
                // F jmp J ile bitiyor mu ve J > B'nin sonu mu?
                const Ins* fLast = !bF->insIdx.empty() ? &ins[bF->insIdx.back()] : nullptr;
                if (!handled && fLast && fLast->isJmp && !fLast->isIndirect) {
                    u64 J = fLast->target;
                    if (J > bB->end && !consumed.count(J)) {
                        // then-bölgesi: [B .. J'ye kadar)
                        std::vector<const BasicBlock*> thenBlocks;
                        for (auto& tb : blocks)
                            if (tb.start >= B && tb.start < J && tb.start != F)
                                thenBlocks.push_back(&tb);
                        // else: F bloğu (jmp hariç)
                        // A-blogunun kendi komutlari (cagri/atanim dahil) +
                        // kosul katlamasi (jcc oncesi)
                        std::string cond;
                        std::vector<std::string> preStmts;
                        {
                            Folder cf(az_, ti, start, isElf);
                            cf.DiscoverLocals(ins);
                            for (size_t k = 0; k + 1 < b.insIdx.size(); k++) {
                                const Ins& xi = ins[b.insIdx[k]];
                                if (xi.isJcc || xi.isJmp) continue;
                                std::string st = cf.Fold(xi, b.insIdx[k], ins);
                                if (!st.empty()) preStmts.push_back(st);
                            }
                            cond = cf.CondFor(last->mnemonic);
                        }
                        for (auto& st : preStmts) emit(st);
                        // then katla — v5: iç içe dallanma varsa ÖZYİNELEMELİ çöz
                        bool thenHasCtrl = false;
                        for (auto* tb : thenBlocks) {
                            const Ins* tLast0 = !tb->insIdx.empty()
                                ? &ins[tb->insIdx.back()] : nullptr;
                            if (tLast0 && tLast0->isJcc && !tLast0->isIndirect)
                                thenHasCtrl = true;
                        }
                        if (thenHasCtrl) {
                            // iç elmaslar (else-if zinciri) özyinelemeli yapılaştırılır
                            emit("if ( " + cond + " ) {");
                            indent++;
                            {
                                Folder tf2(az_, ti, start, isElf);
                                tf2.DiscoverLocals(ins);
                                emitTopRegion(B, J, tf2);
                            }
                            indent--;
                            if (bF && !bF->insIdx.empty()) {
                                // else tarafı (F, jmp hariç) + return yükseltme
                                Folder ef2(az_, ti, start, isElf);
                                ef2.DiscoverLocals(ins);
                                std::vector<std::string> es2;
                                for (size_t k = 0; k + 1 < bF->insIdx.size(); k++) {
                                    const Ins& xi = ins[bF->insIdx[k]];
                                    if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                                    std::string s = ef2.Fold(xi, bF->insIdx[k], ins);
                                    if (!s.empty()) es2.push_back(s);
                                }
                                // J saf epilogue ise else return alır
                                bool pureEpi2 = false;
                                const BasicBlock* bJ3 = cfg.BlockAt(J);
                                if (bJ3 && !bJ3->insIdx.empty()) {
                                    pureEpi2 = true;
                                    for (size_t k = 0; k < bJ3->insIdx.size(); k++) {
                                        const Ins& xi = ins[bJ3->insIdx[k]];
                                        if (xi.mnemonic != "leave" && xi.mnemonic != "ret" &&
                                            xi.mnemonic != "pop" && xi.mnemonic != "nop") {
                                            pureEpi2 = false; break;
                                        }
                                    }
                                }
                                std::string rE2;
                                if (pureEpi2 && sig && sig->retKind != ArgKind::None) {
                                    if (sig->retKind == ArgKind::Float) {
                                        auto& xs = ef2.RegStateOf("xmm0");
                                        if (xs.valid && !xs.expr.empty()) rE2 = xs.expr;
                                    } else {
                                        auto& rs = ef2.RegStateOf("rax");
                                        if (rs.valid && !rs.expr.empty()) rE2 = rs.expr;
                                    }
                                }
                                if (!es2.empty() || !rE2.empty()) {
                                    emit("} else {");
                                    indent++;
                                    for (auto& s : es2) emit(s);
                                    if (!rE2.empty()) emit("return " + rE2 + ";");
                                    indent--;
                                }
                            }
                            emit("}");
                            for (auto* tb : thenBlocks) consumed.insert(tb->start);
                            consumed.insert(F);
                            consumed.insert(b.start);
                            handled = true;
                            continue;
                        }
                        Folder tf(az_, ti, start, isElf);
                        tf.DiscoverLocals(ins);
                        std::vector<std::string> thenStmts;
                        for (auto* tb : thenBlocks) {
                            size_t skipTail = 0;
                            const Ins* tLast = !tb->insIdx.empty()
                                ? &ins[tb->insIdx.back()] : nullptr;
                            if (tLast && tLast->isJmp && !tLast->isIndirect &&
                                tLast->target == J) skipTail = 1;
                            for (size_t k = 0; k + skipTail < tb->insIdx.size(); k++) {
                                const Ins& xi = ins[tb->insIdx[k]];
                                if (xi.isJcc || xi.isRet) continue;
                                std::string s = tf.Fold(xi, tb->insIdx[k], ins);
                                if (!s.empty()) thenStmts.push_back(s);
                            }
                        }
                        // else katla (F, jmp hariç)
                        Folder ef(az_, ti, start, isElf);
                        ef.DiscoverLocals(ins);
                        std::vector<std::string> elseStmts;
                        for (size_t k = 0; k + 1 < bF->insIdx.size(); k++) {
                            const Ins& xi = ins[bF->insIdx[k]];
                            if (xi.isJcc) continue;
                            std::string s = ef.Fold(xi, bF->insIdx[k], ins);
                            if (!s.empty()) elseStmts.push_back(s);
                        }
                        // return yükseltme: J saf epilogue ise return'leri dallara al
                        const BasicBlock* bJ = cfg.BlockAt(J);
                        bool pureEpilogue = false;
                        std::string retThen, retElse;
                        if (bJ) {
                            pureEpilogue = true;
                            for (size_t k = 0; k < bJ->insIdx.size(); k++) {
                                const Ins& xi = ins[bJ->insIdx[k]];
                                auto ops2 = SplitOps(xi.opStr);
                                bool ok = xi.mnemonic == "leave" || xi.mnemonic == "ret" ||
                                          xi.mnemonic == "pop" || xi.mnemonic == "nop";
                                if (!ok && xi.mnemonic == "mov" && ops2.size() == 2 &&
                                    ops2[1].find('[') != std::string::npos &&
                                    IsRegTok(ops2[0])) {
                                    MemOp m = ParseMem(ops2[1]);
                                    if (m.base == "rbp" && m.index.empty() &&
                                        !folder.Vars().count(m.disp) &&
                                        (ops2[0] == "rbx" || ops2[0] == "rbp" ||
                                         ops2[0] == "r12" || ops2[0] == "r13" ||
                                         ops2[0] == "r14" || ops2[0] == "r15"))
                                        ok = true;
                                }
                                if (!ok) { pureEpilogue = false; break; }
                            }
                        }
                        if (pureEpilogue) {
                            auto rstate = [&](const Folder& f) -> std::string {
                                auto& rs = f.RegStateOf("rax");
                                if (rs.valid) return rs.expr;
                                if (sig && sig->retKind == ArgKind::Float) {
                                    auto& xs = f.RegStateOf("xmm0");
                                    if (xs.valid) return xs.expr;
                                }
                                return "";
                            };
                            retThen = rstate(tf);
                            retElse = rstate(ef);
                        }

                        // then tarafında dallar J'ye jmp etmiyorsa ve return yoksa
                        // güvenli geri dönüş: goto
                        bool safe = true;
                        for (auto* tb : thenBlocks) {
                            const Ins* tLast = !tb->insIdx.empty()
                                ? &ins[tb->insIdx.back()] : nullptr;
                            if (!tLast) continue;
                            if (tLast->isJmp && !tLast->isIndirect && tLast->target != J)
                                safe = false;
                            if (tLast->isJmp && tLast->isIndirect) safe = false;
                        }
                        if (!safe && !pureEpilogue) {
                            // güvenli değil: goto geri dönüşü
                        }

                        // ternary (v4): iki taraf da tek atama VE aynı hedef ise
                        if (!pureEpilogue && thenStmts.size() == 1 && elseStmts.size() == 1) {
                            auto assignOf = [](const std::string& st, std::string& lhs,
                                               std::string& rhs) {
                                size_t eq = st.find(" = ");
                                if (eq == std::string::npos || st.size() < eq + 5) return false;
                                if (st.back() != ';') return false;
                                lhs = st.substr(0, eq);
                                rhs = st.substr(eq + 3, st.size() - eq - 4);
                                return !lhs.empty() && !rhs.empty() &&
                                       lhs.find(' ') == std::string::npos;
                            };
                            std::string l1, r1, l2b, r2;
                            if (assignOf(thenStmts[0], l1, r1) &&
                                assignOf(elseStmts[0], l2b, r2) && l1 == l2b) {
                                emit(l1 + " = ( " + cond + " ) ? " + r1 + " : " + r2 + ";");
                                for (auto* tb : thenBlocks) consumed.insert(tb->start);
                                consumed.insert(F);
                                handled = true;
                            }
                        }
                        emit("if ( " + cond + " ) {");
                        indent++;
                        for (auto& s : thenStmts) emit(s);
                        if (pureEpilogue && !retThen.empty() && sig && sig->retKind != ArgKind::None)
                            emit("return " + retThen + ";");
                        indent--;
                        if (!elseStmts.empty() || (pureEpilogue && !retElse.empty())) {
                            emit("} else {");
                            indent++;
                            for (auto& s : elseStmts) emit(s);
                            if (pureEpilogue && !retElse.empty() && sig && sig->retKind != ArgKind::None)
                                emit("return " + retElse + ";");
                            indent--;
                        }
                        emit("}");
                        for (auto* tb : thenBlocks) consumed.insert(tb->start);
                        consumed.insert(F);
                        if (pureEpilogue && bJ) consumed.insert(J);
                        handled = true;
                    }
                }
            }
        }

        if (!handled) {
            // ---- switch (jump table) ----
            const SwitchInfo* sw = nullptr;
            if (last && last->isJmp && last->isIndirect)
                sw = cfg.SwitchAt(b.start);
            if (sw) {
                // indeks ifadesi: ölçekli lea/mov anında indeks register ifadesi
                Folder sf(az_, ti, start, isElf);
                sf.DiscoverLocals(ins);
                std::string idxExpr = sw->indexReg;
                std::string scaleTok = "*" + std::to_string(sw->entrySize);
                for (size_t k = 0; k + 1 < b.insIdx.size(); k++) {
                    const Ins& xi = ins[b.insIdx[k]];
                    if (xi.isJcc || xi.isJmp || xi.isRet) continue;
                    if ((xi.mnemonic == "lea" || xi.mnemonic == "mov") &&
                        xi.opStr.find(scaleTok) != std::string::npos) {
                        auto o = SplitOps(xi.opStr);
                        MemOp m = ParseMem(o.size() > 1 ? o[1] : "");
                        if (!m.index.empty()) {
                            std::string e = sf.RegExpr(m.index);
                            if (e != m.index) idxExpr = e;
                        }
                    }
                    std::string st = sf.Fold(xi, b.insIdx[k], ins);
                    if (!st.empty()) emit(st);
                }
                emit("switch ( " + idxExpr + " ) {   // jump table @ 0x" +
                     ToHex(sw->tableVa) + ", " + std::to_string(sw->nCases) +
                     " giridi (" + (sw->isPic ? "PIC rel32" : "mutlak") + ")");
                indent++;
                auto isPureEpilogue = [&](const BasicBlock* eb) -> bool {
                    if (!eb) return false;
                    for (size_t k = 0; k < eb->insIdx.size(); k++) {
                        const Ins& xi = ins[eb->insIdx[k]];
                        bool ok = xi.mnemonic == "leave" || xi.mnemonic == "ret" ||
                                  xi.mnemonic == "pop" || xi.mnemonic == "nop";
                        if (!ok) return false;
                    }
                    return true;
                };
                auto emitCaseBody = [&](u64 target, const std::string& label) {
                    const BasicBlock* tb = cfg.BlockAt(target);
                    bool simple = tb && !consumed.count(target) &&
                                  tb->insIdx.size() <= 8 && !regionBlocks.count(target);
                    if (getenv("GODTIER_SW_DEBUG"))
                        std::printf("[SW] target=0x%llx tb=%p consumed=%d n=%zu region=%d simple=%d\n",
                                    (unsigned long long)target, (void*)tb,
                                    (int)consumed.count(target), tb ? tb->insIdx.size() : 0,
                                    (int)regionBlocks.count(target), (int)simple);
                    bool emittedBody = false;
                    if (simple) {
                        Folder cf(az_, ti, start, isElf);
                        cf.DiscoverLocals(ins);
                        std::vector<std::string> stmts;
                        bool didReturn = false;
                        for (size_t k = 0; k < tb->insIdx.size(); k++) {
                            const Ins& xi = ins[tb->insIdx[k]];
                            if (xi.isRet) { didReturn = true; break; }
                            if (xi.isJmp || xi.isJcc) continue;
                            std::string s = cf.Fold(xi, tb->insIdx[k], ins);
                            if (!s.empty()) stmts.push_back(s);
                        }
                        const Ins* tLast = &ins[tb->insIdx.back()];
                        if (tLast->isJmp && !tLast->isIndirect &&
                            isPureEpilogue(cfg.BlockAt(tLast->target)) &&
                            sig && sig->retKind != ArgKind::None) {
                            if (sig->retKind == ArgKind::Float) {
                                auto& xs = cf.RegStateOf("xmm0");
                                if (xs.valid) { stmts.push_back("return " + xs.expr + ";"); didReturn = true; }
                            } else {
                                auto& rs = cf.RegStateOf("rax");
                                if (rs.valid) { stmts.push_back("return " + rs.expr + ";"); didReturn = true; }
                            }
                        }
                        emit(label);
                        indent++;
                        for (auto& s : stmts) emit(s);
                        if (!didReturn) emit("break;");
                        indent--;
                        consumed.insert(target);
                        emittedBody = true;
                    }
                    if (!emittedBody)
                        emit(label + " goto 0x" + ToHex(target) + ";");
                };
                bool defaultIsCase = false;
                if (sw->defaultTarget)
                    for (auto& t : sw->targets)
                        if (t == sw->defaultTarget) defaultIsCase = true;
                std::map<u64, std::vector<u32>> byTarget;
                for (u32 i = 0; i < sw->nCases; i++) {
                    if (sw->defaultTarget && defaultIsCase &&
                        sw->targets[i] == sw->defaultTarget)
                        continue;
                    byTarget[sw->targets[i]].push_back(i);
                }
                for (auto& [t, cases] : byTarget) {
                    std::string label;
                    for (size_t i = 0; i < cases.size(); i++) {
                        if (i) label += " ";
                        label += "case " + std::to_string(cases[i]) + ":";
                    }
                    emitCaseBody(t, label);
                }
                if (sw->defaultTarget)
                    emitCaseBody(sw->defaultTarget, "default:");
                indent--;
                emit("}");
                consumed.insert(b.start);
                continue;
            }

            // normal doğrusal blok
            Folder bf(az_, ti, start, isElf);
            bf.DiscoverLocals(ins);
            if (b.pred.size() == 1) {
                importExitState(bf, b);
            } else if (b.pred.size() > 1) {
                // ---- v5: BİRLEŞİM (join) phi-SSA'sı ------------------------
                // TÜM öncüllerin çıkış durumları KAYITLI ve bir yazmaçta
                // AYNI ifadede birleşiyorsa o değer miras alınır (güvenli).
                // Farklı ifadeler dürüstçe ham bırakılır (yanlış birleştirme yok).
                std::map<std::string, Folder::RegSnapshot> merged;
                bool allPresent = true;
                for (u64 p : b.pred)
                    if (!exitState_.count(p)) { allPresent = false; break; }
                if (allPresent) {
                    bool first = true;
                    for (u64 p : b.pred) {
                        auto& st = exitState_[p];
                        if (first) { merged = st; first = false; continue; }
                        for (auto it = merged.begin(); it != merged.end(); ) {
                            auto q = st.find(it->first);
                            bool same = q != st.end() &&
                                        q->second.valid == it->second.valid &&
                                        q->second.expr == it->second.expr &&
                                        q->second.vec == it->second.vec;
                            if (!same) it = merged.erase(it);
                            else ++it;
                        }
                    }
                    if (!merged.empty()) bf.ImportRegs(merged);
                } else {
                    // v6: öncüllerden bazıları henüz emit edilmediyse (init
                    // trambolini kuyruğu) — emit EDİLMİŞ öncülden al
                    importExitState(bf, b);
                }
            }
            // ---- v5: süper blok soğurması (b'nin KENDİ komutlarından SONRA) --
            // Tek-öncüllü zincir bloklar aynı gösterimde birleştirilir:
            // goto yerine düz akış. Yalnız koşulsuz jmp/düşen akış üzerinden
            // ilerlenir (jcc hedefi elmas kolu olabilir — dokunma).
            auto absorbChain = [&](const BasicBlock* from) {
                const BasicBlock* cur = from;
                int absorbGuard = 0;
                while (absorbGuard++ < 32) {
                    if (cur->insIdx.empty()) break;
                    const Ins& l3 = ins[cur->insIdx.back()];
                    u64 nextVa = 0;
                    if (l3.isJmp && !l3.isIndirect) nextVa = l3.target;
                    else if (!l3.isJmp && !l3.isRet && !l3.isJcc)
                        nextVa = l3.addr + l3.len;         // düşen akış
                    else break;
                    const BasicBlock* nb = cfg.BlockAt(nextVa);
                    if (!nb || nb->start != nextVa) break;
                    if (nb->start == b.start) break;
                    if (consumed.count(nb->start) || deadBlocks.count(nb->start)) break;
                    if (loopAtHead.count(nb->start)) break;          // döngü başı
                    if (regionBlocks.count(nb->start)) break;
                    if (nb->pred.size() != 1 || nb->pred[0] != cur->start) break;
                    if (nb->insIdx.empty()) break;
                    const Ins& nl = ins[nb->insIdx.back()];
                    if (nl.isJcc || (nl.isJmp && nl.isIndirect)) break;  // yapılaştırıcı halleder
                    // soğur: komutları bu gösterime kat
                    for (size_t k = 0; k < nb->insIdx.size(); k++) {
                        const Ins& xi = ins[nb->insIdx[k]];
                        if (xi.isJmp) {
                            if (regionBlocks.count(xi.target)) continue;
                            if (xi.isIndirect) { emit("goto *;   // jmp " + xi.opStr); continue; }
                            // zincir sonu: geriye dönüş ya da çok-öncüllü birleşim
                            // ise goto dürüstçe kalır; ileri tek-öncül ise zincir devam eder
                            if (xi.target < xi.addr)
                                emit("goto 0x" + ToHex(xi.target) + ";");
                            else {
                                const BasicBlock* tb = cfg.BlockAt(xi.target);
                                if (tb && tb->pred.size() > 1)
                                    emit("goto 0x" + ToHex(xi.target) + ";");
                            }
                            continue;
                        }
                        if (xi.isRet) {
                            auto& rs = bf.RegStateOf("rax");
                            bool hasRet = rs.valid && sig && sig->retKind != ArgKind::None;
                            if (sig && sig->retKind == ArgKind::Float) {
                                auto& xs = bf.RegStateOf("xmm0");
                                if (xs.valid) { emit("return " + xs.expr + ";"); continue; }
                            }
                            if (hasRet) emit("return " + rs.expr + ";");
                            else emit("return;");
                            continue;
                        }
                        std::string stmt = bf.Fold(xi, nb->insIdx[k], ins);
                        if (!stmt.empty()) emit(stmt);
                    }
                    consumed.insert(nb->start);
                    cur = nb;
                }
            };
            for (size_t k = 0; k < b.insIdx.size(); k++) {
                const Ins& xi = ins[b.insIdx[k]];
                if (dwarf) {
                    const DwarfInline* di = dwarf->InlineAt(xi.addr);
                    if (di && !di->funcName.empty() && xi.addr == di->low)
                        emit("// >>> " + di->funcName + "() buraya inline edilmis (DWARF kaniti)");
                }
                if (xi.isJmp) {
                    if (regionBlocks.count(xi.target)) continue;
                    if (xi.isIndirect) { emit("goto *;   // jmp " + xi.opStr); continue; }
                    if (xi.target < xi.addr) emit("goto 0x" + ToHex(xi.target) + ";");
                    continue;
                }
                if (xi.isJcc) {
                    if (regionBlocks.count(xi.target)) continue;
                    std::string cond = bf.CondFor(xi.mnemonic);
                    emit("if ( " + cond + " ) goto 0x" + ToHex(xi.target) + ";");
                    continue;
                }
                if (xi.isRet) {
                    auto& rs = bf.RegStateOf("rax");
                    bool hasRet = rs.valid && sig && sig->retKind != ArgKind::None;
                    if (sig && sig->retKind == ArgKind::Float) {
                        auto& xs = bf.RegStateOf("xmm0");
                        if (xs.valid) { emit("return " + xs.expr + ";"); continue; }
                    }
                    if (hasRet) emit("return " + rs.expr + ";");
                    else emit("return;");
                    continue;
                }
                std::string stmt = bf.Fold(xi, b.insIdx[k], ins);
                if (!stmt.empty()) emit(stmt);
            }
            // v5: b'nin komutları bitti — tek-öncüllü zinciri soğur
            absorbChain(&b);
            bf.ExportRegs(exitState_[b.start]);
            consumed.insert(b.start);
        }
    }

    {
        auto isCallStmt = [](const std::string& t) {
            if (t.size() < 4 || t.substr(t.size() - 2) != ");") return false;
            static const char* kw[] = {"return", "if ", "while", "do ", "else",
                                       "goto", "struct", "printf_?"};
            for (auto* k : kw) if (t.rfind(k, 0) == 0) return false;
            return t.find('(') != std::string::npos;
        };
        for (size_t i = 0; i < lines.size(); i++) {
            if (!isCallStmt(lines[i].text)) continue;
            // note'lu satır ("...();   // not") önce nottan arındır
            std::string bodyTxt = lines[i].text;
            size_t nc = bodyTxt.find("   //");
            if (nc != std::string::npos) bodyTxt = bodyTxt.substr(0, nc);
            std::string core = bodyTxt.substr(0, bodyTxt.size() - 1); // ';' kirp
            if (core.size() < 3) continue;
            for (size_t j = 0; j < lines.size(); j++) {
                if (j == i) continue;
                if (lines[j].text.find(core) != std::string::npos &&
                    lines[j].text.size() > lines[i].text.size()) {
                    lines[i].ind = -1;   // yutuldu (atama/return icine gomuldu)
                    break;
                }
            }
        }
        for (auto& L : lines)
            if (L.ind >= 0)
                out += std::string((size_t)L.ind * 4, ' ') + L.text + "\n";
    }
    // DWARF parametre adları: aN belirteçlerini gerçek adlarla değiştir
    // (token sınırları korunur: "a1" ancak başına/sonuna harf-rakam-_ gelmezse)
    if (sig && sig->fromDwarf) {
        for (int i = 0; i < sig->nArgs && i < 6; i++) {
            std::string from = "a" + std::to_string(i + 1);
            std::string to = sig->argNames[i];
            if (to.empty() || to == from) continue;
            std::string r;
            r.reserve(out.size());
            size_t pos = 0;
            while (pos < out.size()) {
                size_t hit = out.find(from, pos);
                if (hit == std::string::npos) { r += out.substr(pos); break; }
                r += out.substr(pos, hit - pos);
                bool leftOk = hit == 0 ||
                    !(isalnum((unsigned char)out[hit - 1]) || out[hit - 1] == '_');
                size_t e = hit + from.size();
                bool rightOk = e >= out.size() ||
                    !(isalnum((unsigned char)out[e]) || out[e] == '_');
                if (leftOk && rightOk) { r += to; pos = e; }
                else { r += from; pos = hit + from.size(); }
            }
            out = r;
        }
    }
    out += "}\n\n";
    return out;
}

// ----------------------------------------------------------------------------
// Tümünü yaz + köprüler
// ----------------------------------------------------------------------------
std::string Pseudocoder::DecompileAll(size_t limit) {
    TypeInferer& ti = TI();
    std::string out = "// i4M GodTier Engine — otomatik pseudocode dokumu (v2)\n\n";
    // struct tanımları başta
    if (!ti.Structs().empty()) {
        out += "// ---- geri kazanilan struct'lar ----\n";
        for (auto& s : ti.Structs()) out += s.Decl() + "\n";
        out += "\n";
    }
    size_t n = 0;
    for (auto& [va, f] : az_.Functions()) {
        if (limit && n >= limit) break;
        out += DecompileFunction(va);
        n++;
    }
    return out;
}

std::string Pseudocoder::BridgeRetDec(const std::string& pePath, const std::string& outPath) {
    if (system("retdec-decompiler --version > /dev/null 2>&1") != 0)
        return "[kopru] retdec-decompiler PATH'te bulunamadi — https://github.com/avast/retdec kurun\n"
               "        (Not: RetDec 'limited maintenance' modunda; x86/x64 destegi sinirli)";
    std::string cmd = "retdec-decompiler -o \"" + outPath + "\" \"" + pePath + "\" 2>&1";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return "[kopru] retdec calistirilamadi";
    std::string logo;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) logo += buf;
    pclose(p);
    return "[kopru] RetDec tamam -> " + outPath + "\n" + logo.substr(0, 2000);
}

std::string Pseudocoder::BridgeGhidra(const std::string& filePath, const std::string& outPath) {
    if (system("analyzeHeadless 2>&1 | head -1 > /dev/null") != 0)
        return "[kopru] analyzeHeadless bulunamadi — Ghidra kurulum dizinini PATH'e ekleyin\n"
               "        (scripts/godtier_ghidra.py projemizle birlikte gelir)";
    std::string py = "godtier_ghidra.py";
    std::string cmd = "analyzeHeadless /tmp/gt_ghidra_proj GT -import \"" + filePath +
                      "\" -postScript " + py + " \"" + outPath + "\" -deleteProject 2>&1";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return "[kopru] Ghidra headless calistirilamadi";
    std::string logo;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) logo += buf;
    pclose(p);
    return "[kopru] Ghidra headless tamam -> " + outPath + "\n" + logo.substr(0, 2000);
}

// ----------------------------------------------------------------------------
// v7: RTTI atlası + DEVRİT-PRO (lazy) + x86-32 pseudocode yolu
// ----------------------------------------------------------------------------
MsvcRtti& Pseudocoder::Rtti() {
    if (!rtti_) {
        rtti_ = std::make_unique<MsvcRtti>(az_);
        rtti_->Build();
        // v8: RTTI-GÜDÜMLÜ FONKSİYON KEŞFİ — vtable slotları GERÇEK kod
        // adreslerini gösterir; doğrudan çağrılmayan sanal metotlar (yalnız
        // vtable'dan referanslı: CPythonPlayer::GetStatus gibi) böylece
        // fonksiyon evrenine girer → devirt/decompile kapsamı genişler.
        size_t added = 0;
        std::set<u64> seen;
        for (auto& c : rtti_->Classes())
            for (u64 t : c.slots) {
                if (!t || !seen.insert(t).second) continue;
                if (!az_.FunctionStart(t)) {
                    if (!az_.DisassembleFunction(t).empty()) added++;
                }
            }
        if (added)
            LogInfo("rtti: +%zu sanal metod fonksiyonu kesfedildi (vtable slotlari)",
                    added);
    }
    return *rtti_;
}

DevirtPro& Pseudocoder::Devirt() {
    if (!devirtPro_) {
        devirtPro_ = std::make_unique<DevirtPro>(az_, TI(), Rtti());
        devirtPro_->Build();
        // kanıtları TypeInferer'a taşı: TryDevirtualize strateji-0 olarak
        // servis eder (dolaylı çağrı render'ı otomatik statikleşir)
        for (auto& [a, r] : devirtPro_->Results())
            if (r.resolved)
                TI().RegisterDevirtFact(a, r.target, r.name, r.why, r.vftVa,
                                        r.slot, r.className, r.proofKind);
    }
    return *devirtPro_;
}

// ---- x86-32 ifade katlayıcı (PE32 cdecl/thiscall/stdcall) -------------------
namespace {

// MSVC veri sembolü basit demangle (devirtpro.cpp ile aynı kurallar):
// "?ms_singleton@?$CSingleton@VX@@@@0PA" → "CSingleton<X>::ms_singleton"
std::string Pc32DemangleData(const std::string& m) {
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

class Folder32 {
public:
    Folder32(Analyzer& az, TypeInferer& ti, u64 funcVa)
        : az_(az), ti_(ti), funcVa_(funcVa) {
        regs_["rax"] = regs_["rcx"] = regs_["rdx"] = regs_["rbx"] =
        regs_["rsp"] = regs_["rbp"] = regs_["rsi"] = regs_["rdi"] = "";
        // PDB global sembol haritası (VA -> demangle edilmiş ad)
        if (const PdbInfo* pdb = ti_.Pdb())
            for (auto& g : pdb->Globals())
                if (g.va) globalsByVa_[g.va] = Pc32DemangleData(
                    !g.name.empty() && g.name[0] != '?' ? g.name : g.mangled);
    }

    // [ebp+D] çözümü: arg (D>=8) / yerel (D<0, yazılmış) / vN
    std::string FrameRef(i64 d, bool write) {
        if (d >= 8 && (d - 8) % 4 == 0) {
            int idx = (int)((d - 8) / 4);
            EnsureArg(idx);
            return args_[idx];
        }
        if (write || locals_.count(d)) return Local(d);
        return Local(d);   // okuma: tanımlanacak
    }
    std::string Local(i64 d) {
        auto it = locals_.find(d);
        if (it != locals_.end()) return it->second.name;
        // PDB yerel adı varsa gerçek adı kullan
        std::string nm = "v" + std::to_string(++nLoc_);
        if (const PdbInfo* pdb = ti_.Pdb()) {
            for (auto& f : pdb->Funcs()) {
                if (f.va != funcVa_) continue;
                for (auto& l : f.locals) {
                    if (!l.isArg && l.off == (i32)d && !l.name.empty()) {
                        nm = l.name; break;
                    }
                }
                break;
            }
        }
        LocalVar lv; lv.name = nm; lv.type = "int";
        locals_[d] = lv;
        return nm;
    }
    void EnsureArg(int idx) {
        while ((int)args_.size() <= idx) {
            int i = (int)args_.size();
            std::string nm = "a" + std::to_string(i + 1);
            if (const PdbInfo* pdb = ti_.Pdb()) {
                for (auto& f : pdb->Funcs()) {
                    if (f.va != funcVa_) continue;
                    if ((size_t)i < f.argNames.size() && !f.argNames[i].empty())
                        nm = f.argNames[i];
                    break;
                }
            }
            args_.push_back(nm);
        }
    }
    std::string Reg(const std::string& canon) {
        auto it = regs_.find(canon);
        return it == regs_.end() ? "" : it->second;
    }
    // v7: ERTELENMİŞ ÇAĞRI MALZEMELEŞMESİ — çağrı ifadesi ilk OKUNUŞUNDA
    // vN değişkenine bağlanır (body'ye "vN = çağrı;" basılır). Böylece
    // her çağrı dosyada TEK kez gösterilir: koşul/argüman/return hep vN.
    std::string UseVal(const std::string& canon) {
        std::string v = Reg(canon);
        if (v.empty() || pendingCall_.empty() || v != pendingCall_) return v;
        std::string var = "v" + std::to_string(++nLoc_);
        temps_.push_back(var);
        // kanıt notunu ('   // devirt-pro: ...') ';'nin SONRASINA al —
        // geçerli C sözdizimi kalsın
        std::string core = v, note;
        size_t np = v.find("   //");
        if (np != std::string::npos) {
            core = v.substr(0, np);
            note = v.substr(np);
        }
        if (onMat) onMat(var + " = " + core + ";" + note);
        for (auto& kv : regs_)
            if (kv.second == pendingCall_) kv.second = var;
        pendingCall_.clear();
        return var;
    }
    void ConsumePending() { pendingCall_.clear(); }
    const std::string& Pending() const { return pendingCall_; }
    void SetPending(const std::string& e) { pendingCall_ = e; }
    void SetReg(const std::string& canon, const std::string& e) {
        if (regs_.count(canon)) regs_[canon] = e;
    }
    // bellek erişim ifadesi: [reg+K] / [rbp+D] / [imm]
    // (NOT: ParseMem taban adlarını CANON yapar: ebp→rbp, edi→rdi)
    std::string MemExpr(const MemOp& m, const Ins& x) {
        if (m.base == "rbp" && m.index.empty()) return FrameRef(m.disp, false);
        if (m.base == "rsp" && m.index.empty()) return "sp_" + ToHex((u64)m.disp);
        if (m.base.empty() && m.index.empty()) {
            // mutlak / IAT / veri sembolü
            if (az_.Bin().Imports().size() && m.disp) {
                for (auto& d : az_.Bin().Imports())
                    for (auto& f : d.funcs)
                        if (f.iatVa == (u64)m.disp && !f.name.empty())
                            return "&" + d.name + "." + f.name;
            }
            // PDB global sembolü (ms_singleton, TWOHANDED_... gibi)
            auto git = globalsByVa_.find((u64)m.disp);
            if (git != globalsByVa_.end()) return "*(" + git->second + ")";
            std::string nm = az_.SymbolOrLabel((u64)m.disp);
            std::string addr = "0x" + ToHex((u64)m.disp);
            if (!nm.empty() && nm != addr && nm.find("loc_") != 0 &&
                nm.find("sub_") != 0)
                return nm;
            return "*(" + addr + ")";
        }
        std::string b = Reg(m.base.empty() ? "" : m.base);
        if (m.base == "rdi" || m.base == "rsi" || m.base == "rbx") {
            // sık görülen this-taşima alışkanlığı: this->alan
            if (thisRegs_.count(m.base) && !b.empty() && b != m.base) {
                std::string idx = m.index.empty() ? "" :
                    "[" + (Reg(m.index).empty() ? m.index : Reg(m.index)) +
                    (m.scale > 1 ? "*" + std::to_string(m.scale) : "") + "]";
                return b + "->field_" + ToHex((u64)(m.disp < 0 ? 0 : m.disp)) + idx;
            }
        }
        std::string base = b.empty() ? m.base : b;
        if (!m.index.empty()) {
            base += " + " + (Reg(m.index).empty() ? m.index : Reg(m.index));
            if (m.scale > 1) base += "*" + std::to_string(m.scale);
        }
        if (m.disp) base += (m.disp > 0 ? " + 0x" : " - 0x") +
                            ToHex((u64)(m.disp < 0 ? -m.disp : m.disp));
        return "*(" + base + ")";
    }
    void MarkThis(const std::string& canon) { thisRegs_.insert(canon); }

    std::vector<std::string>& pushed() { return pushed_; }
    int nLocals() const { return nLoc_; }

    struct LocalVar { std::string name, type; };
    std::map<i64, LocalVar> locals_;
    std::vector<std::string> args_;
    std::vector<std::string> temps_;              // malzemeleşen çağrı değişkenleri
    std::function<void(const std::string&)> onMat;  // body'ye basma kancası
    std::string pendingCall_;                     // henüz okunmamış çağrı ifadesi

private:
    Analyzer& az_;
    TypeInferer& ti_;
    u64 funcVa_;
    std::map<std::string, std::string> regs_;
    std::set<std::string> thisRegs_;
    std::map<u64, std::string> globalsByVa_;   // PDB global VA -> ad
    std::vector<std::string> pushed_;
    int nLoc_ = 0;
};

} // namespace

std::string Pseudocoder::Decompile32(u64 start) {
    std::vector<Ins> ins = az_.DisassembleFunction(start, (size_t)opt_.maxInsPerFunc);
    if (ins.empty()) return "";
    TypeInferer& ti = TI();
    // v7: devirt-pro kanıtlarını KUR (lazy — RTTI atlası + singleton taraması)
    Devirt();
    // PDB imzası (varsa) — PE32 isim/parametre zenginliği
    const PdbFunc* pfn = nullptr;
    if (const PdbInfo* pdb = ti.Pdb())
        for (auto& f : pdb->Funcs())
            if (f.va == start) { pfn = &f; break; }

    Folder32 f(az_, ti, start);
    std::vector<std::string> body;
    std::vector<std::string> pushArgs;   // çağrı arg yığını (ifadeler)
    f.onMat = [&](const std::string& s) { body.push_back("    " + s); };
    std::set<u64> jumpTargets;
    for (auto& x : ins)
        if (x.isJcc || x.isJmp) jumpTargets.insert(x.target);
    bool eaxWritten = false;
    // koşul parçaları: (lhs, op, rhs) — jcc anında BİRLEŞTİR
    std::string cmpL, cmpOp, cmpR;
    bool cmpIsTest = false;

    auto isCalleeSave = [](const std::string& e) {
        // açılmamış (ifadesiz) callee-save yazmaç push'u = arg DEĞİL (kaydet)
        return e == "rsi" || e == "rdi" || e == "rbx" || e == "rbp" ||
               e == "esi" || e == "edi" || e == "ebx" || e == "ebp";
    };

    // v8: SINGLETON KATLAMASI — metin2 kaynağındaki
    // "CPythonPlayer::Instance().GetStatus(iType)" satırını geri kazanmak
    // için: ilk arg "(*(CSingleton<T>::ms_singleton) + 0xK)" (PDB'li) veya
    // "(*(0x8BD2D0) + 0xK)" (PDB'siz) kalıbındaysa VE +K ofsetindeki vptr
    // kanıtı çözülen metodun sınıfıyla eşleşiyorsa → "T::Instance()".
    // +K taban-ayarı MSVC çoklu-kalıtım detayıdır — kaynakta görünmez.
    auto tryFoldSingleton = [&](const std::string& arg,
                                const std::string& cls) -> std::pair<bool, std::string> {
        if (arg.empty() || cls.empty()) return {false, ""};
        std::string s = arg;
        // dış parantezleri sıyır (dengeliyse)
        while (s.size() >= 2 && s.front() == '(' && s.back() == ')') {
            int d = 0; bool bal = true;
            for (size_t i = 0; i < s.size(); i++) {
                if (s[i] == '(') d++;
                else if (s[i] == ')') { d--; if (d == 0 && i + 1 != s.size()) { bal = false; break; } }
            }
            if (!bal || d != 0) break;
            s = s.substr(1, s.size() - 2);
        }
        std::string deref, tail;
        if (s.rfind("*(", 0) == 0) {
            size_t close = s.find(')');
            if (close == std::string::npos) return {false, ""};
            deref = s.substr(2, close - 2);
            tail = s.substr(close + 1);
        } else if (s.rfind("dword_", 0) == 0 || s.rfind("qword_", 0) == 0) {
            size_t sp = s.find(' ');
            if (sp == std::string::npos) { deref = s; }
            else { deref = s.substr(0, sp); tail = s.substr(sp); }
        } else return {false, ""};
        // kuyruk: "+ 0xK" / "+ K" (ondalık) / "- ..."
        i64 k = 0;
        {
            size_t p = tail.find_first_not_of(" \t");
            if (p != std::string::npos) {
                std::string t = tail.substr(p);
                bool minus = (t[0] == '-');
                if (t.rfind("+ 0x", 0) == 0 || (minus && t.rfind("- 0x", 0) == 0)) {
                    u64 v = strtoull(t.substr(4).c_str(), nullptr, 16);
                    k = minus ? -(i64)v : (i64)v;
                } else if (t[0] == '+' || minus) {
                    // ondalık: " + 4" (capstone add ecx, 4 böyle yazar)
                    u64 v = strtoull(t.substr(1).c_str(), nullptr, 10);
                    k = minus ? -(i64)v : (i64)v;
                }
            }
        }
        // yol 1 (PDB sembolü): "CSingleton<T>::ms_singleton"
        if (deref.rfind("CSingleton<", 0) == 0 &&
            deref.find(">::ms_singleton") != std::string::npos) {
            const size_t b1 = 11;   // strlen("CSingleton<") — dikkat: 11!
            size_t b2 = deref.find('>', b1);
            if (b2 != std::string::npos) {
                std::string T = deref.substr(b1, b2 - b1);
                if (T == cls) return {true, cls + "::Instance()"};
            }
            return {false, ""};
        }
        // yol 2 (PDB'siz): "0xADDR" / "dword_ADDR" → statik-kanıt + RTTI
        std::string hexpart;
        if (deref.rfind("dword_", 0) == 0 || deref.rfind("qword_", 0) == 0)
            hexpart = deref.substr(6);
        else if (deref.rfind("0x", 0) == 0) hexpart = deref.substr(2);
        if (hexpart.empty()) return {false, ""};
        u64 sva = strtoull(hexpart.c_str(), nullptr, 16);
        if (!sva || !devirtPro_) return {false, ""};
        auto fv = devirtPro_->StaticView(sva);
        if (!fv.proven) return {false, ""};
        auto it = fv.vptrCand.find(k);
        if (it == fv.vptrCand.end()) it = fv.vptrCand.find(0);
        if (it == fv.vptrCand.end()) return {false, ""};
        for (u64 vft : it->second) {
            const RttiClass* rc = Rtti().ByVftable(vft);
            if (rc && rc->name == cls) return {true, cls + "::Instance()"};
        }
        return {false, ""};
    };

    auto isPlainIdent = [](const std::string& s) {
        if (s.empty()) return false;
        for (char c : s)
            if (!(isalnum((unsigned char)c) || c == '_')) return false;
        return true;
    };

    // v8.1: fonksiyon-sonu vfN sözlüğü (callRender doldurur, footer basar)
    std::map<int, std::string> vfGloss;

    auto callRender = [&](size_t idx) -> std::string {
        const Ins& x = ins[idx];
        bool indirect = x.isIndirect;
        // cdecl arg sayısı: çağrıdan SONRAKI "add esp, N" (stack cleanup)
        int nargs = -1;
        for (size_t j = idx + 1; j < ins.size() && j < idx + 16; j++) {
            const std::string& m2 = ins[j].mnemonic;
            if (ins[j].isCall) break;                    // temizlik yok (stdcall/thiscall)
            if (m2 == "add" || m2 == "sub") {
                auto o2 = SplitOps(ins[j].opStr);
                if (o2.size() == 2 && o2[0] == "esp") {
                    u64 n = strtoull(o2[1].c_str(), nullptr, 0);
                    nargs = (int)((m2 == "add" ? n : (u64)0) / 4);
                    if (m2 == "sub") nargs = 0;
                    break;
                }
                break;                                  // esp'siz add: dur
            }
            if (m2 == "ret" || m2 == "leave") break;
        }
        // aday arg'lar: push edilenler (son çağrıdan beri), callee-save hariç
        std::vector<std::string> cand;
        for (auto& p : pushArgs)
            if (!isCalleeSave(p)) cand.push_back(p);
        pushArgs.clear();
        std::vector<std::string> a;
        if (nargs >= 0 && (size_t)nargs <= cand.size()) {
            // cdecl: son N push'un TERSI (son push = ilk argüman)
            a.assign(cand.end() - nargs, cand.end());
            std::reverse(a.begin(), a.end());
        } else {
            a.assign(cand.rbegin(), cand.rend());   // thiscall/stdcall: hepsi ters
        }
        // devirt-kanıtı (strateji 0) — sanal çağrı STATİK çözülmüş mü?
        std::string name;
        bool devirted = false;
        std::string candNote;   // dürüst çoklu-aday notu (çağrının SONUNA)
        std::string vfNote;     // v8.1: vfN sözlük notu (vfN NE olan?)
        const TypeInferer::DevirtResult* dvf = nullptr;
        if (indirect) {
            if ((dvf = ti.DevirtFactAt(x.addr)) != nullptr) {
                if (dvf->target || !dvf->methodName.empty()) {
                    name = dvf->methodName.empty() ? az_.NameFor(dvf->target)
                                                  : dvf->methodName;
                    devirted = true;
                }
            }
        } else {
            name = az_.NameFor(x.target);
        }
        if (!devirted && indirect) {
            std::string op = SplitOps(x.opStr).empty() ? "?" : SplitOps(x.opStr)[0];
            std::string e;
            if (IsRegTok(op)) e = f.Reg(CanonReg(op));
            else if (op.find('[') != std::string::npos)
                e = f.MemExpr(ParseMem(op), x);
            // IAT import adı: "&dll.api" → doğrudan dll.api göster
            if (!e.empty() && e[0] == '&') name = e.substr(1);
            else name = "(*" + (e.empty() ? op : e) + ")";
            // v7 DÜRÜSTLÜK: çoklu-aday sanal çağrı — aday listesini göster
            // (yanlış tekil tahmin YOK; kim olduğu belliyse yukarıda çözüldü)
            if (devirtPro_) {
                auto dit = devirtPro_->Results().find(x.addr);
                if (dit != devirtPro_->Results().end() &&
                    !dit->second.candidates.empty()) {
                    std::string cl;
                    for (auto& cn : dit->second.candidateNames) {
                        if (!cl.empty()) cl += ", ";
                        cl += cn;
                    }
                    candNote = "   // sanal kaldi: vtable[" +
                               std::to_string(dit->second.slot) +
                               "] adaylari: " + cl;
                }
            }
        }
        // thiscall: ecx = this → metot çağrısı olarak göster
        std::string ecx = f.UseVal("rcx");
        bool thisInjected = false;
        if (devirted && !ecx.empty() && ecx != "rcx") {
            a.insert(a.begin(), ecx);
            thisInjected = true;
        } else if (!devirted && !indirect) {
            // thiscall sezgisi (doğrudan çağrı): ecx'te anlamalı ifade varsa
            // ilk argüman (this) olarak göster — MSVC thiscall kuralı
            if (!ecx.empty() && ecx != "rcx" && ecx != "ecx") {
                a.insert(a.begin(), ecx);
                thisInjected = true;
            }
        }
        // v8: METOT SÖZDİZİMİ + Instance() KATLAMASI
        //   CPlayer::vf4((*(0x403000) + 0x4), iType) → CPlayer::Instance().vf4(iType)
        //   CInstanceBase::GetWeaponType(v4)          → v4->GetWeaponType()
        std::string instanceNote;
        std::string s;
        bool foldedInstance = false;
        if (thisInjected && !a.empty() && name.find("::") != std::string::npos) {
            std::string cls = name.substr(0, name.find("::"));
            std::string mth = name.substr(name.find("::") + 2);
            auto fold = tryFoldSingleton(a[0], cls);
            if (fold.first) {
                s = fold.second + "." + mth + "(";
                for (size_t i = 1; i < a.size(); i++) {
                    if (i > 1) s += ", ";
                    s += a[i].empty() ? "?" : a[i];
                }
                s += ")";
                foldedInstance = true;
                instanceNote = "   // Instance() geri kazanildi: singleton "
                               "kalibi (" +
                               std::string(ti.Pdb() ? "PDB sembolu" : "RTTI sinif kaniti") +
                               ", taban ayari +0x gizlendi)";
            } else if (isPlainIdent(a[0]) && !mth.empty()) {
                name = a[0] + "->" + mth;
                a.erase(a.begin());
            }
        }
        if (!foldedInstance) {
            s = name + "(";
            for (size_t i = 0; i < a.size(); i++) {
                if (i) s += ", ";
                s += a[i].empty() ? "?" : a[i];
            }
            s += ")";
        }
        if (!candNote.empty()) s += candNote;
        if (!instanceNote.empty()) s += instanceNote;
        // v8.1: vfN SÖZLÜĞÜ — PDB'siz "vf4" adının NE olduğunu çağrının
        // yanında kanıt koordinatlarıyla yaz: vfN = vtable slot N (x86-32:
        // bayt ofseti 4*N). "vf4 = 0x8bd2d0" DEĞİL: 0x8bd2d0 singleton
        // yuvasıdır; vf4 = vftable[slot*4] hedefidir.
        if (devirted && dvf && name.find("::vf") != std::string::npos &&
            dvf->vftVa && dvf->slot >= 0) {
            char vb[176];
            snprintf(vb, sizeof vb,
                     "   // vf%d = %s vftable[0x%llx] + 0x%llx -> 0x%llx",
                     dvf->slot, dvf->className.c_str(),
                     (unsigned long long)dvf->vftVa,
                     (unsigned long long)(dvf->slot * 4),
                     (unsigned long long)dvf->target);
            vfNote = vb;
            s += vfNote;
            // fonksiyon-sonu sözlüğü için topla (footer)
            vfGloss[dvf->slot] = vfNote.substr(6);   // "   // " kırp
        }
        if (devirted && a.empty() == false)
            if (const TypeInferer::DevirtResult* dv = ti.DevirtFactAt(x.addr))
                s += "   // devirt-pro: " + dv->why;
        for (auto* r : {"rax", "rcx", "rdx"})
            f.SetReg(r, "");      // caller-saved temizliği
        f.SetReg("rax", s);        // dönüş değeri = çağrı ifadesi (katlanır)
        return s;
    };

    for (size_t xi = 0; xi < ins.size(); xi++) {
        const Ins& x = ins[xi];
        const std::string& mn = x.mnemonic;
        auto ops = SplitOps(x.opStr);
        bool isTarget = jumpTargets.count(x.addr) > 0;
        if (isTarget && !mn.empty()) {
            char lb[48];
            snprintf(lb, sizeof lb, "loc_%llx:", (unsigned long long)x.addr);
            body.push_back(std::string(lb));
        }

        if (x.isCall) {
            // önceki çağrının değeri hiç okunmadıysa düz ifade olarak ver
            if (!f.Pending().empty()) {
                std::string pc = f.Pending(), pn;
                size_t np = pc.find("   //");
                if (np != std::string::npos) { pn = pc.substr(np); pc = pc.substr(0, np); }
                body.push_back("    " + pc + ";" + pn);
                f.ConsumePending();
            }
            f.SetPending(callRender(xi));
            eaxWritten = false;
            continue;
        }
        if (mn == "push") {
            std::string e;
            if (!ops.empty()) {
                if (IsRegTok(ops[0])) e = f.UseVal(CanonReg(ops[0]));
                else if (ops[0].find('[') != std::string::npos) {
                    MemOp m = ParseMem(ops[0]);
                    e = f.MemExpr(m, x);
                } else if (IsNumberTok(ops[0])) {
                    e = ops[0];
                    // hazır değer string'e işaret ediyor olabilir ("i" formatı)
                    u64 sv = strtoull(ops[0].c_str(), nullptr, 0);
                    std::string s;
                    if (az_.IsStringAt(sv, &s) && s.size() <= 12)
                        e = "\"" + s + "\"";
                    else {
                        // kısa string sabiti (1-3 karakter): string taraması
                        // >=4 karakter ister; Py_BuildValue("i", ...) gibi
                        // formatları imajdan doğrudan oku
                        u8 sb[8] = {};
                        if (sv && az_.Image().ReadBytes(sv, sb, 8)) {
                            int n = 0;
                            while (n < 8 && sb[n] && sb[n] >= 0x20 && sb[n] < 0x7f)
                                n++;
                            if (n >= 1 && n < 8 && sb[n] == 0 && n <= 3) {
                                s.assign((const char*)sb, (size_t)n);
                                e = "\"" + s + "\"";
                            }
                        }
                    }
                } else e = ops[0];
            }
            pushArgs.push_back(e.empty() ? ops.empty() ? "?" : ops[0] : e);
            continue;
        }
        if (mn == "pop") { continue; }
        if (mn == "mov" && ops.size() == 2) {
            const std::string& dst = ops[0];
            const std::string& src = ops[1];
            // this-tasima: mov edi/esi/ebx, ecx  → this işaretle
            if (IsRegTok(dst) && IsRegTok(src) && CanonReg(src) == "rcx") {
                std::string e = f.UseVal("rcx");
                f.SetReg(CanonReg(dst), e.empty() ? CanonReg(dst) : e);
                if (e.empty() || e == "ecx") {
                    f.MarkThis(CanonReg(dst));
                    f.SetReg(CanonReg(dst), "this");
                }
                continue;
            }
            if (dst.find('[') != std::string::npos) {
                MemOp m = ParseMem(dst);
                if (m.base == "rbp" && m.index.empty()) {
                    std::string e;
                    if (IsRegTok(src)) e = f.Reg(CanonReg(src));
                    else e = src;
                    if (e.empty()) e = IsRegTok(src) ? CanonReg(src) : src;
                    body.push_back("    " + f.FrameRef(m.disp, true) + " = " + e + ";");
                    continue;
                }
                std::string lhs = f.MemExpr(m, x);
                std::string e = IsRegTok(src) ? f.Reg(CanonReg(src)) : src;
                if (e.empty()) e = src;
                body.push_back("    " + lhs + " = " + e + ";");
                continue;
            }
            if (!IsRegTok(dst)) continue;
            std::string dc = CanonReg(dst);
            if (src.find('[') != std::string::npos) {
                MemOp m = ParseMem(src);
                f.SetReg(dc, f.MemExpr(m, x));
            } else if (IsRegTok(src)) {
                f.SetReg(dc, f.UseVal(CanonReg(src)));
            } else {
                f.SetReg(dc, src);
            }
            // rax üzerine yazılıyor: okunmamış çağrı değeri düz ifadeye dönsün
            if (dc == "rax" && !f.Pending().empty() &&
                f.Reg("rax") != f.Pending()) {
                std::string pc = f.Pending(), pn;
                size_t np = pc.find("   //");
                if (np != std::string::npos) { pn = pc.substr(np); pc = pc.substr(0, np); }
                body.push_back("    " + pc + ";" + pn);
                f.ConsumePending();
            }
            if (dc == "rax") eaxWritten = true;
            continue;
        }
        if (mn == "lea" && ops.size() == 2 && IsRegTok(ops[0])) {
            MemOp m = ParseMem(ops[1]);
            std::string dc = CanonReg(ops[0]);
            if (m.base == "rbp" && m.index.empty()) {
                // &yerel / &arguman
                f.SetReg(dc, "&" + f.FrameRef(m.disp, false));
            } else {
                std::string b = f.Reg(m.base);
                if (b.empty()) b = m.base;
                std::string e = "&" + b;
                if (m.disp > 0) e += " + 0x" + ToHex((u64)m.disp);
                else if (m.disp < 0) e += " - 0x" + ToHex((u64)(-m.disp));
                f.SetReg(dc, e);
            }
            continue;
        }
        if ((mn == "add" || mn == "sub" || mn == "xor" || mn == "and" ||
             mn == "or" || mn == "shl" || mn == "shr" || mn == "imul") &&
            ops.size() == 2 && IsRegTok(ops[0])) {
            std::string dc = CanonReg(ops[0]);
            std::string cur = f.UseVal(dc);
            if (cur.empty()) cur = dc;
            // xor r,r → 0
            if (mn == "xor" && IsRegTok(ops[1]) && CanonReg(ops[1]) == dc) {
                f.SetReg(dc, "0");
                if (dc == "rax") eaxWritten = true;
                continue;
            }
            auto foldRhs = [&](const std::string& o) -> std::string {
                if (IsRegTok(o)) {
                    std::string e = f.Reg(CanonReg(o));
                    return e.empty() ? o : e;
                }
                if (o.find('[') != std::string::npos)
                    return f.MemExpr(ParseMem(o), x);
                return o;
            };
            std::string rhs = foldRhs(ops[1]);
            const char* op = mn == "add" ? " + " : mn == "sub" ? " - " :
                             mn == "xor" ? " ^ " : mn == "and" ? " & " :
                             mn == "or" ? " | " : mn == "shl" ? " << " :
                             mn == "shr" ? " >> " : " * ";
            f.SetReg(dc, "(" + cur + op + rhs + ")");
            continue;
        }
        if ((mn == "cmp" || mn == "test") && ops.size() == 2) {
            auto foldOp = [&](const std::string& o) -> std::string {
                if (IsRegTok(o)) {
                    std::string e = f.UseVal(CanonReg(o));
                    return e.empty() ? o : e;
                }
                if (o.find('[') != std::string::npos)
                    return f.MemExpr(ParseMem(o), x);
                return o;
            };
            cmpL = foldOp(ops[0]);
            cmpR = foldOp(ops[1]);
            cmpIsTest = (mn == "test");
            continue;
        }
        if (x.isJcc && ops.size() >= 1) {
            // jcc anında koşulu kur: test → (a & b) !=/== 0; cmp → a OP b
            std::string neg = mn.substr(1);   // e/ne/z/nz/s/ns/g/...
            std::string ce;
            if (cmpIsTest) {
                std::string op = (neg == "e" || neg == "z") ? "==" : "!=";
                if (neg == "e" || neg == "z" || neg == "ne" || neg == "nz") {
                    // test a,a: ifadeyi TEK kez göster (çağrı katlaması uzun olur)
                    bool plainIdent = !cmpL.empty() &&
                        cmpL.find_first_not_of(
                            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789_") == std::string::npos;
                    std::string lhs = plainIdent ? cmpL : "(" + cmpL + ")";
                    if (cmpL == cmpR) ce = lhs + " " + op + " 0";
                    else ce = "(" + cmpL + " & " + cmpR + ") " + op + " 0";
                } else ce = cmpL + " & " + cmpR;
            } else {
                std::string op;
                if (neg == "e" || neg == "z") op = "==";
                else if (neg == "ne" || neg == "nz") op = "!=";
                else if (neg == "s") op = "< 0";
                else if (neg == "ns") op = ">= 0";
                else if (neg == "g" || neg == "nle") op = ">";
                else if (neg == "ge" || neg == "nl") op = ">=";
                else if (neg == "l" || neg == "nge") op = "<";
                else if (neg == "le" || neg == "ng") op = "<=";
                else if (neg == "b" || neg == "nae") op = "< (u)";
                else if (neg == "be" || neg == "na") op = "<= (u)";
                else if (neg == "a" || neg == "nbe") op = "> (u)";
                else if (neg == "ae" || neg == "nb") op = ">= (u)";
                ce = cmpL + " " + op + " " + cmpR;
                if (op.empty()) ce = cmpL + " ? " + cmpR;
            }
            char b[96];
            snprintf(b, sizeof b, "loc_%llx", (unsigned long long)x.target);
            body.push_back("    if (" + ce + ") goto " + b + ";");
            cmpL.clear(); cmpR.clear();
            continue;
        }
        if (x.isJmp) {
            // kuyruk çağrısı (tail-call) veya dallanma
            if (!x.isIndirect) {
                char b[96];
                snprintf(b, sizeof b, "loc_%llx", (unsigned long long)x.target);
                const FuncInfo* tf = az_.FunctionStart(x.target);
                if (tf && tf->start != start)
                    body.push_back("    return " + callRender(xi) + ";   // kuyruk cagri");
                else
                    body.push_back(std::string("    goto ") + b + ";");
            } else {
                body.push_back("    goto *(dolayli);   // " + x.opStr);
            }
            continue;
        }
        if (mn == "ret") {
            std::string e = f.Reg("rax");
            std::string rn;
            if (!e.empty() && e == f.Pending()) f.ConsumePending();
            size_t np = e.find("   //");
            if (np != std::string::npos) { rn = e.substr(np); e = e.substr(0, np); }
            body.push_back(std::string("    return ") +
                           (e.empty() ? "eax" : e) + ";" + rn);
            // ERKEN ÇIKIŞ: pencereyi durdurma — devam eden gövde de render
            // edilir (birden çok return tek fonksiyonda normal MSVC deseni)
            pushArgs.clear();
            continue;
        }
        if (mn == "leave" || mn == "nop" || mn == "int3") continue;
        // bilinmeyen: yorum satırı olarak koru (dürüstlük)
        if (mn != "endbr32" && mn != "cdq" && mn != "movsx" && mn != "movzx" &&
            mn != "setne" && mn != "sete" && mn != "movsxd")
            body.push_back("    // " + mn + " " + x.opStr);
        if (IsRegTok(ops.empty() ? "" : ops[0]))
            f.SetReg(CanonReg(ops[0]), "");
    }

    // döngü bitti: hâlâ okunmamış çağrı varsa düz ifade olarak ver
    if (!f.Pending().empty()) {
        std::string pc = f.Pending(), pn;
        size_t np = pc.find("   //");
        if (np != std::string::npos) { pn = pc.substr(np); pc = pc.substr(0, np); }
        body.push_back("    " + pc + ";" + pn);
        f.ConsumePending();
    }

    // ---- ÇAĞRI TEK-SEFER GEÇİŞİ (64-bit yoldan devralınan "yutuldu"
    // mekanizması): bağımsız çağrı satırı, aynı ifadenin geçtiği daha uzun
    // bir satır (return / if koşulu / atama) varsa yutulur — çağrı dosyası
    // her noktada TEK kez gösterilir (Hex-Rays semantiği) ----
    {
        auto isCallStmt = [](const std::string& t) {
            if (t.size() < 5 || t.substr(t.size() - 2) != ");") return false;
            if (t.find("loc_") == 0) return false;
            static const char* kw[] = {"return", "if ", "while", "do ",
                                       "else", "goto", "//"};
            for (auto* k : kw) if (t.rfind(k, 0) == 0) return false;
            return t.find('(') != std::string::npos;
        };
        std::set<size_t> eaten;
        for (size_t i = 0; i < body.size(); i++) {
            if (!isCallStmt(body[i])) continue;
            std::string bt = body[i];
            size_t nc = bt.find("   //");
            if (nc != std::string::npos) bt = bt.substr(0, nc);
            std::string core = bt.substr(0, bt.size() - 1);   // ';' kır
            if (core.size() < 3) continue;
            for (size_t j = 0; j < body.size(); j++) {
                if (j == i || eaten.count(j)) continue;
                if (body[j].find(core) != std::string::npos &&
                    body[j].size() > body[i].size()) {
                    eaten.insert(i);
                    break;
                }
            }
        }
        std::vector<std::string> kept;
        kept.reserve(body.size());
        for (size_t i = 0; i < body.size(); i++)
            if (!eaten.count(i)) kept.push_back(body[i]);
        body.swap(kept);
    }

    // ---- imza ----
    std::string fname = az_.NameFor(start);
    std::string sigLine;
    if (pfn && !pfn->proto.empty()) {
        sigLine = pfn->proto;
    } else {
        // PDB parametre adlarıyla imza kur
        if (pfn) {
            fname = pfn->shortName.empty() ? pfn->name : pfn->shortName;
            if (!fname.empty() && fname[0] == '?') fname = pfn->shortName;
        }
        std::string argList;
        for (size_t i = 0; i < f.args_.size(); i++) {
            if (i) argList += ", ";
            argList += "int " + f.args_[i];
        }
        sigLine = "int " + fname + "(" + (argList.empty() ? "void" : argList) + ")";
    }

    std::string out;
    out += "// ============================================================\n";
    out += "// " + fname + "  (" + std::to_string(ins.size()) + " komut, x86-32)\n";
    out += "// kapsam: 0x" + ToHex(start) + " - 0x" +
           ToHex(ins.back().addr + ins.back().len) + "\n";
    out += "// ============================================================\n";
    out += sigLine + "\n{\n";
    // yerel tanımlar
    for (auto& [d, lv] : f.locals_) {
        (void)d;
        out += "    int " + lv.name + ";\n";
    }
    for (auto& t : f.temps_) out += "    int " + t + ";\n";
    out += "\n";
    for (auto& s : body) out += s + "\n";
    // v8.1: vfN SÖZLÜĞÜ footer — PDB'siz adlandırılan sanal çağrıların
    // kanıt koordinatları (vfN = vtable slot N; x86-32 bayt ofseti = 4*N).
    // "vf4 ne?" sorusunun çıktıdaki kalıcı cevabı:
    //   vf4  = CPythonPlayer vftable[0x805054] + 0x10 -> 0x4e2f60
    if (!vfGloss.empty()) {
        out += "\n    // --- vfN sozlugu (PDB'siz adlandirma — kanit adresleri) ---\n";
        for (auto& [slot, line] : vfGloss)
            out += "    // " + line + "\n";
    }
    out += "}\n";
    return out;
}

} // namespace gt
