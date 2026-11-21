// ============================================================================
//  i4M GodTier Engine — core/util.cpp
// ============================================================================
#include "core/util.h"
#include "core/log.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>

namespace gt {

std::string ToHex(uint64_t v, int width) {
    char buf[32];
    if (width > 0 && width <= 16)
        std::snprintf(buf, sizeof(buf), "%0*llx", width, (unsigned long long)v);
    else
        std::snprintf(buf, sizeof(buf), "%llx", (unsigned long long)v);
    return buf;
}

std::string ToHexBytes(const uint8_t* p, size_t n) {
    std::string s;
    s.reserve(n * 3);
    for (size_t i = 0; i < n; i++) {
        char b[4];
        std::snprintf(b, sizeof(b), "%02x ", p[i]);
        s += b;
    }
    if (!s.empty()) s.pop_back();
    return s;
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool StartsWith(const std::string& s, const std::string& pre) {
    return s.size() >= pre.size() && 0 == s.compare(0, pre.size(), pre);
}

std::vector<uint8_t> ReadFileBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

bool WriteFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write((const char*)data.data(), (std::streamsize)data.size());
    return (bool)f;
}

bool FileExists(const std::string& path) {
    std::ifstream f(path);
    return (bool)f;
}

double Entropy(const uint8_t* p, size_t n) {
    if (!n) return 0.0;
    size_t freq[256] = {};
    for (size_t i = 0; i < n; i++) freq[p[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double pxi = (double)freq[i] / (double)n;
        e -= pxi * std::log2(pxi);
    }
    return e;
}

// ----------------------------------------------------------------------------
// MD5 (RFC 1321) — imphash ve genel özet için gömülü minimal implementasyon
// ----------------------------------------------------------------------------
namespace {
struct MD5Ctx {
    uint32_t a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    uint64_t len = 0;
    uint8_t buf[64]{};
    size_t buflen = 0;
};
inline uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }
const uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
const int S[64] = {7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                   5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
                   4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                   6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
void md5block(MD5Ctx& c, const uint8_t blk[64]) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = blk[i*4] | (blk[i*4+1] << 8) | (blk[i*4+2] << 16) | ((uint32_t)blk[i*4+3] << 24);
    uint32_t A = c.a, B = c.b, C = c.c, D = c.d;
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if (i < 16)      { F = (B & C) | (~B & D);      g = i; }
        else if (i < 32) { F = (D & B) | (~D & C);      g = (5*i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;               g = (3*i + 5) % 16; }
        else             { F = C ^ (B | ~D);            g = (7*i) % 16; }
        uint32_t tmp = D; D = C; C = B;
        B = B + rol(A + F + K[i] + M[g], S[i]);
        A = tmp;
    }
    c.a += A; c.b += B; c.c += C; c.d += D;
}
} // namespace

std::vector<uint8_t> MD5(const uint8_t* p, size_t n) {
    MD5Ctx c;
    c.len = n;
    auto feed = [&](const uint8_t* q, size_t m) {
        while (m) {
            size_t take = std::min(m, 64 - c.buflen);
            std::memcpy(c.buf + c.buflen, q, take);
            c.buflen += take; q += take; m -= take;
            if (c.buflen == 64) { md5block(c, c.buf); c.buflen = 0; }
        }
    };
    feed(p, n);
    uint8_t pad = 0x80;
    feed(&pad, 1);
    uint8_t zero = 0;
    while (c.buflen != 56) feed(&zero, 1);
    uint8_t lenbuf[8];
    uint64_t bits = c.len * 8;
    for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(bits >> (8 * i));
    feed(lenbuf, 8);
    std::vector<uint8_t> out(16);
    for (int i = 0; i < 4; i++) {
        out[i]    = (uint8_t)(c.a >> (8*i));
        out[4+i]  = (uint8_t)(c.b >> (8*i));
        out[8+i]  = (uint8_t)(c.c >> (8*i));
        out[12+i] = (uint8_t)(c.d >> (8*i));
    }
    return out;
}

std::string MD5Hex(const uint8_t* p, size_t n) {
    auto d = MD5(p, n);
    std::string s;
    for (uint8_t b : d) {
        char h[3];
        std::snprintf(h, sizeof(h), "%02x", b);
        s += h;
    }
    return s;
}

// ----------------------------------------------------------------------------
// Demangle-lite: Itanium (_ZN...) temel kalıpları; MSVC (?...) sadece tespit
// ----------------------------------------------------------------------------
std::string Demangle(const std::string& m) {
    if (m.size() > 2 && m[0] == '_' && m[1] == 'Z') {
        // özel önekler: vtable/typeinfo/typeinfo-name (Itanium RTTI)
        if (m.rfind("_ZTV", 0) == 0) return "vtable for " + Demangle("_Z" + m.substr(4));
        if (m.rfind("_ZTI", 0) == 0) return "typeinfo for " + Demangle("_Z" + m.substr(4));
        if (m.rfind("_ZTS", 0) == 0) return "typeinfo name for " + Demangle("_Z" + m.substr(4));
        if (m.rfind("_ZTh", 0) == 0 || m.rfind("_ZTv", 0) == 0)
            return "virtual thunk to " + Demangle("_Z" + m.substr(4));
        std::string s = m.substr(2);
        // _ZL... : yerel (static) sembol — L önekini atla
        if (!s.empty() && s[0] == 'L') s = s.substr(1);
        // _ZN...E formu: iç içe isimler
        if (!s.empty() && s[0] == 'N') {
            s = s.substr(1);
            // niteleyicileri atla: K=const, V=volatile, r=restrict, R=&, O=&&
            while (!s.empty() && (s[0] == 'K' || s[0] == 'V' || s[0] == 'r' ||
                                  s[0] == 'R' || s[0] == 'O'))
                s = s.substr(1);
            size_t e = s.rfind('E');
            if (e != std::string::npos) s = s.substr(0, e);
            std::string out, last;
            std::string dtorOf;                 // D0/D1/D2 görülürse yıkıcı sınıfı
            bool isCtor = false;
            size_t i = 0;
            bool ok = true;
            while (i < s.size()) {
                size_t j = i;   // uzunluk önekini İŞARETÇİDEN tara (baştan değil!)
                while (j < s.size() && isdigit((unsigned char)s[j])) j++;
                if (j == i) {
                    // kurucu/yıkıcı kod eki: C1/C2 kurucu, D0/D1/D2 yıkıcı
                    if (i + 1 < s.size() &&
                        (s[i] == 'C' || s[i] == 'D') &&
                        isdigit((unsigned char)s[i + 1])) {
                        if (s[i] == 'D') dtorOf = last;
                        if (s[i] == 'C') isCtor = true;
                        i += 2;      // kod eki atla (parametre listesi kalır)
                        break;       // isim zinciri bitti
                    }
                    ok = false; break;
                }
                int len = std::atoi(s.substr(i, j - i).c_str());
                if ((int)s.size() < (int)j + len) { ok = false; break; }
                last = s.substr(j, (size_t)len);
                if (!out.empty()) out += "::";
                out += last;
                i = j + (size_t)len;
            }
            (void)isCtor;
            if (ok && !out.empty()) {
                // _ZN...D0/D1/D2Ev -> SonSınıf::~SonSınıf
                if (!dtorOf.empty()) {
                    size_t cc = out.rfind("::" + dtorOf);
                    if (cc != std::string::npos)
                        return out.substr(0, cc + 2) + "~" + dtorOf;
                    return out + "::~" + dtorOf;   // tek sınıf: Daire::~Daire
                }
                return out;
            }
        }
        // Basit _Z<form> formu
        size_t j = 0;
        while (j < s.size() && isdigit((unsigned char)s[j])) j++;
        if (j > 0) {
            int len = std::atoi(s.substr(0, j).c_str());
            if ((int)s.size() >= (int)j + len) return s.substr(j, (size_t)len);
        }
        return m;
    }
    return m; // MSVC (?...) tam demangling harici llvm-cxxfilt'e bırakılır
}

} // namespace gt

// ----------------------------------------------------------------------------
// v6: aritmetik ifade çözücü (script set/eval/if motoru)
// ----------------------------------------------------------------------------
#include <cstdlib>

namespace gt {

int64_t EvalArith(const std::string& expr, bool* ok) {
    size_t pos = 0;
    const std::string& s = expr;
    auto skipWs = [&]() { while (pos < s.size() && isspace((unsigned char)s[pos])) pos++; };
    std::function<int64_t(bool&)> parseExpr;
    std::function<int64_t(bool&)> parsePrimary = [&](bool& okk) -> int64_t {
        skipWs();
        if (pos >= s.size()) { okk = false; return 0; }
        if (s[pos] == '(') {
            pos++;
            int64_t v = parseExpr(okk);
            skipWs();
            if (pos < s.size() && s[pos] == ')') pos++;
            else okk = false;
            return v;
        }
        if (s[pos] == '-') { pos++; return -parsePrimary(okk); }
        if (s[pos] == '+') { pos++; return parsePrimary(okk); }
        if (s[pos] == '~') { pos++; return ~parsePrimary(okk); }
        // sayı: 0x hex veya ondalık
        size_t start = pos;
        if (pos + 1 < s.size() && s[pos] == '0' && (s[pos+1] == 'x' || s[pos+1] == 'X')) {
            pos += 2;
            size_t ds = pos;
            while (pos < s.size() && isxdigit((unsigned char)s[pos])) pos++;
            if (pos == ds) { okk = false; return 0; }
            return (int64_t)strtoull(s.substr(start, pos - start).c_str(), nullptr, 16);
        }
        if (!isdigit((unsigned char)s[pos])) { okk = false; return 0; }
        while (pos < s.size() && isdigit((unsigned char)s[pos])) pos++;
        return (int64_t)strtoll(s.substr(start, pos - start).c_str(), nullptr, 10);
    };
    // seviye: << >> (en düşük öncelik burada en dışta olmalı — klasik C önceliği:
    // expr(bitişik |) > ^ > & > shift > eşitlik... biz basitleştiriyoruz:
    // expr := bor ( '|' bor )* ; bor := xor ( '^' xor )* ; xor := band ( '&' band )*
    // band := shift ; shift := mul-shift... pratik sıra:
    std::function<int64_t(bool&, int)> parseShift = [&](bool& okk, int) -> int64_t {
        int64_t v = parsePrimary(okk);
        while (okk) {
            skipWs();
            if (pos + 1 < s.size() && s[pos] == '<' && s[pos+1] == '<') {
                pos += 2; bool o2 = true; int64_t r = parsePrimary(o2);
                if (!o2) { okk = false; break; }
                v <<= r;
            } else if (pos + 1 < s.size() && s[pos] == '>' && s[pos+1] == '>') {
                pos += 2; bool o2 = true; int64_t r = parsePrimary(o2);
                if (!o2) { okk = false; break; }
                v >>= r;
            } else break;
        }
        return v;
    };
    std::function<int64_t(bool&)> parseBand = [&](bool& okk) -> int64_t {
        int64_t v = parseShift(okk, 0);
        while (okk) {
            skipWs();
            if (pos < s.size() && s[pos] == '&' && !(pos + 1 < s.size() && s[pos+1] == '&')) {
                pos++; bool o2 = true; int64_t r = parseShift(o2, 0);
                if (!o2) { okk = false; break; }
                v &= r;
            } else break;
        }
        return v;
    };
    std::function<int64_t(bool&)> parseXor = [&](bool& okk) -> int64_t {
        int64_t v = parseBand(okk);
        while (okk) {
            skipWs();
            if (pos < s.size() && s[pos] == '^') {
                pos++; bool o2 = true; int64_t r = parseBand(o2);
                if (!o2) { okk = false; break; }
                v ^= r;
            } else break;
        }
        return v;
    };
    std::function<int64_t(bool&)> parseBor = [&](bool& okk) -> int64_t {
        int64_t v = parseXor(okk);
        while (okk) {
            skipWs();
            if (pos < s.size() && s[pos] == '|' && !(pos + 1 < s.size() && s[pos+1] == '|')) {
                pos++; bool o2 = true; int64_t r = parseXor(o2);
                if (!o2) { okk = false; break; }
                v |= r;
            } else break;
        }
        return v;
    };
    std::function<int64_t(bool&)> parseTerm = [&](bool& okk) -> int64_t {
        int64_t v = parseBor(okk);
        while (okk) {
            skipWs();
            if (pos < s.size() && s[pos] == '*') {
                pos++; bool o2 = true; int64_t r = parseBor(o2);
                if (!o2) { okk = false; break; }
                v *= r;
            } else if (pos < s.size() && s[pos] == '/') {
                pos++; bool o2 = true; int64_t r = parseBor(o2);
                if (!o2 || r == 0) { okk = false; break; }
                v /= r;
            } else if (pos < s.size() && s[pos] == '%') {
                pos++; bool o2 = true; int64_t r = parseBor(o2);
                if (!o2 || r == 0) { okk = false; break; }
                v %= r;
            } else break;
        }
        return v;
    };
    parseExpr = [&](bool& okk) -> int64_t {
        int64_t v = parseTerm(okk);
        while (okk) {
            skipWs();
            if (pos < s.size() && s[pos] == '+') {
                pos++; bool o2 = true; int64_t r = parseTerm(o2);
                if (!o2) { okk = false; break; }
                v += r;
            } else if (pos < s.size() && s[pos] == '-') {
                pos++; bool o2 = true; int64_t r = parseTerm(o2);
                if (!o2) { okk = false; break; }
                v -= r;
            } else break;
        }
        return v;
    };
    bool okk = true;
    int64_t v = parseExpr(okk);
    skipWs();
    if (pos != s.size()) okk = false;   // artık karakter: çözülemedi
    if (ok) *ok = okk;
    return okk ? v : 0;
}

} // namespace gt
