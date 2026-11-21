// ============================================================================
//  i4M GodTier Engine — format/pdb.cpp
//  MSF 7.00 + TPI + DBI sembol taraması. PDBX v3 (0xByteDeveloper) çekirdeği
//  uyarlaması: blok tabanlı stream okuma, TPI leaf ayrıştırma, S_GPROC32 ve
//  PUB32/S_DATA taraması, BP-göreli yerel değişken çıkarma.
// ============================================================================
#include "format/pdb.h"
#include "core/log.h"
#include "core/util.h"
#include <algorithm>
#include <cstring>

namespace gt {
namespace {

inline u16 rd16p(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }
inline u32 rd32p(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
inline u64 rd64p(const u8* p) { return (u64)rd32p(p) | ((u64)rd32p(p + 4) << 32); }

struct NumLeaf { i64 val = 0; const u8* next = nullptr; bool ok = false; };
NumLeaf ReadNum(const u8* p, const u8* end) {
    NumLeaf r;
    if (p + 2 > end) return r;
    u16 v = rd16p(p);
    if (v < 0x8000) { r.val = v; r.next = p + 2; r.ok = true; return r; }
    switch (v) {
    case 0x8000: if (p + 3 <= end) { r.val = (i8)p[2]; r.next = p + 3; r.ok = true; } break;
    case 0x8001: if (p + 4 <= end) { r.val = (i16)rd16p(p + 2); r.next = p + 4; r.ok = true; } break;
    case 0x8002: if (p + 4 <= end) { r.val = rd16p(p + 2); r.next = p + 4; r.ok = true; } break;
    case 0x8003: if (p + 6 <= end) { r.val = (i32)rd32p(p + 2); r.next = p + 6; r.ok = true; } break;
    case 0x8004: if (p + 6 <= end) { r.val = (i64)rd32p(p + 2); r.next = p + 6; r.ok = true; } break;
    case 0x8009: case 0x800A:
        if (p + 10 <= end) { r.val = (i64)rd64p(p + 2); r.next = p + 10; r.ok = true; } break;
    default: r.next = p + 2; break;
    }
    return r;
}
std::string ReadCStr(const u8* p, const u8* end, const u8** nextOut) {
    const u8* e = p;
    while (e < end && *e) e++;
    std::string s((const char*)p, e - p);
    if (nextOut) *nextOut = e < end ? e + 1 : end;
    return s;
}
bool PrintableName(const u8* p, size_t max, size_t* lenOut) {
    size_t n = 0;
    while (n < max && p[n]) {
        if (p[n] < 0x20 || p[n] > 0x7E) return false;
        n++;
    }
    if (n == 0 || n >= max) return false;
    *lenOut = n;
    return true;
}

const char* SimpleTypeName(u32 t) {
    switch (t & 0xFF) {
    case 0x03: return "void";
    case 0x10: return "char";
    case 0x11: return "short";
    case 0x12: return "int";
    case 0x13: return "__int64";
    case 0x20: return "unsigned char";
    case 0x21: return "unsigned short";
    case 0x22: return "unsigned int";
    case 0x23: return "unsigned __int64";
    case 0x30: return "bool";
    case 0x40: return "float";
    case 0x41: return "double";
    case 0x68: return "int8";
    case 0x69: return "int16";
    case 0x6a: return "int32";
    case 0x6b: return "int64";
    case 0x74: return "int";
    case 0x75: return "unsigned int";
    default: return nullptr;
    }
}

} // anonim

// ----------------------------------------------------------------------------
// MSF konteyner
// ----------------------------------------------------------------------------
bool Msf::Load(const std::vector<u8>& raw, std::string& err) {
    if (raw.size() < 0x40) { err = "dosya cok kucuk"; return false; }
    if (memcmp(raw.data(), "Microsoft C/C++ MSF 7.00", 24) != 0) {
        err = "MSF 7.00 imzasi yok (bu surum desteklenmiyor)";
        return false;
    }
    blockSize = rd32p(raw.data() + 0x20);
    numBlocks = rd32p(raw.data() + 0x28);
    u32 dirBytes = rd32p(raw.data() + 0x2C);
    u32 dirMapAddr = rd32p(raw.data() + 0x34);
    if (blockSize < 512 || blockSize > (1 << 16) || (blockSize & (blockSize - 1))) {
        err = "gecersiz blok boyutu"; return false;
    }
    data = raw;
    if ((u64)numBlocks * blockSize > raw.size())
        numBlocks = (u32)(raw.size() / blockSize);
    u32 nDirBlocks = (dirBytes + blockSize - 1) / blockSize;
    if ((u64)dirMapAddr * blockSize + (u64)nDirBlocks * 4 > raw.size()) {
        err = "dizin adresi tasma"; return false;
    }
    std::vector<u8> dir;
    dir.reserve(dirBytes);
    const u8* mapBase = raw.data() + (size_t)dirMapAddr * blockSize;
    for (u32 i = 0; i < nDirBlocks; i++) {
        u32 b = rd32p(mapBase + i * 4);
        if (b >= numBlocks) { err = "dizin blogu gecersiz"; return false; }
        size_t off = (size_t)b * blockSize;
        size_t take = blockSize;
        if (dir.size() + take > dirBytes) take = dirBytes - dir.size();
        dir.insert(dir.end(), data.begin() + off, data.begin() + off + take);
    }
    if (dir.size() < 4) { err = "dizin bos"; return false; }
    u32 nStreams = rd32p(dir.data());
    size_t p = 4;
    std::vector<u32> sizes(nStreams);
    for (u32 i = 0; i < nStreams; i++) {
        if (p + 4 > dir.size()) { err = "dizin bozuk (1)"; return false; }
        sizes[i] = rd32p(dir.data() + p); p += 4;
    }
    streams.resize(nStreams);
    for (u32 i = 0; i < nStreams; i++) {
        u32 sz = sizes[i];
        streams[i].size = sz;
        if (sz == 0xFFFFFFFF || sz == 0) continue;
        u32 nb = (sz + blockSize - 1) / blockSize;
        for (u32 k = 0; k < nb; k++) {
            if (p + 4 > dir.size()) { err = "dizin bozuk (2)"; return false; }
            u32 b = rd32p(dir.data() + p); p += 4;
            if (b >= numBlocks) { err = "stream blogu gecersiz"; return false; }
            streams[i].blocks.push_back(b);
        }
    }
    return true;
}

bool Msf::StreamBytes(size_t idx, std::vector<u8>& out) const {
    out.clear();
    if (idx >= streams.size()) return false;
    const MsfStream& s = streams[idx];
    if (s.size == 0xFFFFFFFF || s.size == 0) return true;
    out.reserve(s.size);
    for (u32 b : s.blocks) {
        if (b >= numBlocks) return false;
        size_t off = (size_t)b * blockSize;
        size_t take = blockSize;
        if (out.size() + take > s.size) take = s.size - out.size();
        out.insert(out.end(), data.begin() + off, data.begin() + off + take);
        if (out.size() >= s.size) break;
    }
    return true;
}

// ----------------------------------------------------------------------------
// tip erişimi
// ----------------------------------------------------------------------------
const PdbTypeRec* PdbInfo::Type(u32 idx) const {
    auto it = types_.find(idx);
    return it == types_.end() ? nullptr : &it->second;
}
const PdbTypeRec* PdbInfo::CompleteType(u32 idx) const {
    const PdbTypeRec* t = Type(idx);
    if (!t) return nullptr;
    if (!t->members.empty() || t->name.empty()) return t;
    auto it = completeByName_.find(t->name);
    if (it == completeByName_.end()) return t;
    const PdbTypeRec* c = Type(it->second);
    return (c && !c->members.empty()) ? c : t;
}

std::string PdbInfo::TypeName(u32 idx, int depth) const {
    if (depth > 8) return "...";
    if (idx < 0x1000) {
        u32 mode = (idx >> 8) & 0xFF;
        const char* base = SimpleTypeName(idx);
        char b[32];
        if (!base) { snprintf(b, sizeof b, "T_%X", idx & 0xFF); base = b; }
        if (mode == 0) return base;
        if (mode == 0x0A || mode == 0x09) return std::string(base) + " &";
        return std::string(base) + " *";
    }
    const PdbTypeRec* t = CompleteType(idx);
    if (!t || !t->valid) {
        char b[16]; snprintf(b, sizeof b, "#%X", idx); return b;
    }
    switch (t->leaf) {
    case 0x1504: case 0x1505: case 0x1506: case 0x1507:
        return t->name.empty() ? ("#" + std::to_string(idx)) : t->name;
    case 0x1002:   // POINTER
        return TypeName(t->a, depth + 1) + " *";
    case 0x1001: { // MODIFIER
        std::string s;
        if (t->attr16 & 1) s += "const ";
        if (t->attr16 & 2) s += "volatile ";
        return s + TypeName(t->a, depth + 1);
    }
    case 0x1503: { // ARRAY
        char sz[32];
        snprintf(sz, sizeof sz, " [%llu]", (unsigned long long)t->size);
        return TypeName(t->a, depth + 1) + std::string(sz);
    }
    case 0x1205: return TypeName(t->baseType, depth + 1);
    case 0x1008: case 0x1009: return "<fonksiyon>";
    default:
        return t->name.empty() ? ("#" + std::to_string(idx)) : t->name;
    }
}

// ----------------------------------------------------------------------------
// TPI ayrıştırma (PDBX akışı: iki geçiş leaf + fieldlist)
// ----------------------------------------------------------------------------
bool PdbInfo::ParseTpi(const std::vector<u8>& tpi) {
    if (tpi.size() < 64) return false;
    u32 hdrSize = rd32p(tpi.data() + 4);
    if (hdrSize < 28 || hdrSize > tpi.size()) return false;
    tpiBegin_ = rd32p(tpi.data() + 8);
    struct RawRec { u16 leaf; const u8* body; const u8* end; };
    std::map<u32, RawRec> raws;
    u32 idx = tpiBegin_;
    size_t p = hdrSize;
    while (p + 4 <= tpi.size()) {
        u16 ln = rd16p(tpi.data() + p);
        u16 leaf = rd16p(tpi.data() + p + 2);
        if (ln < 2) break;
        if (p + 2 + ln > tpi.size()) break;
        raws[idx] = {leaf, tpi.data() + p + 4, tpi.data() + p + 2 + ln};
        idx++;
        p += 2 + ln;
    }
    // 1. geçiş: kayıtlar
    for (auto& kv : raws) {
        u32 id = kv.first;
        const RawRec& r = kv.second;
        PdbTypeRec t;
        t.leaf = r.leaf;
        switch (r.leaf) {
        case 0x1504: case 0x1505:
            if (r.body + 18 <= r.end) {
                t.fieldlist = rd32p(r.body + 4);
                NumLeaf n = ReadNum(r.body + 16, r.end);
                if (n.ok) { t.size = (u64)n.val; t.sizeKnown = true; }
                t.name = ReadCStr(r.body + 18, r.end, nullptr);
                t.valid = true;
            }
            break;
        case 0x1506:
            if (r.body + 10 <= r.end) {
                t.fieldlist = rd32p(r.body + 4);
                NumLeaf n = ReadNum(r.body + 8, r.end);
                if (n.ok) { t.size = (u64)n.val; t.sizeKnown = true; }
                t.name = ReadCStr(r.body + 10, r.end, nullptr);
                t.valid = true;
            }
            break;
        case 0x1507:
            if (r.body + 12 <= r.end) {
                t.fieldlist = rd32p(r.body + 8);
                t.name = ReadCStr(r.body + 12, r.end, nullptr);
                t.valid = true;
            }
            break;
        case 0x1001:
            if (r.body + 6 <= r.end) { t.a = rd32p(r.body); t.attr16 = rd16p(r.body + 4); t.valid = true; }
            break;
        case 0x1002:
            if (r.body + 8 <= r.end) { t.a = rd32p(r.body); t.attr16 = (u16)(rd32p(r.body + 4) & 0xFFFF); t.valid = true; }
            break;
        case 0x1503:
            if (r.body + 10 <= r.end) {
                t.a = rd32p(r.body); t.b = rd32p(r.body + 4);
                NumLeaf n = ReadNum(r.body + 8, r.end);
                if (n.ok) { t.size = (u64)n.val; t.sizeKnown = true; }
                t.valid = true;
            }
            break;
        case 0x1008:
            if (r.body + 12 <= r.end) {
                t.rvType = rd32p(r.body); t.callconv = rd16p(r.body + 4);
                t.nparams = rd16p(r.body + 6); t.arglist = rd32p(r.body + 8);
                t.valid = true;
            }
            break;
        case 0x1009:
            if (r.body + 24 <= r.end) {
                t.rvType = rd32p(r.body); t.clsType = rd32p(r.body + 4); t.thisType = rd32p(r.body + 8);
                t.callconv = rd16p(r.body + 12); t.nparams = rd16p(r.body + 14); t.arglist = rd32p(r.body + 16);
                t.valid = true;
            }
            break;
        case 0x1201: {
            if (r.body + 4 <= r.end) {
                u32 n = rd32p(r.body);
                for (u32 i = 0; i < n && r.body + 4 + 4 * (i + 1) <= r.end; i++)
                    t.args.push_back(rd32p(r.body + 4 + 4 * i));
                t.valid = true;
            }
            break;
        }
        case 0x1203: t.valid = true; break;
        case 0x1205:
            if (r.body + 6 <= r.end) { t.baseType = rd32p(r.body); t.bitLen = r.body[4]; t.bitPos = r.body[5]; t.valid = true; }
            break;
        default: break;
        }
        types_[id] = std::move(t);
    }
    // 2. geçiş: fieldlist üyeleri
    for (auto& kv : raws) {
        if (kv.second.leaf != 0x1203) continue;
        const u8* q = kv.second.body;
        const u8* end = kv.second.end;
        PdbTypeRec& fr = types_[kv.first];
        int guard = 0;
        while (q + 2 <= end && guard++ < 100000) {
            u16 lf2 = rd16p(q);
            const u8* body = q + 2;
            if (lf2 == 0x150D) { // LF_MEMBER
                if (body + 8 > end) break;
                PdbMember m;
                m.attr = rd16p(body);
                m.tidx = rd32p(body + 2);
                NumLeaf n = ReadNum(body + 6, end);
                const u8* np = nullptr;
                if (n.ok) {
                    m.off = n.val;
                    m.name = ReadCStr(n.next, end, &np);
                } else {
                    m.name = ReadCStr(body + 8, end, &np);
                }
                if (m.name.empty() || !np) break;
                fr.members.push_back(std::move(m));
                q = np;
            } else if (lf2 == 0x1502) { // LF_ENUMERATE
                if (body + 4 > end) break;
                PdbEnumVal ev;
                NumLeaf n = ReadNum(body + 2, end);
                const u8* np = nullptr;
                if (n.ok) {
                    ev.val = n.val;
                    ev.name = ReadCStr(n.next, end, &np);
                } else {
                    ev.name = ReadCStr(body + 4, end, &np);
                }
                if (ev.name.empty() || !np) break;
                fr.evals.push_back(std::move(ev));
                q = np;
            } else if (lf2 == 0x1510) { // LF_NESTTYPE
                if (body + 6 > end) break;
                PdbMember m;
                m.attr = 0xFFFF;
                m.tidx = rd32p(body + 2);
                m.off = -1;
                const u8* np = nullptr;
                m.name = ReadCStr(body + 6, end, &np);
                if (m.name.empty() || !np) break;
                fr.members.push_back(std::move(m));
                q = np;
            } else if (lf2 == 0x1409) { // LF_VFUNCTAB
                if (body + 6 > end) break;
                PdbMember m;
                m.attr = 0xFFFE;
                m.tidx = rd32p(body + 2);
                m.off = -1;
                m.name = "`vftable'";
                fr.members.push_back(std::move(m));
                q = body + 6;
            } else if (lf2 == 0x150E) { // LF_STMEMBER
                if (body + 6 > end) break;
                PdbMember m;
                m.attr = 0xFFFD;
                m.tidx = rd32p(body + 2);
                m.off = -1;
                const u8* np = nullptr;
                m.name = ReadCStr(body + 6, end, &np);
                if (m.name.empty() || !np) break;
                fr.members.push_back(std::move(m));
                q = np;
            } else if (lf2 == 0x1400) { // LF_BCLASS
                if (body + 6 > end) break;
                NumLeaf n = ReadNum(body + 6, end);
                if (!n.ok) break;
                q = n.next;
            } else if (lf2 == 0x1401 || lf2 == 0x1402) { // VBCLASS/IVBCLASS
                if (body + 6 > end) break;
                NumLeaf n1 = ReadNum(body + 6, end);
                if (!n1.ok) break;
                NumLeaf n2 = ReadNum(n1.next, end);
                if (!n2.ok) break;
                q = n2.next;
            } else if (lf2 == 0x1408) { // LF_INDEX
                if (body + 6 > end) break;
                q = body + 6;
            } else if (lf2 == 0x140A) { // LF_VFUNCOFF
                if (body + 10 > end) break;
                q = body + 10;
            } else if (lf2 == 0x150F || lf2 == 0x1511 || lf2 == 0x150C) {
                // METHOD/ONEMETHOD: adı atla
                if (body + 6 > end) break;
                const u8* np = nullptr;
                size_t extra = (lf2 == 0x1511) ? 6 : 0;
                // ONEMETHOD: attr(2)+tidx(4)[+vbaseoff(4)]name — mprop'a göre
                const u8* npos = body + 6;
                u16 attr = lf2 == 0x1511 ? rd16p(body) : 0;
                u16 mprop = (attr >> 2) & 0x1F;
                if (lf2 == 0x1511 && (mprop == 4 || mprop == 6)) npos += 4;
                if (npos > end) break;
                std::string nm = ReadCStr(npos, end, &np);
                if (nm.empty() || !np) break;
                (void)extra;
                q = np;
            } else if (lf2 == 0x1509) { // iç enum bildirimi
                if (body + 12 > end) break;
                PdbMember m;
                m.attr = 0xFFFF;
                m.tidx = rd32p(body + 4);
                m.off = -1;
                const u8* np = nullptr;
                m.name = ReadCStr(body + 12, end, &np);
                if (m.name.empty() || !np) break;
                fr.members.push_back(std::move(m));
                q = np;
            } else {
                break; // bilinmeyen üye: dur
            }
            while (q < end && *q >= 0xF0) q += (*q - 0xF0);   // pad baytları
        }
    }
    // 3. geçiş: fieldlist -> sahip struct bağlantısı + isim->en-tam-kayıt
    for (auto& kv : types_) {
        PdbTypeRec& t = kv.second;
        if (!t.fieldlist) continue;
        auto fit = types_.find(t.fieldlist);
        if (fit == types_.end()) continue;
        PdbTypeRec& fl = fit->second;
        if (t.leaf == 0x1507) t.evals = fl.evals;
        else t.members = fl.members;
    }
    for (auto& kv : types_) {
        const PdbTypeRec& t = kv.second;
        if (t.name.empty()) continue;
        if (t.leaf != 0x1504 && t.leaf != 0x1505 && t.leaf != 0x1506 && t.leaf != 0x1507) continue;
        auto it = completeByName_.find(t.name);
        if (it == completeByName_.end()) completeByName_[t.name] = kv.first;
        else if (t.members.size() > types_[it->second].members.size())
            completeByName_[t.name] = kv.first;
    }
    return true;
}

// ----------------------------------------------------------------------------
// modül sembol akışı: S_GPROC32 + yerel değişkenler
// ----------------------------------------------------------------------------
void PdbInfo::ScanModuleStream(const std::vector<u8>& buf) {
    size_t n = buf.size();
    if (n < 200) return;
    std::vector<size_t> procStarts;
    std::vector<PdbFunc> found;
    for (size_t R = 0; R + 44 <= n; R++) {
        u16 ln = rd16p(buf.data() + R);
        u16 kind = rd16p(buf.data() + R + 2);
        if (kind != 0x1110 && kind != 0x110F) continue;
        if (ln < 39 || ln > 800 || R + 2 + ln > n) continue;
        const u8* body = buf.data() + R + 4;
        u32 pEnd = rd32p(body + 4);
        u32 codesz = rd32p(body + 12);
        u32 off = rd32p(body + 28);
        u32 seg = rd16p(body + 32);
        u32 pParent = rd32p(body);
        if (seg < 1 || seg > 64) continue;
        if (off > 0x4000000 || codesz > 0x200000) continue;
        if (pEnd > n) continue;
        if (pParent != 0 && pParent > n) continue;
        size_t nameLen = 0;
        if (!PrintableName(body + 35, ln - 36, &nameLen)) continue;
        PdbFunc f;
        f.name.assign((const char*)body + 35, nameLen);
        f.seg = seg; f.off = off; f.size = codesz; f.tidx = rd32p(body + 24);
        f.hasType = Type(f.tidx) != nullptr;
        found.push_back(std::move(f));
        procStarts.push_back(R);
        R += 2 + ln - 1;
    }
    if (found.empty()) return;
    // yerel değişkenler (PROC gövdesi içinde)
    for (size_t k = 0; k < procStarts.size(); k++) {
        size_t R = procStarts[k];
        u16 ln = rd16p(buf.data() + R);
        size_t q = R + 2 + ln;
        size_t pEnd = rd32p(buf.data() + R + 4 + 4);
        if (pEnd > n) pEnd = n;
        std::set<std::string> seen;
        while (q + 4 <= pEnd) {
            u16 ln2 = rd16p(buf.data() + q);
            u16 k2 = rd16p(buf.data() + q + 2);
            if (ln2 < 2 || q + 2 + ln2 > n) break;
            const u8* body = buf.data() + q + 4;
            const u8* bend = buf.data() + q + 2 + ln2;
            if (k2 == 0x0006) break; // S_END
            if (k2 == 0x110B && body + 12 <= bend) {  // S_BPREL32
                PdbLocal v;
                v.off = (i32)rd32p(body);
                v.tidx = rd32p(body + 4);
                const u8* np = nullptr;
                v.name = ReadCStr(body + 8, bend, &np);
                v.isArg = v.off >= 8;
                if (!v.name.empty() && seen.insert(v.name).second)
                    found[k].locals.push_back(std::move(v));
            } else if (k2 == 0x1106 && body + 10 <= bend) {  // S_REGISTER
                PdbLocal v;
                v.tidx = rd32p(body);
                // reg no: body+4 — isim body+6
                const u8* np = nullptr;
                v.name = ReadCStr(body + 6, bend, &np);
                if (!v.name.empty() && seen.insert(v.name).second)
                    found[k].locals.push_back(std::move(v));
            } else if (k2 == 0x1111 && body + 14 <= bend) {  // S_BPREL32_1995
                PdbLocal v;
                v.off = (i32)rd32p(body);
                v.tidx = rd32p(body + 4);
                const u8* np = nullptr;
                v.name = ReadCStr(body + 10, bend, &np);
                v.isArg = v.off >= 8;
                if (!v.name.empty() && seen.insert(v.name).second)
                    found[k].locals.push_back(std::move(v));
            } else if (k2 == 0x113E && body + 10 <= bend) {  // S_LOCAL
                PdbLocal v;
                v.tidx = rd32p(body);
                const u8* np = nullptr;
                v.name = ReadCStr(body + 6, bend, &np);
                size_t z = q + 2 + ln2;
                int guard = 0;
                while (z + 4 <= pEnd && guard++ < 12) {
                    u16 ln3 = rd16p(buf.data() + z);
                    u16 k3 = rd16p(buf.data() + z + 2);
                    if (ln3 < 2 || z + 2 + ln3 > n) break;
                    if (k3 == 0x113E || k3 == 0x0006) break;
                    if (k3 == 0x1144 && ln3 >= 6) {   // S_DEFRANGE
                        v.off = (i32)rd32p(buf.data() + z + 4);
                        break;
                    }
                    z += 2 + ln3;
                }
                v.isArg = v.off >= 8;
                if (!v.name.empty() && seen.insert(v.name).second)
                    found[k].locals.push_back(std::move(v));
            }
            q += 2 + ln2;
        }
    }
    for (auto& f : found) {
        if (getenv("GODTIER_PDB_DEBUG"))
            std::printf("[PDB] func %s locals=%zu (ilk off=%d)\n",
                        f.name.c_str(), f.locals.size(),
                        f.locals.empty() ? 0 : f.locals[0].off);
        funcs_.push_back(std::move(f));
    }
}

// ----------------------------------------------------------------------------
// global kayıtlar: PUB32 + DATA
// ----------------------------------------------------------------------------
void PdbInfo::ScanGlobalRecords(const std::vector<u8>& buf) {
    size_t n = buf.size();
    size_t p = 0;
    while (p + 4 <= n) {
        u16 ln = rd16p(buf.data() + p);
        u16 kind = rd16p(buf.data() + p + 2);
        if (ln < 2 || p + 2 + ln > n) break;
        const u8* body = buf.data() + p + 4;
        const u8* bend = buf.data() + p + 2 + ln;
        if (kind == 0x110E && body + 10 <= bend) { // S_PUB32
            u32 off = rd32p(body + 4);
            u16 seg = rd16p(body + 8);
            const u8* np = nullptr;
            std::string nm = ReadCStr(body + 10, bend, &np);
            if (seg >= 1 && seg <= 64 && off <= 0x4000000 && nm.size() > 2)
                pubByVa_[((u64)seg << 32) | off] = nm;
        } else if ((kind == 0x110D || kind == 0x110C) && body + 10 <= bend) {
            PdbGlobal g;
            g.tidx = rd32p(body);
            g.off = rd32p(body + 4);
            g.seg = rd16p(body + 8);
            const u8* np = nullptr;
            g.name = ReadCStr(body + 10, bend, &np);
            if (g.seg >= 1 && g.seg <= 64 && g.off <= 0x4000000 && g.name.size() > 1)
                globals_.push_back(std::move(g));
        } else if (kind == 0x1107 && body + 4 <= bend) { // S_CONSTANT
            NumLeaf v = ReadNum(body + 4, bend);
            if (v.ok) {
                std::string nm = ReadCStr(v.next, bend, nullptr);
                (void)nm;   // sabitler: şimdilik sadece tara
            }
        }
        p += 2 + ln;
    }
}

// ----------------------------------------------------------------------------
// dosya yükleme
// ----------------------------------------------------------------------------
bool PdbInfo::Load(const std::string& path) {
    std::vector<u8> raw = ReadFileBytes(path);
    if (raw.empty()) { err_ = "dosya okunamadi/bos: " + path; return false; }
    pdbPath_ = path;
    return Parse(raw, err_);
}

bool PdbInfo::Parse(const std::vector<u8>& raw, std::string& err) {
    if (!msf_.Load(raw, err)) return false;
    {   // stream 1: PDB info (GUID + age)
        std::vector<u8> info;
        if (msf_.StreamBytes(1, info) && info.size() >= 32) {
            age_ = rd32p(info.data() + 8);
            char guid[48];
            const u8* g = info.data() + 12;
            snprintf(guid, sizeof guid,
                     "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X%02X%02X",
                     g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
                     g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
            guidStr_ = guid;
        }
    }
    {   // stream 2: TPI
        std::vector<u8> tpi;
        if (!msf_.StreamBytes(2, tpi)) { err = "TPI stream yok"; return false; }
        ParseTpi(tpi);
    }
    // modül akışları (5..n): S_GPROC32'ler
    for (size_t i = 3; i < msf_.streams.size(); i++) {
        std::vector<u8> buf;
        if (!msf_.StreamBytes(i, buf)) continue;
        if (buf.size() < 200) continue;
        ScanModuleStream(buf);
    }
    // globals: PUB32 yoğunluğu en yüksek büyük akış
    {
        size_t best = 0, bestCount = 0;
        std::vector<u8> bestBuf;
        for (size_t i = 3; i < msf_.streams.size(); i++) {
            std::vector<u8> buf;
            if (!msf_.StreamBytes(i, buf)) continue;
            if (buf.size() < 4096) continue;
            size_t cnt = 0, p = 0;
            while (p + 4 <= buf.size()) {
                u16 ln = rd16p(buf.data() + p);
                u16 kind = rd16p(buf.data() + p + 2);
                if (ln < 2 || p + 2 + ln > buf.size()) break;
                if (kind == 0x110E && ln >= 12) {
                    u16 seg = rd16p(buf.data() + p + 4 + 8);
                    if (seg >= 1 && seg <= 64) cnt++;
                }
                p += 2 + ln;
            }
            if (cnt > bestCount) { bestCount = cnt; best = i; bestBuf = std::move(buf); }
        }
        if (bestCount >= 1) ScanGlobalRecords(bestBuf);
    }
    LogInfo("PDB: %zu tip, %zu fonksiyon, %zu global (GUID %s)",
            types_.size(), funcs_.size(), globals_.size(), guidStr_.c_str());
    return !funcs_.empty() || !globals_.empty() || !types_.empty();
}

// ----------------------------------------------------------------------------
// VA çözümü + prototip
// ----------------------------------------------------------------------------
void PdbInfo::ResolveVAs(u64 imageBase, const std::vector<SectionInfo>& secs) {
    auto secRva = [&](u32 seg) -> u64 {
        if (seg < 1 || (size_t)seg > secs.size()) return 0;
        u64 v = secs[seg - 1].va;
        // SectionInfo.va PE'de ImageBase dahindir — RVA'ya indir (ELF zaten RVA)
        if (imageBase && v >= imageBase) v -= imageBase;
        return v;
    };
    for (auto& f : funcs_)
        f.va = imageBase + secRva(f.seg) + f.off;
    std::sort(funcs_.begin(), funcs_.end(), [](const PdbFunc& a, const PdbFunc& b) {
        if (a.va != b.va) return a.va < b.va;
        return a.size > b.size;
    });
    funcByVa_.clear();
    for (size_t i = 0; i < funcs_.size(); i++) funcByVa_[funcs_[i].va] = i;
    for (auto& g : globals_)
        g.va = imageBase + secRva(g.seg) + g.off;
    std::sort(globals_.begin(), globals_.end(),
              [](const PdbGlobal& a, const PdbGlobal& b) { return a.va < b.va; });
    // pub32 mangled isimleri eşleştir
    for (auto& kv : pubByVa_) {
        u16 seg = (u16)(kv.first >> 32);
        u32 off = (u32)(kv.first & 0xFFFFFFFF);
        u64 va = imageBase + secRva(seg) + off;
        auto it = funcByVa_.find(va);
        if (it != funcByVa_.end() && funcs_[it->second].mangled.empty())
            funcs_[it->second].mangled = kv.second;
    }
    // kısa isimler (MSVC dekor zinciri: ?Metod@Sinif@@...) + arg adları + proto
    for (auto& f : funcs_) {
        const std::string& m = !f.mangled.empty() ? f.mangled : f.name;
        if (m.size() > 3 && m[0] == '?' && m[1] == '?') {
            if (m[2] == '0' || m[2] == '1') {   // kurucu/yıkıcı
                std::vector<std::string> ids;
                size_t i = 3;
                while (i < m.size()) {
                    size_t j = m.find('@', i);
                    if (j == std::string::npos || j == i) break;
                    ids.push_back(m.substr(i, j - i));
                    i = j + 1;
                }
                if (!ids.empty()) {
                    std::string cls;
                    for (size_t k = ids.size(); k-- > 0;) {
                        if (!cls.empty()) cls += "::";
                        cls += ids[k];
                    }
                    f.shortName = cls + "::" +
                        (m[2] == '0' ? ids.back() : "~" + ids.back());
                }
            }
        }
        if (f.shortName.empty() && !m.empty() && m[0] == '?') {
            std::vector<std::string> ids;
            size_t i = 1;
            while (i < m.size()) {
                size_t j = m.find('@', i);
                if (j == std::string::npos || j == i) break;
                ids.push_back(m.substr(i, j - i));
                i = j + 1;
            }
            if (!ids.empty()) {
                std::string r;
                for (size_t k = ids.size(); k-- > 0;) {
                    if (!r.empty()) r += "::";
                    r += ids[k];
                }
                f.shortName = r;
            }
        }
        // konumsal arg adları: [ebp+8]=arg0, [ebp+C]=arg1 ... (32-bit thiscall/cdecl)
        const PdbTypeRec* t = Type(f.tidx);
        if (t && (t->leaf == 0x1009 || t->leaf == 0x1008)) {
            const PdbTypeRec* al = Type(t->arglist);
            size_t nargs = (al && al->leaf == 0x1201) ? al->args.size() : 0;
            size_t skip = (t->leaf == 0x1009 && nargs == (size_t)t->nparams + 1) ? 1 : 0;
            f.argNames.resize(nargs > skip ? nargs - skip : 0);
            for (auto& v : f.locals) {
                if (v.off < 8) continue;
                size_t ai = (size_t)((v.off - 8) / 4);
                if (ai < f.argNames.size() && f.argNames[ai].empty())
                    f.argNames[ai] = v.name;
            }
            f.proto = FullProto(f);
        }
    }
}

std::string PdbInfo::FullProto(const PdbFunc& f) const {
    const PdbTypeRec* t = Type(f.tidx);
    if (!t || (t->leaf != 0x1009 && t->leaf != 0x1008)) return f.name;
    std::string rv = TypeName(t->rvType);
    std::string cls;
    if (t->leaf == 0x1009) cls = TypeName(t->clsType);
    const PdbTypeRec* al = Type(t->arglist);
    std::vector<u32> ats;
    if (al && al->leaf == 0x1201) ats = al->args;
    size_t start = (t->leaf == 0x1009 && ats.size() == (size_t)t->nparams + 1) ? 1 : 0;
    std::string args;
    for (size_t i = start; i < ats.size(); i++) {
        if (i > start) args += ", ";
        args += TypeName(ats[i]);
        size_t ai = i - start;
        if (ai < f.argNames.size() && !f.argNames[ai].empty()) {
            args += " ";
            args += f.argNames[ai];
        }
    }
    if (ats.empty()) args = "void";
    return rv + " " + (f.shortName.empty() ? f.name : f.shortName) + "(" + args + ")";
}

const PdbFunc* PdbInfo::FuncAt(u64 va) const {
    auto it = funcByVa_.find(va);
    return it == funcByVa_.end() ? nullptr : &funcs_[it->second];
}
const PdbGlobal* PdbInfo::GlobalAt(u64 va) const {
    for (auto& g : globals_) if (g.va == va) return &g;
    return nullptr;
}

// ----------------------------------------------------------------------------
// struct listesi (TypeInferer giydirmesi için DwarfStruct benzeri format)
// ----------------------------------------------------------------------------
std::vector<PdbInfo::StructOut> PdbInfo::Structs() const {
    std::vector<StructOut> out;
    std::set<std::string> seen;
    for (auto& kv : types_) {
        const PdbTypeRec& t = kv.second;
        if (t.leaf != 0x1504 && t.leaf != 0x1505 && t.leaf != 0x1506) continue;
        if (t.name.empty() || t.members.empty()) continue;
        if (!seen.insert(t.name).second) continue;
        StructOut so;
        so.name = t.name;
        so.size = t.size;
        // üye boyutu: tip kaydından ya da sonraki üye offset'inden
        for (size_t i = 0; i < t.members.size(); i++) {
            const PdbMember& m = t.members[i];
            if (m.attr == 0xFFFF || m.attr == 0xFFFE || m.attr == 0xFFFD) continue;
            StructOut::M om;
            om.name = m.name;
            om.offset = (u64)(m.off < 0 ? 0 : m.off);
            om.typeName = TypeName(m.tidx, 0);
            const PdbTypeRec* mt = Type(m.tidx);
            if (mt && mt->sizeKnown) om.size = (u32)mt->size;
            if (mt && mt->leaf == 0x1503) {   // dizi
                om.isArray = true;
                u64 es = 4;
                const PdbTypeRec* et = Type(mt->a);
                if (et && et->sizeKnown && et->size) es = et->size;
                else if (et && et->leaf == 0x1002) es = 8;
                else {
                    u32 elemIdx = mt->a;
                    if (elemIdx < 0x1000) {
                        switch (elemIdx & 0xFF) {
                        case 0x10: case 0x20: case 0x70: case 0x68: es = 1; break;
                        case 0x11: case 0x21: case 0x71: case 0x72: case 0x73: case 0x69: es = 2; break;
                        case 0x12: case 0x22: case 0x74: case 0x75: case 0x40: case 0x6a: es = 4; break;
                        case 0x13: case 0x23: case 0x76: case 0x77: case 0x41: case 0x6b: es = 8; break;
                        default: es = 4;
                        }
                    }
                }
                if (es && mt->size) om.arrayLen = mt->size / es;
                if (!om.size) om.size = (u32)mt->size;
            }
            // sonraki üyeye kadar boy
            if (!om.size) {
                for (size_t j = i + 1; j < t.members.size(); j++) {
                    if (t.members[j].attr == 0xFFFF || t.members[j].attr == 0xFFFE ||
                        t.members[j].attr == 0xFFFD || t.members[j].off < 0) continue;
                    u64 no = (u64)t.members[j].off;
                    if (no > om.offset) { om.size = (u32)(no - om.offset); }
                    break;
                }
            }
            so.members.push_back(std::move(om));
        }
        if (getenv("GODTIER_PDB_DEBUG"))
            std::printf("[PDB-STRUCT] %s: %zu uye\n", so.name.c_str(), so.members.size());
        if (!so.members.empty()) out.push_back(std::move(so));
    }
    return out;
}

} // namespace gt
