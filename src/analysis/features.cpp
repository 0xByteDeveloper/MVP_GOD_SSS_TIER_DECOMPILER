// ============================================================================
//  i4M GodTier Engine — analysis/features.cpp
// ============================================================================
#include "analysis/features.h"
#include "core/util.h"
#include "core/log.h"
#include <algorithm>
#include <cstring>

namespace gt {

// ============================================================================
// imphash — Mandiant (pefile) algoritması:
//   dll.şey1,dll.şey2,... (küçük harf, sıralı) -> MD5
//   ordinal: "dll.ord#N", isim uzantısız ("kernel32.createfilea" değil;
//   pefile ismi OLDUĞU GİBİ (uzantısız) lower-case kullanır)
// ============================================================================
std::string FeatureAnalyzer::Imphash() const {
    // pefile (Mandiant) algoritmasıyla birebir:
    //  - dll adı küçük harf + uzantı soyulur (.dll/.sys/.ocx)
    //  - "dll.func" küçük harf, SIRALAMA YOK (import sırası anlamlı)
    //  - ordinal: "ord%d" (pefile ordLookup kullanır; biz sade tutarız)
    std::vector<std::string> parts;
    for (auto& dll : bin_.Imports()) {
        std::string d = ToLower(dll.name);
        size_t dot = d.rfind('.');
        if (dot != std::string::npos) {
            std::string ext = d.substr(dot + 1);
            if (ext == "dll" || ext == "sys" || ext == "ocx")
                d = d.substr(0, dot);
        }
        for (auto& fn : dll.funcs) {
            std::string f = fn.name.empty()
                ? ("ord" + std::to_string(fn.ordinal))
                : ToLower(fn.name);
            parts.push_back(d + "." + f);
        }
    }
    std::string joined;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i) joined += ",";
        joined += parts[i];
    }
    return MD5Hex((const u8*)joined.data(), joined.size());
}

// ============================================================================
// Entropi
// ============================================================================
std::vector<EntropyRow> FeatureAnalyzer::SectionEntropies() const {
    std::vector<EntropyRow> out;
    for (auto& s : bin_.Sections()) {
        if (!s.rawSize && !s.vsize) continue;
        EntropyRow r;
        r.section = s.name;
        // ham dosya verisini kullan (map edilmiş görüntü değil)
        const auto& raw = bin_.Raw();
        u64 off = s.rawOffset, sz = s.rawSize;
        if (off + sz > raw.size()) sz = off < raw.size() ? raw.size() - off : 0;
        r.entropy = sz ? Entropy(&raw[(size_t)off], (size_t)sz) : 0.0;
        r.percent = r.entropy / 8.0 * 100.0;
        if (r.entropy < 1.0) r.verdict = "boş/düzenli";
        else if (r.entropy < 6.0) r.verdict = "normal (kod/veri)";
        else if (r.entropy < 7.2) r.verdict = "yüksek (sıkışmış olabilir)";
        else r.verdict = "ÇOK YÜKSEK (şifreli/packed?)";
        out.push_back(r);
    }
    return out;
}

double FeatureAnalyzer::OverallEntropy() const {
    const auto& raw = bin_.Raw();
    return raw.empty() ? 0.0 : Entropy(raw.data(), raw.size());
}

// ============================================================================
// Packer sezgileri (Detect It Easy tarzı kurallar)
// ============================================================================
std::vector<PackerHint> FeatureAnalyzer::PackerHeuristics() const {
    std::vector<PackerHint> hints;
    auto add = [&](const std::string& r, int w) { hints.push_back({r, w}); };

    // 1) klasik packer section adları
    static const char* packerSecs[] = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata",
        ".nsp0", ".nsp1", ".nsp2", ".themida", ".taz", ".winsc", ".petite",
        "pec1", "pec2", "pec3", ".packed", "PEBundle", ".MPRESS1", ".MPRESS2",
        ".enigma1", ".enigma2", "vmp0", "vmp1", "vmp2", ".svkp"};
    for (auto& s : bin_.Sections())
        for (auto* ps : packerSecs)
            if (s.name == ps)
                add("Bölüm adı '" + s.name + "' klasik packer imzası", 3);

    // 2) entry point son bölümde mi?
    if (!bin_.Sections().empty()) {
        auto& last = bin_.Sections().back();
        u64 ep = bin_.EntryPoint();
        if (ep >= last.va && ep < last.va + last.vsize && last.executable)
            add("Entry point son bölümde (" + last.name + ") — packer davranışı", 2);
    }

    // 3) import sayısı çok az mı? (packer IAT'ı gizler)
    size_t totalImports = 0;
    for (auto& d : bin_.Imports()) totalImports += d.funcs.size();
    if (totalImports && totalImports <= 5 && bin_.Is64() /*yaklaşık filtre*/)
        add("Çok az import (" + std::to_string(totalImports) + ") — gizlenmiş IAT", 2);

    // 4) yazılabilir+çalıştırılabilir bölüm
    for (auto& s : bin_.Sections())
        if (s.executable && s.writable)
            add("Bölüm '" + s.name + "' hem W hem X — self-modifying/packer şüphesi", 2);

    // 5) yüksek entropili çalıştırılabilir bölüm
    for (auto& r : SectionEntropies())
        if (r.entropy >= 7.2)
            add("Bölüm '" + r.section + "' entropisi " + std::to_string(r.entropy).substr(0, 5), 2);

    // 6) section sanal boyut >> ham boyut
    for (auto& s : bin_.Sections())
        if (s.vsize > s.rawSize * 4 && s.vsize > 0x1000)
            add("Bölüm '" + s.name + "' vsize >> rawsize (açılımda şişiyor)", 1);

    return hints;
}

int FeatureAnalyzer::PackerRisk() const {
    int w = 0;
    for (auto& h : PackerHeuristics()) w += h.weight;
    return w;
}

// ============================================================================
// findcrypt — kripto sabiti taraması (findcrypt/yara dersi)
// ============================================================================
std::vector<CryptoHit> FeatureAnalyzer::FindCryptoConstants() const {
    std::vector<CryptoHit> hits;
    const auto& raw = bin_.Raw();

    struct Sig { const char* name; const u8* p; size_t n; };
    // AES S-box ilk 32 baytı
    static const u8 AES_SBOX[32] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0};
    // AES inverse S-box ilk 16
    static const u8 AES_ISBOX[16] = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb};
    // MD5 init (little-endian sabitler: 0x67452301 0xefcdab89 0x98badcfe 0x10325476)
    static const u8 MD5_INIT[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    // MD5 T tablosu ilk 16 bayt (0xd76aa478 LE)
    static const u8 MD5_T[8] = {0x78,0xa4,0x6a,0xd7,0x56,0xb7,0xc7,0xe8};
    // SHA-1 init (0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0)
    static const u8 SHA1_INIT[20] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,
        0x76,0x54,0x32,0x10,0xf0,0xe1,0xd2,0xc3};
    // SHA-256 K[0..3] (0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5)
    static const u8 SHA256_K[16] = {
        0x42,0x8a,0x2f,0x98,0x71,0x37,0x44,0x91,0xb5,0xc0,0xfb,0xcf,0xe9,0xb5,0xdb,0xa5};
    // CRC32 polynomial table başlangıcı (0x00000000, 0x77073096, ...)
    static const u8 CRC32_T[8] = {0x96,0x30,0x07,0x77,0x2b,0x06,0x2a,0xed};

    Sig sigs[] = {
        {"AES S-box", AES_SBOX, 32}, {"AES inverse S-box", AES_ISBOX, 16},
        {"MD5 init (LE)", MD5_INIT, 16}, {"MD5 T-table", MD5_T, 8},
        {"SHA-1 init (LE)", SHA1_INIT, 20}, {"SHA-256 K[0..3]", SHA256_K, 16},
        {"CRC32 tablosu", CRC32_T, 8},
    };

    if (raw.size() < 64) return hits;
    for (auto& sig : sigs) {
        for (size_t i = 0; i + sig.n <= raw.size(); i++) {
            if (memcmp(&raw[i], sig.p, sig.n) == 0) {
                CryptoHit h;
                u64 va = bin_.RawToVa(i);
                h.va = (va != (u64)-1) ? va : i;
                h.algo = sig.name;
                for (auto& s : bin_.Sections())
                    if (i >= s.rawOffset && i < s.rawOffset + s.rawSize) h.section = s.name;
                hits.push_back(h);
                i += sig.n - 1; // üst üste binmeyi atla
            }
        }
    }
    return hits;
}

// ============================================================================
// capa-lite: import tablosundan yetenek çıkarımı
// ============================================================================
std::vector<Capability> FeatureAnalyzer::Capabilities() const {
    // kurallar: (isim, ağırlık, api alt dizeleri)
    struct Rule { const char* name; int w; const char* apis[6]; };
    static const Rule rules[] = {
        {"Dosya sistemi erişimi", 2, {"CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile", nullptr}},
        {"Kayıt defteri erişimi", 2, {"RegOpenKey", "RegSetValue", "RegCreateKey", "RegDelete", nullptr, nullptr}},
        {"Ağ/İnternet erişimi", 3, {"InternetOpen", "URLDownload", "WinHttpOpen", "WSAStartup", "socket", "connect"}},
        {"Süreç oluşturma/komut çalıştırma", 3, {"CreateProcess", "WinExec", "ShellExecute", "system", nullptr, nullptr}},
        {"DLL enjeksiyonu/uzaktan kod", 4, {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx", nullptr, nullptr}},
        {"Hizmet yönetimi", 2, {"OpenSCManager", "CreateService", "StartService", nullptr, nullptr, nullptr}},
        {"Kriptografi (Windows CryptoAPI)", 2, {"CryptAcquireContext", "CryptEncrypt", "CryptCreateHash", "BCryptOpen", nullptr, nullptr}},
        {"Anti-analiz/hata ayıklama", 3, {"IsDebuggerPresent", "CheckRemoteDebugger", "OutputDebugString", "NtQueryInformation", nullptr, nullptr}},
        {"Ekran/klavye izleme", 4, {"GetAsyncKeyState", "GetKeyState", "keybd_event", "BitBlt", "GetDC", nullptr}},
        {"Kendi kendini silme/gizleme", 3, {"SetFileAttributes", "GetModuleFileName", nullptr, nullptr, nullptr, nullptr}},
        {"Kalıcılık (autorun)", 3, {"RegSetValue", "CopyFile", "SetWindowsHookEx", nullptr, nullptr, nullptr}},
    };

    // tüm import isimlerini düz listeye dök
    std::vector<std::string> apis;
    for (auto& d : bin_.Imports())
        for (auto& f : d.funcs) apis.push_back(ToLower(f.name));

    std::vector<Capability> caps;
    for (auto& rule : rules) {
        std::string evidence;
        int hits = 0;
        for (auto* a : rule.apis) {
            if (!a) break;
            for (auto& api : apis) {
                if (api.find(ToLower(a)) != std::string::npos) {
                    if (!evidence.empty()) evidence += ", ";
                    evidence += api;
                    hits++;
                    break;
                }
            }
        }
        if (hits) caps.push_back({rule.name, evidence, rule.w * hits});
    }
    std::sort(caps.begin(), caps.end(),
              [](const Capability& a, const Capability& b) { return a.weight > b.weight; });
    return caps;
}

} // namespace gt
