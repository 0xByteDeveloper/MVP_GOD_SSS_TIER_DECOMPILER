// ============================================================================
//  i4M GodTier Engine — analysis/sigs.cpp
// ============================================================================
#include "analysis/sigs.h"
#include "core/log.h"
#include "core/util.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>

namespace gt {

// ----------------------------------------------------------------------------
// Desen kuralları — gerçek derlenmiş fonksiyon gövdeleri üzerinde çalışır
// ----------------------------------------------------------------------------
std::vector<SigMatch> SigEngine::RuleScan() {
    std::vector<SigMatch> out;
    for (auto& [fva, f] : az_.Functions()) {
        auto* ins = az_.InstructionsOf(fva);
        if (!ins || ins->empty()) continue;

        // 1) rep movs -> memcpy ( confidently 90)
        bool repMovs = false, repStos = false, bswap = false, rdtsc = false,
             cpuid = false, syscall = false;
        std::string movsDetail;
        for (auto& x : *ins) {
            std::string m = x.mnemonic;
            if (m.find("rep") != std::string::npos && m.find("movs") != std::string::npos) {
                repMovs = true;
                movsDetail = m;
            }
            if (m.find("rep") != std::string::npos && m.find("stos") != std::string::npos) {
                repStos = true;
                movsDetail = m;
            }
            if (m == "bswap") bswap = true;
            if (m == "rdtsc") rdtsc = true;
            if (m == "cpuid") cpuid = true;
            if (m == "syscall") syscall = true;
        }
        auto add = [&](const char* lib, const std::string& rule, int conf) {
            SigMatch s;
            s.funcVa = fva;
            s.funcName = f.name;
            s.libraryName = lib;
            s.rule = rule;
            s.confidence = conf;
            out.push_back(s);
        };
        if (repMovs) add("memcpy", "rep movs kalibi (" + movsDetail + ") — libc memcpy/inline kopya", 90);
        if (repStos) add("memset", "rep stos kalibi (" + movsDetail + ") — libc memset/sifir doldurma", 90);

        // 2) strlen kalibi: xor eax,eax + cmp byte ptr [..], 0 + geri dallanma
        {
            bool hasXorEax = false, hasByteCmp0 = false, hasBackJcc = false;
            for (size_t i = 0; i < ins->size(); i++) {
                auto& x = (*ins)[i];
                if (x.mnemonic == "xor" && x.opStr == "eax, eax") hasXorEax = true;
                if (x.mnemonic == "cmp" && x.opStr.find("byte ptr") != std::string::npos &&
                    (x.opStr.find(", 0") != std::string::npos))
                    hasByteCmp0 = true;
                if (x.isJcc && !x.isIndirect && x.target < x.addr) hasBackJcc = true;
            }
            if (hasXorEax && hasByteCmp0 && hasBackJcc && ins->size() < 32)
                add("strlen", "xor eax,eax + byte-dizi karsilastirma + geri donus dongusu", 70);
        }

        if (bswap) add("htonl/ntohl (bswap)", "bayt sirasi degisimi (ag bayti duzenleme)", 60);
        if (rdtsc) add("rdtsc_sarmalayici", "zam damgasi okuma — anti-analiz/benchmark", 50);
        if (cpuid) add("cpuid_sarmalayici", "islemci kimligi — VM/sanal makine tespiti", 50);
        if (syscall) add("syscall_sarmalayici", "dogrudan sistem cagrisi (statik libc)", 60);
    }
    return out;
}

// ----------------------------------------------------------------------------
// Masked pattern: ilk n baytı komut komut çöz, call/jmp rel32 ve
// [rip+disp32] son 4 baytını jokerle (FLIRT'in yeniden-konumlanabilir
// bayt maskeleme fikrinin sade uygulaması)
// ----------------------------------------------------------------------------
std::string SigEngine::MaskInsns(u64 va, size_t n) const {
    auto& img = az_.Image();
    auto& eng = az_.Engine();
    std::string hex;
    u64 cur = va;
    u8 buf[32];
    size_t produced = 0;
    std::set<u64> done;
    while (produced < n) {
        if (!img.ReadBytes(cur, buf, 32)) break;
        Ins x;
        if (!eng.DisasmOne(buf, 32, cur, x) || x.len == 0) {
            // çözülemeyen bayt: olduğu gibi (1 bayt)
            char tmp[4];
            snprintf(tmp, sizeof tmp, "%02x", buf[0]);
            hex += tmp;
            produced++; cur++;
            continue;
        }
        // maske: rel32 (E8/E9) veya rip-göreli disp32
        bool maskTail4 = false;
        if (!x.isIndirect && (x.isCall || x.isJmp || x.isJcc)) maskTail4 = true;
        if (x.opStr.find("[rip") != std::string::npos) maskTail4 = true;
        size_t take = std::min<size_t>(x.len, n - produced);
        for (size_t i = 0; i < take; i++) {
            bool masked = maskTail4 && x.len >= 5 && i >= (size_t)(x.len - 4);
            if (masked) { hex += "xx"; continue; }
            char tmp[4];
            snprintf(tmp, sizeof tmp, "%02x", x.bytes[i]);
            hex += tmp;
        }
        produced += take;
        cur += x.len;
        (void)done;
    }
    return hex;
}

std::string SigEngine::MaskedPattern(u64 va, size_t n) const {
    return MaskInsns(va, n);
}

// ----------------------------------------------------------------------------
// .gsig export/import
// ----------------------------------------------------------------------------
bool SigEngine::ExportGsig(const std::string& path, size_t patternBytes) {
    std::ofstream f(path);
    if (!f) return false;
    f << "# i4M-GodTier imza veritabani v1 (FLIRT-esintili masked pattern)\n";
    f << "# format: <isim> <bayt-sayisi> <maskeli-hex>  (xx = joker)\n";
    size_t n = 0;
    for (auto& [fva, fn] : az_.Functions()) {
        // yalnız GERÇEK isimli fonksiyonlar: sub_/FUN_/entry_point değil,
        // PLT/import değil (adında '@' yok)
        if (!fn.fromSymbol) continue;
        if (fn.name.empty() || fn.name.rfind("sub_", 0) == 0 ||
            fn.name.rfind("FUN_", 0) == 0 || fn.name == "entry_point" ||
            fn.name == "main" || fn.name.find('@') != std::string::npos)
            continue;
        if (fn.insCount < 3) continue;   // çok kısa: çakışma riski
        std::string pat = MaskInsns(fva, patternBytes);
        if (pat.size() < 32) continue;
        f << fn.name << " " << pat.size() / 2 << " " << pat << "\n";
        n++;
    }
    return n > 0;
}

SigEngine::ImportResult SigEngine::ImportGsig(const std::string& path) {
    ImportResult res;
    std::ifstream f(path);
    if (!f) return res;
    struct Entry { std::string name; size_t nbytes; std::string pat; };
    std::vector<Entry> entries;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream is(line);
        Entry e;
        is >> e.name >> e.nbytes >> e.pat;
        if (!e.name.empty() && e.nbytes >= 16 && e.pat.size() >= 32)
            entries.push_back(e);
    }
    if (entries.empty()) return res;

    for (auto& [fva, fn] : az_.Functions()) {
        // yalnız adsız/sub_/FUN_ fonksiyonları yeniden adlandır
        bool renameable = fn.name.empty() || fn.name.rfind("sub_", 0) == 0 ||
                          fn.name.rfind("FUN_", 0) == 0;
        if (!renameable) continue;
        res.compared++;
        std::string pat = MaskInsns(fva, 64);   // uzun kesit al, girişle öneşle
        for (auto& e : entries) {
            if (e.pat.size() > pat.size()) continue;
            if (pat.compare(0, e.pat.size(), e.pat) == 0) {
                res.matched++;
                az_.EnsureFunction(fva, e.name);
                res.renames.push_back({fva, e.name});
                res.renamed++;
                break;
            }
        }
    }
    return res;
}

} // namespace gt

// ----------------------------------------------------------------------------
// v6: hazır havuz altyapısı + lumina push
// ----------------------------------------------------------------------------
#include <filesystem>
#include <map>

namespace gt {

size_t CountGsigEntries(const std::string& path) {
    std::ifstream f(path);
    if (!f) return 0;
    size_t n = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream is(line);
        std::string name, nb, pat;
        if (is >> name >> nb >> pat && !name.empty() && !pat.empty()) n++;
    }
    return n;
}

std::vector<SigPoolResult> ApplySigPools(Analyzer& az, const std::string& dir) {
    std::vector<SigPoolResult> out;
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) return out;
    std::vector<std::string> files;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        if (!e.is_regular_file()) continue;
        if (e.path().extension() == ".gsig") files.push_back(e.path().string());
    }
    std::sort(files.begin(), files.end());
    for (auto& f : files) {
        SigEngine se(az);
        auto r = se.ImportGsig(f);
        SigPoolResult pr;
        pr.path = f;
        pr.matched = r.matched;
        pr.renamed = r.renamed;
        out.push_back(pr);
    }
    return out;
}

size_t SigEngine::PushToPool(const std::string& path, size_t patternBytes) {
    // mevcut havuz: isim -> (bayt, desen)
    std::map<std::string, std::pair<size_t, std::string>> pool;
    {
        std::ifstream f(path);
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::istringstream is(line);
            std::string name, nb, pat;
            if (is >> name >> nb >> pat && !name.empty() && !pat.empty())
                pool[name] = {atoll(nb.c_str()), pat};
        }
    }
    size_t added = 0;
    for (auto& [fva, fn] : az_.Functions()) {
        if (!fn.fromSymbol) continue;
        if (fn.name.empty() || fn.name.rfind("sub_", 0) == 0 ||
            fn.name.rfind("FUN_", 0) == 0 || fn.name == "entry_point" ||
            fn.name == "main" || fn.name.find('@') != std::string::npos)
            continue;
        if (fn.insCount < 3) continue;
        std::string pat = MaskInsns(fva, patternBytes);
        if (pat.size() < 32) continue;
        auto it = pool.find(fn.name);
        if (it != pool.end() && it->second.second == pat) continue;  // aynı kanıt
        if (it == pool.end()) added++;
        pool[fn.name] = {pat.size() / 2, pat};
    }
    std::ofstream f(path, std::ios::app);   // yoksa oluştur
    f.close();
    std::ofstream f2(path, std::ios::trunc);
    if (!f2) return 0;
    f2 << "# i4M-GodTier lumina havuzu v1 (birikimli isim bilgeliği)\n";
    f2 << "# format: <isim> <bayt-sayisi> <maskeli-hex>  (xx = joker)\n";
    for (auto& [name, v] : pool)
        f2 << name << " " << v.first << " " << v.second << "\n";
    return added;
}

} // namespace gt
