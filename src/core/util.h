// ============================================================================
//  i4M GodTier Engine — core/util.h
//  Hex/string/dosya yardımcıları + Shannon entropisi + MD5 (imphash için).
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace gt {

std::string ToHex(uint64_t v, int width = 0);
std::string ToHexBytes(const uint8_t* p, size_t n);
std::string ToLower(std::string s);
std::string Trim(const std::string& s);
bool         StartsWith(const std::string& s, const std::string& pre);

std::vector<uint8_t> ReadFileBytes(const std::string& path);
bool                 WriteFileBytes(const std::string& path, const std::vector<uint8_t>& data);
bool                 FileExists(const std::string& path);

// Shannon entropisi: 0.0 (düzenli) .. 8.0 (rastgele/sıkıştırılmış)
double Entropy(const uint8_t* p, size_t n);

// MD5 özeti (imphash bunun üzerine kuruludur) — 16 ham bayt döner
std::vector<uint8_t> MD5(const uint8_t* p, size_t n);
std::string MD5Hex(const uint8_t* p, size_t n);

// Basit C++ isim demangling (Itanium temel kalıpları + MSVC tespiti)
std::string Demangle(const std::string& mangled);

// v6: script/eval aritmetik ifadesi çözücü — özyinelemeli iniş:
//   + - * / % << >> & | ^ ( ) unary- ; 0x hex + ondalık
//   "(0x10 + 5) * 3" -> 75. ok=false: çözülemedi.
int64_t EvalArith(const std::string& expr, bool* ok = nullptr);

} // namespace gt
