// ============================================================================
//  i4M GodTier Engine — core/types.h
//  Temel tamsayı tipleri ve ortak tanımlar (tek yerden).
// ============================================================================
#pragma once
#include <cstdint>
#include <cstddef>

namespace gt {

using u8  = uint8_t;   using u16 = uint16_t;
using u32 = uint32_t;  using u64 = uint64_t;
using i8  = int8_t;    using i16 = int16_t;
using i32 = int32_t;   using i64 = int64_t;

// Mimari tanımı (Capstone/Unicorn/Keystone üçlüsüne aynı anda verilir)
// v6: x86-64 (tam decompiler) + ARM64/AArch64 + ARM32 (disasm + analiz + xref)
enum class Arch { X86_32, X86_64, ARM64, ARM32, Unknown };

inline const char* ArchName(Arch a) {
    switch (a) {
        case Arch::X86_32: return "x86 (32-bit)";
        case Arch::X86_64: return "x86-64";
        case Arch::ARM64:  return "ARM64 (AArch64)";
        case Arch::ARM32:  return "ARM (32-bit)";
        default:           return "bilinmeyen";
    }
}

} // namespace gt
