// ============================================================================
//  i4M GodTier Engine — format/image.h
//  MappedImage: dosyayı "process belleği gibi" sanal görünüme çevirir.
//  i4MConsoleLoader'daki MemImage sınıfının cross-platform GOD hali:
//  - raw -> virtual map (PE section'larla / ELF segmentlerle)
//  - VA tabanlı güvenli read/write
//  - shadow IAT bölgesi (emülatör için)
// ============================================================================
#pragma once
#include "format/binary.h"
#include "format/pe.h"
#include "format/elf.h"
#include "core/util.h"
#include <cstring>

namespace gt {

class MappedImage {
public:
    // Dosyayı belleğe map eder (kod ÇALIŞTIRILMAZ — yalnızca görüntü kurulumu)
    bool LoadFromBinary(const Binary& bin);

    // Ham shellcode'yu (PE/ELF olmayan) verilen base'e yerleştir
    bool LoadRaw(std::vector<u8> bytes, u64 base);

    u64  Base() const { return base_; }
    void SetBase(u64 b) { base_ = b; }  // (reloc uygulanmis goruntuler icin)
    u64  Size() const { return data_.size(); }
    bool InRange(u64 va) const { return va >= base_ && va < base_ + data_.size(); }

    u8   Read8(u64 va) const;
    u16  Read16(u64 va) const;
    u32  Read32(u64 va) const;
    u64  Read64(u64 va) const;
    bool ReadBytes(u64 va, u8* out, size_t n) const;

    bool Write8(u64 va, u8 v);
    bool WriteBytes(u64 va, const u8* p, size_t n);

    // Patch edilmiş görüntüyü tekrar diske yazılabilir hale çevirme desteği:
    // VA -> dosya offset çevirimi binary üzerinden
    const Binary* GetBinary() const { return bin_; }

    std::vector<u8>& Data() { return data_; }
    const std::vector<u8>& Data() const { return data_; }

private:
    u64 base_ = 0;
    std::vector<u8> data_;
    const Binary* bin_ = nullptr;
};

// Binary::Open fabrikası (PE/ELF koklar) — binary.h'de beyan edildi
inline Binary* Binary::Open(const std::string& path) {
    auto bytes = ReadFileBytes(path);
    if (bytes.size() < 4) return nullptr;
    if (bytes[0] == 'M' && bytes[1] == 'Z') {
        auto* pe = new PE();
        if (pe->Load(path)) return pe;
        delete pe;
        return nullptr;
    }
    if (memcmp(bytes.data(), "\x7f" "ELF", 4) == 0) {
        auto* elf = new ELF();
        if (elf->Load(path)) return elf;
        delete elf;
        return nullptr;
    }
    return nullptr; // ham shellcode: ayrı yol (ui'de doğrudan image kurulur)
}

} // namespace gt
