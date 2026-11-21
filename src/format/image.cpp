// ============================================================================
//  i4M GodTier Engine — format/image.cpp
// ============================================================================
#include "format/image.h"
#include "core/log.h"
#include <cstring>
#include <algorithm>

namespace gt {

bool MappedImage::LoadFromBinary(const Binary& bin) {
    bin_ = &bin;
    base_ = bin.ImageBase();
    data_.assign((size_t)bin.ImageSize(), 0);

    // PE: header + section'ları virtual konumlarına kopyala
    // ELF: PT_LOAD segmentlerini (veya section'larını) kopyala
    u64 rawHdr = 0;
    for (auto& s : bin.Sections()) if (s.rawOffset) rawHdr = std::max(rawHdr, s.rawOffset);
    if (rawHdr == 0) rawHdr = std::min<u64>(bin.RawSize(), 0x1000);

    // header bloğu (PE: SizeOfHeaders; ELF: segment offset'ine kadar)
    u64 hdrSize = 0x1000;
    // PE section'ları raw offset 0'dan başlayabilir; header'ı ilk section'a kadar al
    for (auto& s : bin.Sections())
        if (s.rawOffset && s.rawOffset < hdrSize && s.rawOffset > 0x40) hdrSize = s.rawOffset;
    hdrSize = std::min(hdrSize, (u64)0x400);
    if (bin.RawSize() < hdrSize) hdrSize = bin.RawSize();

    bool pe = false;
    if (bin.RawSize() >= 2 && bin.Raw()[0] == 'M' && bin.Raw()[1] == 'Z') pe = true;

    if (pe) {
        // DOS+NT header'ları başa kopyala
        std::memcpy(data_.data(), bin.Raw().data(), (size_t)hdrSize);
        for (auto& s : bin.Sections()) {
            u64 off = s.va - base_;
            if (off >= data_.size()) continue;
            size_t copy = (size_t)std::min<u64>(s.rawSize, data_.size() - off);
            if (s.rawOffset + copy <= bin.RawSize() && s.rawOffset)
                std::memcpy(&data_[(size_t)off], &bin.Raw()[(size_t)s.rawOffset], copy);
            else if (s.rawOffset == 0 && s.rawSize == 0) { /* .bss: sıfır kalır */ }
        }
    } else {
        // ELF: section bazlı kopya (va'sı olan her section)
        for (auto& s : bin.Sections()) {
            if (!s.va || !s.rawSize) continue;
            u64 off = s.va - base_;
            if (off >= data_.size()) continue;
            size_t copy = (size_t)std::min<u64>(s.rawSize, data_.size() - off);
            if (s.rawOffset + copy <= bin.RawSize())
                std::memcpy(&data_[(size_t)off], &bin.Raw()[(size_t)s.rawOffset], copy);
        }
    }
    return true;
}

bool MappedImage::LoadRaw(std::vector<u8> bytes, u64 base) {
    base_ = base;
    data_ = std::move(bytes);
    bin_ = nullptr;
    return true;
}

u8  MappedImage::Read8(u64 va) const  { return InRange(va) ? data_[(size_t)(va - base_)] : 0; }
u16 MappedImage::Read16(u64 va) const {
    return InRange(va + 1) ? u16(data_[(size_t)(va - base_)] | (data_[(size_t)(va - base_ + 1)] << 8)) : 0;
}
u32 MappedImage::Read32(u64 va) const {
    if (!InRange(va + 3)) return 0;
    size_t o = (size_t)(va - base_);
    return u32(data_[o] | (data_[o+1] << 8) | (data_[o+2] << 16) | (u32(data_[o+3]) << 24));
}
u64 MappedImage::Read64(u64 va) const {
    if (!InRange(va + 7)) return 0;
    size_t o = (size_t)(va - base_);
    u64 v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | data_[o + i];
    return v;
}
bool MappedImage::ReadBytes(u64 va, u8* out, size_t n) const {
    if (!out || !InRange(va) || !InRange(va + n - 1)) return false;
    std::memcpy(out, &data_[(size_t)(va - base_)], n);
    return true;
}
bool MappedImage::Write8(u64 va, u8 v) {
    if (!InRange(va)) return false;
    data_[(size_t)(va - base_)] = v;
    return true;
}
bool MappedImage::WriteBytes(u64 va, const u8* p, size_t n) {
    if (!p || !InRange(va) || !InRange(va + n - 1)) return false;
    std::memcpy(&data_[(size_t)(va - base_)], p, n);
    return true;
}

} // namespace gt
