// ============================================================================
//  i4M GodTier Engine — asm/assembler.cpp
// ============================================================================
#include "asm/assembler.h"
#include "format/image.h"
#include "core/log.h"
#include "core/util.h"

namespace gt {

Assembler::Assembler() = default;
Assembler::~Assembler() { if (ks_) ks_close(ks_); }

bool Assembler::Init(Arch arch) {
    if (ks_) { ks_close(ks_); ks_ = nullptr; }
    ks_mode mode = (arch == Arch::X86_64) ? KS_MODE_64 : KS_MODE_32;
    if (ks_open(KS_ARCH_X86, mode, &ks_) != KS_ERR_OK) {
        LogErr("Keystone açılamadı");
        return false;
    }
    return true;
}

bool Assembler::Assemble(const std::string& asmText, u64 va, std::vector<u8>& outBytes) {
    if (!ks_) return false;
    std::string text = asmText;

    // Sembol çözümü: "call kernel32.ExitProcess" gibi operandlarda
    // bilinen sembolleri 0x adresine çevir (Keystone sembol bilmez)
    if (resolver_) {
        auto replaceAll = [&](const std::string& from, const std::string& to) {
            size_t pos = 0;
            while ((pos = text.find(from, pos)) != std::string::npos) {
                // kelime sınırı kontrolü kabaca
                text.replace(pos, from.size(), to);
                pos += to.size();
            }
        };
        // bilinen sembolleri tara: resolver'a aday parçaları sor
        // (kaba tarama: tüm 'identifier' benzeri parçaları dene)
        std::string ident;
        for (size_t i = 0; i <= text.size(); i++) {
            char c = (i < text.size()) ? text[i] : ' ';
            bool isIdentChar = isalnum((unsigned char)c) || c == '_' || c == '.';
            if (isIdentChar) ident += c;
            else if (!ident.empty()) {
                u64 addr = resolver_(ident);
                if (addr) replaceAll(ident, "0x" + ToHex(addr));
                ident.clear();
            }
        }
    }

    unsigned char* enc = nullptr;
    size_t sz = 0, cnt = 0;
    if (ks_asm(ks_, text.c_str(), va, &enc, &sz, &cnt) != KS_ERR_OK) {
        LogErr("Keystone hatası: %s (satır %zu)", ks_strerror(ks_errno(ks_)), cnt);
        return false;
    }
    outBytes.assign(enc, enc + sz);
    ks_free(enc);
    return !outBytes.empty();
}

// ----------------------------------------------------------------------------
// PatchBook
// ----------------------------------------------------------------------------
bool PatchBook::Apply(MappedImage& img, u64 va, const std::vector<u8>& bytes) {
    PatchEntry e;
    e.va = va;
    e.after = bytes;
    e.before.resize(bytes.size());
    if (!img.ReadBytes(va, e.before.data(), bytes.size())) {
        LogErr("Patch okunamadı: VA 0x%llx görüntü dışı", (unsigned long long)va);
        return false;
    }
    if (!img.WriteBytes(va, bytes.data(), bytes.size())) {
        LogErr("Patch yazılamadı: VA 0x%llx", (unsigned long long)va);
        return false;
    }
    done_.push_back(e);
    undone_.clear();
    LogOk("Patch: 0x%llx  (%zu bayt)  eski: %s", (unsigned long long)va, bytes.size(),
          ToHexBytes(e.before.data(), std::min<size_t>(e.before.size(), 8)).c_str());
    return true;
}

bool PatchBook::Undo(MappedImage& img) {
    if (done_.empty()) return false;
    PatchEntry e = done_.back();
    done_.pop_back();
    img.WriteBytes(e.va, e.before.data(), e.before.size());
    undone_.push_back(e);
    LogInfo("Undo: 0x%llx geri alındı", (unsigned long long)e.va);
    return true;
}

bool PatchBook::Redo(MappedImage& img) {
    if (undone_.empty()) return false;
    PatchEntry e = undone_.back();
    undone_.pop_back();
    img.WriteBytes(e.va, e.after.data(), e.after.size());
    done_.push_back(e);
    LogInfo("Redo: 0x%llx yeniden uygulandı", (unsigned long long)e.va);
    return true;
}

} // namespace gt
