// ============================================================================
//  i4M GodTier Engine — asm/assembler.h
//  Keystone tabanlı GERÇEK assembler (Capstone'un kardeşi) — i4M'nin elle
//  yazılmış mini assembler'ının yerine geçer. Artık "mov rax, imm64" gibi
//  her şey gerçek motorla kodlanır.
//  Ayrıca: patch motoru + undo/redo (i4M UndoSys mirası) + section ekleme
//  destekli kaydetme üst katmanda (ui) yapılır.
// ============================================================================
#pragma once
#include "core/types.h"
#include <keystone/keystone.h>
#include <string>
#include <vector>
#include <functional>

namespace gt {

class Assembler {
public:
    Assembler();
    ~Assembler();
    Assembler(const Assembler&) = delete;
    Assembler& operator=(const Assembler&) = delete;

    bool Init(Arch arch);
    bool Ok() const { return ks_ != nullptr; }

    // "mov rax, 0x1337; ret" -> baytlar. Sonucun disassembly ile
    // doğrulanması (round-trip) üst katmanda yapılabilir.
    bool Assemble(const std::string& asmText, u64 va, std::vector<u8>& outBytes);

    // Sembol çözümü: "kernel32.CreateFileA" gibi operandları
    // adresine çevirmek için geri çağrı (analyzer'dan beslenir)
    void SetSymbolResolver(std::function<u64(const std::string&)> fn) { resolver_ = std::move(fn); }

private:
    ks_engine* ks_ = nullptr;
    std::function<u64(const std::string&)> resolver_;
};

// ----------------------------------------------------------------------------
// Patch defteri: (adres, eski baytlar, yeni baytlar) — sınırsız undo/redo
// ----------------------------------------------------------------------------
struct PatchEntry {
    u64 va = 0;
    std::vector<u8> before, after;
};

class PatchBook {
public:
    bool Apply(class MappedImage& img, u64 va, const std::vector<u8>& bytes);
    bool Undo(MappedImage& img);
    bool Redo(MappedImage& img);
    size_t UndoCount() const { return done_.size(); }
    size_t RedoCount() const { return undone_.size(); }
    const std::vector<PatchEntry>& Done() const { return done_; }
    void Clear() { done_.clear(); undone_.clear(); }

private:
    std::vector<PatchEntry> done_;
    std::vector<PatchEntry> undone_;
};

} // namespace gt
