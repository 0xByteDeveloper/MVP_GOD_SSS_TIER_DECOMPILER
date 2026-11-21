// ============================================================================
//  i4M GodTier Engine — disasm/engine.h
//  Capstone sarmalayıcı. Capstone = OSS disasm şampiyonu (xlsx'te Motor 10/10).
//  Intel sözdizimi + detay modu (operand/memory analizi için zorunlu).
// ============================================================================
#pragma once
#include "core/types.h"
#include <capstone/capstone.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace gt {

// Tek satır disassembly sonucu (i4M DisLine'inin GOD hali)
struct Ins {
    u64 addr = 0;
    u8  bytes[16] = {};
    u8  len = 0;
    std::string mnemonic;
    std::string opStr;
    // analiz bayrakları (analyzer doldurur)
    bool isCall = false, isJmp = false, isJcc = false, isRet = false;
    bool isIndirect = false;      // hedef register/bellek üzerinden
    u64  target = 0;              // doğrudan hedef (varsa)
    bool hasMemRef = false;       // bellek operandı var
    u64  memRef = 0;              // çözülebilirse sabit bellek adresi
    std::string comment;          // "kernel32.CreateFileA" gibi satır üstü not

    bool valid() const { return len != 0; }
};

class DisasmEngine {
public:
    DisasmEngine();
    ~DisasmEngine();
    DisasmEngine(const DisasmEngine&) = delete;
    DisasmEngine& operator=(const DisasmEngine&) = delete;

    bool Init(Arch arch);
    bool Ok() const { return handle_ != 0; }
    Arch GetArch() const { return arch_; }

    // Bellekten N satır disassemble et (linear sweep)
    std::vector<Ins> Disasm(const u8* code, size_t size, u64 va, size_t maxCount = 1);

    // Tek komut
    bool DisasmOne(const u8* code, size_t size, u64 va, Ins& out);

    // Callback tabanlı bellek erişimi (MappedImage'e bağlanır)
    void SetMemoryReader(std::function<bool(u64, u8*, size_t)> rd) { reader_ = std::move(rd); }
    std::vector<Ins> DisasmRange(u64 va, size_t maxCount);

private:
    csh handle_ = 0;
    Arch arch_ = Arch::Unknown;
    std::function<bool(u64, u8*, size_t)> reader_;
};

} // namespace gt
