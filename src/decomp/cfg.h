// ============================================================================
//  i4M GodTier Engine — decomp/cfg.h
//  Control Flow Graph: basic block'lar + kenarlar + döngü tespiti.
//  Ghidra decompiler'ının "structuring" adımının hafifletilmiş hali.
// ============================================================================
#pragma once
#include "disasm/engine.h"
#include "disasm/analyzer.h"
#include <vector>
#include <set>
#include <map>

namespace gt {

enum class EdgeType : u8 { Fallthrough, Branch, Backedge };

struct BasicBlock {
    u64 start = 0;                   // ilk komut adresi
    u64 end = 0;                     // son komut ADRESİ (bitiş = end+len)
    std::vector<size_t> insIdx;      // fonksiyon komut listesine indeks
    std::vector<std::pair<u64, EdgeType>> succ;  // (hedef, tip)
    std::vector<u64> pred;
    bool endsWithRet = false;
    bool endsWithJmp = false;
};

struct LoopInfo {
    u64 head = 0;        // döngü başı (backedge hedefi)
    u64 latch = 0;       // backedge kaynağı
    bool isWhile = true; // false: do-while (head'e dallanan koşullu olmayan akış)
};

// Jump-table (switch) çözümü sonucu
struct SwitchInfo {
    u64 blockVa = 0;         // dolaylı jmp ile biten blok
    u64 tableVa = 0;         // tablo adresi (.rodata)
    u32 entrySize = 4;       // 4 (PIC rel32) veya 8 (mutlak qword)
    u32 nCases = 0;          // tablo girdisi sayısı
    std::vector<u64> targets;   // case i -> hedef VA
    u64 defaultTarget = 0;   // varsayılan hedef (0 = bilinmiyor)
    std::string indexReg;    // indeks register'ı (rax gibi)
    bool isPic = true;       // true: hedef = tablo + rel32
};

class CFG {
public:
    // Fonksiyon komutlarından CFG kurar (extraLeaders: jump-table hedefleri)
    bool Build(const std::vector<Ins>& ins, const std::set<u64>& extraLeaders = {});

    // v5: SÜPER BLOK birleştirme — trambolin (tek komutlu jmp) kenar yeniden
    // yönlendirme + adres-komşu tek-öncül füzyonu + öncülsüz blok temizliği.
    // Build sonrası çağrılır; DetectLoops/ResolveJumpTables ÖNCE çalışmalı mı?
    // Hayır: Build içinde çağrılır (switch kenarları eklenmeden güvenli).
    void MergeSuperBlocks();
    size_t MergedCount() const { return mergedCount_; }   // istatistik

    // Dolaylı jmp bloklarını jump-table olarak çözer (kenarları ekler)
    // Analyzer'dan bellek okur; Build sonrası çağrılmalı
    void ResolveJumpTables(const Analyzer& az);

    const std::vector<BasicBlock>& Blocks() const { return blocks_; }
    const BasicBlock* BlockAt(u64 va) const;
    std::vector<LoopInfo> DetectLoops() const;
    size_t BlockCount() const { return blocks_.size(); }
    const std::vector<Ins>* InsList() const { return ins_; }
    const SwitchInfo* SwitchAt(u64 blockVa) const;
    const std::vector<SwitchInfo>& Switches() const { return switches_; }
    bool HasSwitches() const { return !switches_.empty(); }

private:
    std::vector<BasicBlock> blocks_;
    std::map<u64, size_t> byAddr_;    // block start -> index
    const std::vector<Ins>* ins_ = nullptr;
    std::vector<SwitchInfo> switches_;
    size_t mergedCount_ = 0;         // v5: birleştirilen blok sayısı
};

} // namespace gt
