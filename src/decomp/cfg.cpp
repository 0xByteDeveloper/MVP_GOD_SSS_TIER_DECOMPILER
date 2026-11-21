// ============================================================================
//  i4M GodTier Engine — decomp/cfg.cpp
// ============================================================================
#include "decomp/cfg.h"
#include <algorithm>
#include <cctype>

namespace gt {

// yerel operand bölücü ("mov rax, [rbp - 8]" -> {"rax", "[rbp - 8]"})
static std::vector<std::string> SplitOpsOf(const std::string& s) {
    std::vector<std::string> out;
    int depth = 0; std::string cur;
    for (char c : s) {
        if (c == '[') depth++;
        if (c == ']') depth--;
        if (c == ',' && depth == 0) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool CFG::Build(const std::vector<Ins>& ins, const std::set<u64>& extraLeaders) {
    ins_ = &ins;
    blocks_.clear();
    byAddr_.clear();
    switches_.clear();
    if (ins.empty()) return false;

    // 1) Liderleri (leader) bul: ilk komut, dal hedefleri, koşullu dal sonrası
    std::set<u64> leaders;
    if (!ins.empty()) leaders.insert(ins[0].addr);
    for (u64 L : extraLeaders) {
        // yalnız fonksiyon aralığı içindekiler
        if (L >= ins.front().addr && L <= ins.back().addr) leaders.insert(L);
    }
    for (auto& x : ins) {
        if ((x.isJmp || x.isJcc || x.isCall) && !x.isIndirect &&
            x.target >= ins.front().addr && x.target <= ins.back().addr + x.len)
            leaders.insert(x.target);
        if (x.isJcc) {
            // düşen akış: sonraki komut yeni lider
            u64 next = x.addr + x.len;
            leaders.insert(next);
        }
        if (x.isJmp) {
            u64 next = x.addr + x.len;
            leaders.insert(next); // (jmp sonrası komut başka fonksiyonun olabilir)
        }
    }

    // 2) Block'ları kur
    BasicBlock cur;
    cur.start = ins[0].addr;
    for (size_t i = 0; i < ins.size(); i++) {
        const Ins& x = ins[i];
        bool newLeader = (i + 1 < ins.size()) && leaders.count(ins[i + 1].addr);
        cur.insIdx.push_back(i);
        cur.end = x.addr;
        cur.endsWithRet = x.isRet;
        cur.endsWithJmp = x.isJmp;
        if (x.isJmp && !x.isIndirect) cur.succ.push_back({x.target, EdgeType::Branch});
        if (x.isJcc && !x.isIndirect) cur.succ.push_back({x.target, EdgeType::Branch});
        if (newLeader || i + 1 == ins.size() || x.isJmp || x.isRet) {
            // düşen akış kenarı
            if (!x.isJmp && !x.isRet && i + 1 < ins.size())
                cur.succ.push_back({ins[i + 1].addr, EdgeType::Fallthrough});
            byAddr_[cur.start] = blocks_.size();
            blocks_.push_back(cur);
            cur = BasicBlock{};
            if (i + 1 < ins.size()) cur.start = ins[i + 1].addr;
        }
    }

    // 3) Öncüller + backedge işaretleme
    for (auto& b : blocks_) {
        for (auto& [dst, t] : b.succ) {
            auto it = byAddr_.find(dst);
            if (it == byAddr_.end()) continue;
            blocks_[it->second].pred.push_back(b.start);
            if (dst <= b.start) t = EdgeType::Backedge; // geriye giden kenar
        }
    }
    // 4) v5: süper blok birleştirme (switch kenarları eklenmeden ÖNCE güvenli)
    MergeSuperBlocks();
    return !blocks_.empty();
}

// ----------------------------------------------------------------------------
// v5: SÜPER BLOK BİRLEŞTİRME
//   A) TRAMBOLİN YÖNLENDİRMESİ: X = yalnız "jmp T" içeren blok (giriş değil,
//      backedge hedefi değil) -> X'e giden TÜM kenarlar doğrudan T'ye yönlendirilir
//      (jmp-üzerinden-jmp zincirleri ölür). Komut hedefleri de senkron yazılır.
//   B) ADRES-KOMŞU FÜZYON: A koşulsuz jmp'le (veya düşen akışla) B'ye gider,
//      B fiziksel olarak A'nın hemen ardındaysa VE B'nin tek öncülü A ise
//      -> B, A'ya katılır (tek süper blok). Adres-aralığı bölge mantığı
//      ([head..latch] aralıkları) bozulmasın diye yalnız fiziksel komşulukta.
//   C) ÖNCÜLSÜZ TEMİZLİĞİ: trambolin yönlendirmesi sonrası öncüsü kalmayan
//      (giriş olmayan) bloklar silinir.
// ----------------------------------------------------------------------------
void CFG::MergeSuperBlocks() {
    if (!ins_ || blocks_.empty()) return;
    std::vector<Ins>& ins = const_cast<std::vector<Ins>&>(*ins_);
    const u64 entryVa = blocks_.front().start;
    mergedCount_ = 0;

    // backedge hedefleri (döngü başları) — bunlara dokunma
    auto isBackedgeTarget = [&](u64 va) {
        for (auto& b : blocks_)
            for (auto& [dst, t] : b.succ)
                if (t == EdgeType::Backedge && dst == va) return true;
        return false;
    };

    bool changed = true;
    int guard = 0;
    std::set<u64> threadedAway;   // trambolin yönlendirmesinin kurbanları
    while (changed && guard++ < 64) {
        changed = false;

        // ---- A) trambolin yönlendirme ----
        for (size_t xi = 0; xi < blocks_.size(); xi++) {
            BasicBlock& X = blocks_[xi];
            if (X.start == entryVa || X.insIdx.size() != 1) continue;
            const Ins& j = ins[X.insIdx[0]];
            if (!(j.isJmp && !j.isIndirect)) continue;
            u64 T = j.target;
            if (T == X.start || isBackedgeTarget(X.start)) continue;
            // X'e gelen kenarları T'ye çevir
            bool threaded = false;
            for (auto& P : blocks_) {
                if (P.start == X.start) continue;
                bool hits = false;
                for (auto& [dst, t] : P.succ)
                    if (dst == X.start) { hits = true; break; }
                if (!hits) continue;
                // düşen akış kenarı fiziksel komşuluk gerektirir: yönlendirilemez
                // (komut düzeyinde düşen akış yeniden yazılamaz) — yalnız dal kenarı
                for (auto& [dst, t] : P.succ) {
                    if (dst != X.start || t == EdgeType::Fallthrough) continue;
                    dst = T;
                    threaded = true;
                }
                if (!threaded) continue;
                // komut hedeflerini senkron yaz (jcc/jmp -> X.start olanlar)
                for (size_t k : P.insIdx) {
                    Ins& pi = ins[k];
                    if ((pi.isJcc || pi.isJmp) && !pi.isIndirect && pi.target == X.start)
                        pi.target = T;
                }
            }
            if (threaded) {
                threadedAway.insert(X.start);
                changed = true;
                break;   // blok listesi değişti: baştan tara
            }
        }
        if (changed) continue;

        // ---- B) adres-komşu tek-öncül füzyonu ----
        // öncül listelerini tazele
        for (auto& b : blocks_) b.pred.clear();
        for (auto& b : blocks_)
            for (auto& [dst, t] : b.succ) {
                auto it = byAddr_.find(dst);
                if (it != byAddr_.end()) blocks_[it->second].pred.push_back(b.start);
            }
        for (size_t ai = 0; ai < blocks_.size(); ai++) {
            BasicBlock& A = blocks_[ai];
            if (A.insIdx.empty()) continue;
            const Ins& last = ins[A.insIdx.back()];
            u64 Bva = 0;
            if (last.isJmp && !last.isIndirect) {
                Bva = last.target;
            } else if (!last.isJmp && !last.isRet && !last.isJcc) {
                Bva = last.addr + last.len;    // düşen akış
            } else continue;
            auto bit = byAddr_.find(Bva);
            if (bit == byAddr_.end()) continue;
            BasicBlock& B = blocks_[bit->second];
            if (B.start == entryVa || B.start == A.start) continue;
            if (B.pred.size() != 1 || B.pred[0] != A.start) continue;
            // fiziksel komşuluk: B, A'nın son komutunun hemen ardında
            if (B.start != last.addr + last.len) continue;
            if (isBackedgeTarget(B.start)) continue;
            // birleştir
            for (size_t k : B.insIdx) A.insIdx.push_back(k);
            A.end = B.end;
            A.endsWithRet = B.endsWithRet;
            A.endsWithJmp = B.endsWithJmp;
            A.succ = B.succ;
            byAddr_.erase(B.start);
            blocks_.erase(blocks_.begin() + bit->second);
            mergedCount_++;
            changed = true;
            break;
        }
        if (changed) continue;

        // ---- C) öncülsüz blok temizliği ----
        // YALNIZ trambolin yönlendirmesiyle öncülsüz kalanlar silinir.
        // (Switch case blokları kenarlarını ResolveJumpTables'tan SONRA alır:
        //  Build anında öncülsüz görünürler — onlara dokunma!)
        for (auto& b : blocks_) b.pred.clear();
        for (auto& b : blocks_)
            for (auto& [dst, t] : b.succ) {
                auto it = byAddr_.find(dst);
                if (it != byAddr_.end()) blocks_[it->second].pred.push_back(b.start);
            }
        for (size_t i = 0; i < blocks_.size(); i++) {
            if (blocks_[i].start == entryVa) continue;
            if (!blocks_[i].pred.empty()) continue;
            if (!threadedAway.count(blocks_[i].start)) continue;
            byAddr_.erase(blocks_[i].start);
            blocks_.erase(blocks_.begin() + i);
            changed = true;
            break;
        }
    }
    // öncül listelerini son kez tazele
    for (auto& b : blocks_) b.pred.clear();
    for (auto& b : blocks_)
        for (auto& [dst, t] : b.succ) {
            auto it = byAddr_.find(dst);
            if (it != byAddr_.end()) blocks_[it->second].pred.push_back(b.start);
            if (dst <= b.start) t = EdgeType::Backedge;
        }
}

const BasicBlock* CFG::BlockAt(u64 va) const {
    // va'yı içeren blok
    auto it = byAddr_.upper_bound(va);
    if (it == byAddr_.begin()) return nullptr;
    --it;
    const BasicBlock& b = blocks_[it->second];
    if (va >= b.start && va <= b.end) return &b;
    return nullptr;
}

std::vector<LoopInfo> DetectLoopsHelper(const CFG&);

std::vector<LoopInfo> CFG::DetectLoops() const {
    std::vector<LoopInfo> loops;
    for (auto& b : blocks_) {
        for (auto& [dst, t] : b.succ) {
            if (t == EdgeType::Backedge) {
                LoopInfo li;
                li.head = dst;
                li.latch = b.start;
                // v6: SAHTE DÖNGÜ KORUMASI — head'den latch'e İLERİ akışta
                // (fallthrough/branch kenarlarıyla) erişilemiyorsa bu "backedge"
                // gerçek bir yineleme değil, GİRİŞ TRAMBOLİNİDİR: derleyici
                // kuyruk-başlatma bloğunu döngü başının adres ARKASINA yerleştirir
                // (simd_dot n%4 kuyruğu: init bloğu jmp ile geriye sarar).
                // Böyle bir sahte döngü gövdeyi while(true) kapsülüne yanlışlıkla
                // gömer — atla.
                if (li.head != li.latch) {
                    std::set<u64> seen;
                    std::vector<u64> work{li.head};
                    bool reachable = false;
                    while (!work.empty()) {
                        u64 cur = work.back(); work.pop_back();
                        if (cur == li.latch) { reachable = true; break; }
                        if (!seen.insert(cur).second) continue;
                        const BasicBlock* cb = BlockAt(cur);
                        if (!cb) continue;
                        for (auto& [d2, t2] : cb->succ)
                            if (t2 != EdgeType::Backedge) work.push_back(d2);
                    }
                    if (!reachable) continue;   // sahte döngü: yineleme yok
                }
                // while: latch'teki son komut koşullu dal ise
                const Ins* last = nullptr;
                if (ins_ && !b.insIdx.empty()) last = &(*ins_)[b.insIdx.back()];
                li.isWhile = last && last->isJcc;
                // benzersizlik
                bool dup = false;
                for (auto& e : loops) if (e.head == li.head && e.latch == li.latch) dup = true;
                if (!dup) loops.push_back(li);
            }
        }
    }
    return loops;
}

// ----------------------------------------------------------------------------
// Jump-table çözümü (IDA "switch" tanıması):
//   Blok `jmp reg` ile bitiyorsa blok içi kalıpları ara:
//   P1: jmp qword/dword ptr [reg*S + TAB]        (mutlak tablo)
//   P2: lea rB, [rip+TAB] + mov eA,[rD+rB] + cltq + add rA2,rB + jmp  (PIC rel32)
// Girdiler okunur; >=3 ardışık geçerli hedef → jump table. Kenarlar eklenir.
// ----------------------------------------------------------------------------
const SwitchInfo* CFG::SwitchAt(u64 blockVa) const {
    for (auto& s : switches_) if (s.blockVa == blockVa) return &s;
    return nullptr;
}

static bool AddrExecutable(const Analyzer& az, u64 va) {
    for (auto& s : az.Bin().Sections())
        if (s.executable && va >= s.va && va < s.va + s.vsize) return true;
    return false;
}

void CFG::ResolveJumpTables(const Analyzer& az) {
    switches_.clear();
    if (!ins_) return;
    const std::vector<Ins>& ins = *ins_;

    for (auto& b : blocks_) {
        if (b.insIdx.empty()) continue;
        const Ins& last = ins[b.insIdx.back()];
        if (!(last.isJmp && last.isIndirect)) continue;

        // --- taban adaylarını topla (rip-göreli lea + jmp mem operandı) ---
        std::vector<u64> tableCands;
        std::string indexReg;
        u32 memScale = 4;
        size_t tableReadIdx = (size_t)-1;

        for (size_t k = 0; k < b.insIdx.size(); k++) {
            const Ins& x = ins[b.insIdx[k]];
            if (x.mnemonic != "lea" && x.mnemonic != "mov" && x.mnemonic != "jmp") continue;
            auto ops = SplitOpsOf(x.opStr);
            (void)ops;
            // rip-göreli lea: memRef tablo adresi
            if (x.mnemonic == "lea" && x.hasMemRef && x.memRef) {
                // yalnız .rodata/.data benzeri (çalıştırılamaz) bölümdeyse tablo adayı
                if (!AddrExecutable(az, x.memRef)) tableCands.push_back(x.memRef);
            }
            // indeks taraması: [reg*4] / [reg + reg*4] kalıpları (mov/lea)
            if ((x.mnemonic == "lea" || x.mnemonic == "mov") &&
                x.opStr.find('*') != std::string::npos &&
                (x.opStr.find("]*") != std::string::npos ||
                 x.opStr.find("*4]") != std::string::npos ||
                 x.opStr.find("*8]") != std::string::npos)) {
                // ilk *4/*8 indeksli operandın indeks register'ı
                // (mov eax, [rdx + rax*4] gibi)
                for (auto& o : SplitOpsOf(x.opStr)) {
                    size_t st = o.find('*');
                    if (st == std::string::npos) continue;
                    // "*N]" ölçeği
                    u32 sc = (u32)strtoul(o.c_str() + st + 1, 0, 10);
                    // indeks register: '[' sonrası ilk "+ rX*" veya "rX*"
                    size_t lb = o.find('[');
                    if (lb == std::string::npos) continue;
                    std::string inner = o.substr(lb + 1, o.rfind(']') - lb - 1);
                    // token'lara ayır
                    std::vector<std::string> toks;
                    std::string cur;
                    for (char c : inner) {
                        if (c == '+' || c == '*') { if (!cur.empty()) { toks.push_back(cur); cur.clear(); } toks.push_back(std::string(1, c)); }
                        else if (c == ' ') { if (!cur.empty()) { toks.push_back(cur); cur.clear(); } }
                        else cur += c;
                    }
                    if (!cur.empty()) toks.push_back(cur);
                    for (size_t ti = 0; ti + 1 < toks.size(); ti++) {
                        if (toks[ti + 1] == "*" && (ti == 0 || toks[ti - 1] != "*")) {
                            // toks[ti] = indeks register (ilk token da olabilir: [rax*4])
                            std::string r = toks[ti];
                            r.erase(std::remove_if(r.begin(), r.end(), ::isspace), r.end());
                            if (r.size() >= 2 && r[0] == 'r') {
                                indexReg = r;
                                if (sc == 4 || sc == 8) memScale = sc;
                                tableReadIdx = b.insIdx[k];
                            }
                        }
                    }
                }
            }
            // doğrudan jmp mem: [rax*8 + 0xADDR] — mutlak tablo
            if (x.mnemonic == "jmp" && x.opStr.find('[') != std::string::npos &&
                x.hasMemRef && x.memRef && !AddrExecutable(az, x.memRef)) {
                tableCands.push_back(x.memRef);
            }
        }
        if (tableCands.empty() || indexReg.empty()) continue;

        // --- her aday için girdileri dene ---
        // ölçek: indeks * S -> girdi boyu S (lea rdx,[rax*4] -> 4 baytlık girdiler)
        u32 trySizes[2] = {memScale == 8 ? 8u : 4u, memScale == 8 ? 4u : 8u};
        for (u64 tab : tableCands) {
            for (u32 esz : trySizes) {
                SwitchInfo sw;
                sw.blockVa = b.start;
                sw.tableVa = tab;
                sw.entrySize = esz;
                sw.indexReg = indexReg;
                sw.isPic = true;
                u64 minVa = ins.front().addr;
                u64 maxVa = ins.back().addr + ins.back().len;
                u32 valid = 0;
                std::vector<u64> targets;
                for (u32 i = 0; i < 256; i++) {
                    u8 raw[8] = {};
                    if (!az.Image().ReadBytes(tab + (u64)i * esz, raw, esz)) break;
                    u64 target;
                    if (esz == 4) {
                        // PIC rel32: İMZALI ofset (tablo > kod adresi -> negatif)
                        i32 sv;
                        memcpy(&sv, raw, 4);
                        target = tab + (u64)(i64)sv;
                        // geçersizse mutlak 32-bit dene
                        if (target < minVa || target >= maxVa) {
                            u32 uv;
                            memcpy(&uv, raw, 4);
                            if (uv >= minVa && uv < maxVa) { target = uv; sw.isPic = false; }
                            else break;
                        }
                    } else {
                        u64 v;
                        memcpy(&v, raw, 8);
                        target = v;
                        if (target < minVa || target >= maxVa) break;
                    }
                    targets.push_back(target);
                    valid++;
                }
                if (valid < 2) continue;
                sw.nCases = valid;
                sw.targets = targets;
                // varsayılan hedef: tabloya düşen bloğun tek öncüsü ja/jae ile
                // bitiyorsa onun hedefi
                if (b.pred.size() == 1) {
                    const BasicBlock* P = BlockAt(b.pred[0]);
                    if (P && !P->insIdx.empty()) {
                        const Ins& pl = ins[P->insIdx.back()];
                        if (pl.isJcc && !pl.isIndirect)
                            sw.defaultTarget = pl.target;
                    }
                }
                switches_.push_back(sw);
                // kenarları ekle (benzersiz hedefler)
                std::set<u64> uniq(targets.begin(), targets.end());
                if (sw.defaultTarget) uniq.insert(sw.defaultTarget);
                for (u64 t : uniq) {
                    b.succ.push_back({t, EdgeType::Branch});
                    auto it = byAddr_.find(t);
                    if (it != byAddr_.end()) blocks_[it->second].pred.push_back(b.start);
                }
                break;   // bu tablo için ilk geçerli boyut yeter
            }
            if (!switches_.empty() && switches_.back().blockVa == b.start) break;
        }
    }
}

} // namespace gt
