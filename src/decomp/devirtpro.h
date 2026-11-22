// ============================================================================
//  i4M GodTier Engine — decomp/devirtpro.h
//  DEVRİT-PRO v7: sanal çağrıların TAM STATİK ÇÖZÜMÜ — "livestep-lite".
//
//  Felsefe (kullanıcının öngörüsü doğruydu, ama ölçeği küçülttük):
//    "Process'i entry point'ten %100 simüle et" → YANLIŞ ARAÇ. Çünkü
//    playerGetStatus oyuncu login olana dek ÇALIŞMAZ — hiçbir emulator
//    "oyuncunun giriş yapmasını" simüle edemez + D3D döngüsü milyonlarca
//    komut = astronomik yavaş.
//
//    DOĞRU ARAÇ: dolaylı çağrının ÖNCEKİ ~10 komutunu (livestep.cpp'nin
//    sparse-bellek + TEB fikrini mikro ölçeğe indirgedik) somut-simgesel
//    değerlendiriciyle çalıştır; eksik tek bilgi "bu statik nesnenin vtable'ı
//    ne?" ise cevabı KURUCUDA ara (vtable saklama kanıtı — process'i
//    çalıştırmadan, statik bellek + kod kanıtıyla).
//
//  Zincir (metin2client.exe üzerinde kanıtlanmış gerçek örnek):
//    mov ecx, [0x8BD2D0]      ; ms_singleton      ← .bss (imajda 0!)
//    add ecx, 4               ;                   ← ikincil taban ofseti
//    mov eax, [ecx]           ; vptr              ← RT Runtime'da yazılır
//    mov eax, [eax+0x10]      ; slot 4            ← .rdata (imajda VAR!)
//    call eax                 ; → CPythonPlayer::GetStatus  (0x4E2F60)
//
//    Eksik halka "vptr": CPythonPlayer kurucusu (0x4E52..):
//      mov [ecx], 0x805044    ; taban vftable (ara yazım)
//      lea eax, [ecx+4]  ; mov [eax], 0x805054  ; SON yazım kazanır
//      mov [0x8BD2D0], ecx    ; ms_singleton = this  ← İSPAT
//    WindowEvaluator bu depolamaları SIRAYLA değerlendirir (son yazım
//    kazanır — desen eşleme DEĞİL, gerçek ardışık semantik).
// ============================================================================
#pragma once
#include "analysis/msvcrtti.h"
#include "decomp/types.h"
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace gt {

class DevirtEmu;   // v8: tier-3 (Unicorn) — ileri bildirim

class DevirtPro {
public:
    DevirtPro(Analyzer& az, TypeInferer& ti, const MsvcRtti& rtti);
    ~DevirtPro();   // v8: DevirtEmu unique_ptr tamamı tanımlı olmalı

    // 1) Tüm fonksiyonlarda statik-yazıcı taraması (kurucu kanıtları)
    // 2) Tüm dolaylı çağrıları çöz (kanıtlanabilir olanları)
    void Build();

    // Tek dolaylı çağrıyı çöz (call reg / call [mem]) — kanıt iziyle
    struct Result {
        bool resolved = false;
        bool isImport = false;          // IAT import çağrısı (dll.api)
        u64 target = 0;                 // çözülen hedef VA
        u64 vftVa = 0;                  // kanıt vftable'ı (0 = vtable'sız)
        std::string className;          // "CPythonPlayer"
        int slot = -1;                  // vtable slot no
        std::string name;               // hedef adı (PDB/sembol/Class::slot_N)
        std::string why;                // insan-okur kanıt özeti
        // v8.1: MEKANİZMA ETİKETİ — "çözülenler NASIL çözüldü" kırılımı
        //   "IAT"     : import tablosundan (call [IAT] / mov reg,[IAT])
        //   "kurucu"  : kurucu vtable-saklama kanıtı (statik yazıcı)
        //   "atlas"  : atlas inversiyonu (CHA — metodun sahibi sınıflar)
        //   "tier-3" : Unicorn tohumlu pencere emülasyonu
        //   "pencere": vtable'sız somut zincir (imaj verisi)
        std::string proofKind;
        std::vector<std::string> trace; // adım adım zincir
        std::vector<u64> candidates;    // çok adaylı dürüst durum
        std::vector<std::string> candidateNames;
    };
    Result Resolve(u64 callAddr);

    // Build'in çözücüsü: call adresi -> sonuç
    const std::map<u64, Result>& Results() const { return results_; }

    // v9.2 (Tier-5a WinInit): init-anlık-görüntü kanıtları (VA -> değer).
    // SADECE statik kanıt (IAT > yazıcı > imaj) susuz kaldığında danışılır —
    // hiç verilmediyse/kaldırıldıysa davranış bit-bitiye v8.1 ile aynıdır.
    void SetInitOverlay(const std::map<u64, u64>* ov);
    bool HasInitOverlay() const { return initOverlay_ != nullptr; }
    bool UsedInitFact() const { return usedInitFact_; }   // son Resolve/init Build kullandı mı

    // v8: tier-3 (Unicorn) + render erişimi — statik-kanıt görünümleri
    struct StaticFactsView {
        bool proven = false;
        std::vector<u64> writers;
        std::map<i64, std::vector<u64>> vptrCand;   // ofset -> aday vftable'lar
    };
    StaticFactsView StaticView(u64 va) const;
    std::vector<u64> AllStaticVas() const;

    // Shell raporu: statik nesne envanteri
    void DumpStatics(std::string& out) const;
    // Shell raporu: çözülen çağrı özeti
    void DumpResolved(std::string& out) const;

    size_t StaticCount() const { return statics_.size(); }
    size_t ResolvedCount() const;

    // v8.1: MEKANİZMA KIRILIMI — "N/ M çözüldü" sayısının İÇ YAPISI.
    // Çözülenler hangi kanıtla, çözülemeyenler hangi nedenle? (Build doldurur)
    struct Stats {
        size_t universe = 0;         // taranan toplam dolaylı çağrı
        size_t resolved = 0;
        // --- çözülen kırılımı (kanıt mekanizmasına göre) ---
        size_t byIat = 0;            // IAT importu (call [IAT] -> dll.api)
        size_t byCtor = 0;           // kurucu vtable-saklama kanıtı
        size_t byAtlas = 0;          // atlas inversiyonu (CHA)
        size_t byTier3 = 0;          // Unicorn tohumlu pencere emülasyonu
        size_t byConc = 0;           // vtable'sız somut zincir (imaj verisi)
        size_t byInit = 0;           // v9.2: WinInit init-anlık-görüntü kanıtı
        // --- çözülemeyen kırılımı (dürüst neden etiketleri) ---
        size_t unMultiCand = 0;      // çoklu aday — tekil tahmin YASAK
        size_t unNoProof = 0;        // kanıt yok: alıcı heap/parametre nesnesi
        size_t unTier3Win = 0;       // tier-3 pencereye ulaşamadı/kanıt taşımadı
    };
    const Stats& GetStats() const { return stats_; }
    // Shell raporu: kırılım tablosu (devirt stats)
    void DumpStats(std::string& out) const;

    // ---- WindowEvaluator: livestep-lite çekirdeği (test edilebilir) ----
    // Değerler: bilinmeyen / somut / simgesel-nesne / çoklu-aday
    struct VVal {
        enum Kind : u8 { Unknown, Conc, Sym, Cand } k = Unknown;
        u64 c = 0;                    // Conc değeri
        i64 off = 0;                  // Sym: nesne içi ofset
        std::vector<u64> cands;       // Cand: vftable adayları
        bool IsUnknown() const { return k == Unknown; }
    };

    // Bellek okuma politika testleri için dışa açık
    VVal ReadMemory(u64 addr, std::vector<std::string>* trace);

private:
    // ---- kurucu kanıt taraması ----
    struct WriterScan {
        // bu fonksiyonun yazdığı statikler (mov [S], this-türevi)
        std::set<u64> staticsWritten;
        // this+ofset -> vftable (SON yazım kazanır — lineer sıra)
        std::map<i64, u64> vptrAt;
        // this+ofset'e yazılan tüm vftable'lar (CHA dürüstlüğü için)
        std::map<i64, std::set<u64>> vptrAll;
    };
    void ScanWriters();
    // tek fonksiyonu değerlendir; yazıcı kanıtlarını topla
    void EvalFunction(u64 funcVa, const std::vector<Ins>& ins,
                      WriterScan* out, u64 stopAt,
                      Result* result /* nullable: çağrı çözümü */);

    VVal Reg(const std::string& canon) const;
    void SetReg(const std::string& canon, VVal v);
    VVal EvalOperand(const std::string& op, std::vector<std::string>* trace);
    VVal ReadMemAddr(const std::string& memOp, std::vector<std::string>* trace);
    bool IsVftable(u64 va) const { return rtti_.ByVftable(va) != nullptr; }
    bool IsExecVa(u64 va) const;
    // IAT yuvası çözümü (bound-import tuzağına karşı): "dll.api" döner
    std::string ImportAt(u64 iatVa) const;
    std::string NameForTarget(u64 va) const;
    void CollectIndirectCalls(std::vector<u64>& out) const;

    Analyzer& az_;
    TypeInferer& ti_;
    const MsvcRtti& rtti_;
    std::unique_ptr<DevirtEmu> emu3_;   // v8: tier-3 lazy

    // statik VA -> nesne kanıtları (yazıcı fonksiyonlardan birleşik)
    struct ObjFacts {
        std::vector<u64> writers;                     // kurucu fonksiyonlar
        std::map<i64, std::vector<u64>> vptrCand;     // ofset -> vftable adayları
    };
    std::map<u64, ObjFacts> statics_;

    std::map<u64, Result> results_;
    Stats stats_;                       // v8.1: Build doldurur
    // v9.2: WinInit overlay (dışarıdan ödünç — Shell/Pseudocoder sahiplenir)
    const std::map<u64, u64>* initOverlay_ = nullptr;
    mutable bool usedInitFact_ = false;  // ReadMemory overlay'e mi baktı
    mutable std::map<u64, std::string> importByIat_;   // IAT VA -> dll.api
    u64 lastIatSlot_ = 0;    // son okunan IAT yuvası (mov reg,[IAT]; call reg)

    // ---- değerlendirici durumu (EvalFunction sırasında) ----
    std::map<std::string, VVal> regs_;
    // bellek yazımı olguları (bu fonksiyon içinde, lineer sırada):
    // somut-adres -> değer (mov [S], reg|imm kanıtları)
    std::map<u64, VVal> memFacts_;
    // this (giriş ecx/rcx/rdi) objesi: ofset -> son vftable
    std::map<i64, u64> thisVptr_;
    std::map<i64, std::set<u64>> thisVptrAll_;
    // v8: atlas inversiyonu — bu fonksiyonun this vtable ADAYLARI
    // (sanal metod gövdesi: this'in dinamik tipi metodun sahibi sınıflarla
    //  kısıtlı — CHA dürüstlüğü: tek sahipsiz somut, çok sahipli aday)
    std::map<i64, std::vector<u64>> thisVptrCand_;
    // v8: tier-3 orkestrasyonu (çoklu pass + aday birleştirme)
    bool EmuResolve(u64 callAddr, Result& r);
    bool tier3Enabled_ = true;      // v8: toplu tarama süre bütçesi anahtarı
    std::set<u64> thisStatics_;      // this'in yazıldığı statikler
    u64 thisKey_ = 0;                // simgesel nesne anahtarı (fonksiyon VA)
    // simgesel nesne -> kanıt tablosu (ReadMemory için)
    // thisKey_ -> thisVptr_ eşlemesi EvalFunction içinde kurulur

    friend struct DevirtProTestAccess;
};

} // namespace gt
