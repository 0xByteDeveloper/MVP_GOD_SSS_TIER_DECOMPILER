// ============================================================================
//  i4M GodTier Engine — decomp/devirtemu.h
//  DEVRİT TIER-3: Unicorn tabanlı TOHUMLU PENCERE EMÜLASYONU.
//
//  "livestep god mod" — kullanıcının livestep.cpp vizyonunun doğru ölçekte
//  gerçekleştirilmesi: process'i entry point'ten %100 yürütmek YANLIŞ ARAÇTI
//  (v7'de kanıtlandı: playerGetStatus login olana dek çağrılmaz). Bunun
//  yerine dolaylı çağrının TEMEL BLOĞU gerçek x86 semantiğiyle (Unicorn)
//  çalıştırılır — dal/jcc/bayrak/yardımcı-çağrı hepsi GERÇEK.
//
//  Eksik bilgi (runtime'da yazılan vptr'ler) STATİK KANIT TOHUMLARIYLA
//  verilir — process hiç çalışmaz:
//    [ms_singleton]         = &sentetikNesne     (kurucu "mov [S], this" kanıtı)
//    [sentetikNesne + K]    = vftable            (kurucu "mov [this+K], vft" kanıtı)
//  Tohumlanmış blok koştuğunda çağrı yazmacı SOMUT değer taşır → hedef.
//
//  Çoklu-aday dürüstlüğü: kurucu kanıtı birden çok vftable gösteriyorsa her
//  aday için AYRI pass koşulur; tüm pass'ler aynı hedefe giderse ÇÖZÜM,
//  farklı hedeflere gidiyorsa dürüst aday listesi (yanlış tekil tahmin YOK).
//
//  Zincir (metin2client.exe gerçek örneği, process ÇALIŞMADAN):
//    mov  ecx, [0x8BD2D0]    ; ms_singleton  ← tohum: &sentetik
//    add  ecx, 4             ;
//    mov  edx, [ecx]         ; vptr          ← tohum: 0x805054 (RTTI kanıtlı)
//    call dword ptr [edx+0x88]               ← slot 34 GERÇEK DEĞERLE okunur
//         → CPythonPlayer::NEW_GetMainActorPtr (0x4E26F0)  [TIER-3 ÇÖZÜM]
// ============================================================================
#pragma once
#include "analysis/msvcrtti.h"
#include "disasm/analyzer.h"
#include "mapper/mapper.h"
#include <memory>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace gt {

class DevirtPro;   // ileri bildirim (döngüsel include yok)

class DevirtEmu {
public:
    // bir emülasyon pass'inin tohumları
    struct SeedChoice {
        // statik VA -> (nesne ofseti -> seçilmiş vftable)
        std::map<u64, std::map<i64, u64>> staticSeeds;
        // sanal metod gövdesi için this-tohumu (atlas inversiyonundan):
        // ecx/rdi = sentetikThis + thisOff, [ecx] = thisVft
        bool useThis = false;
        i64 thisOff = 0;
        u64 thisVft = 0;
    };

    // tek pencere denemesi sonucu (dürüst raporlama)
    struct Attempt {
        bool reached = false;          // çağrı noktasına ulaşıldı mı
        u64 target = 0;                // çözülen hedef VA (0 = yok)
        u64 vftVa = 0;                 // kanıt vftable'ı (varsa)
        i64 slotOff = -1;              // vtable bayt ofseti
        bool isImport = false;
        std::string importName;        // "dll.api"
        size_t executed = 0;           // çalıştırılan komut sayısı
        std::string why;               // başarısızlık nedeni (dürüst)
        std::set<u64> touchedStatics;  // okunan statik yuvaları (aday genişletme)
    };

    DevirtEmu(Analyzer& az, DevirtPro& dp, const MsvcRtti& rtti);
    ~DevirtEmu();

    // x86 (32/64) + emulator kurulumu başarılıysa true (bir kez dener)
    bool Available();

    // Tek dolaylı çağrıyı pencere emülasyonuyla çöz.
    Attempt TryCall(u64 callAddr, const SeedChoice& sc,
                    std::vector<std::string>* trace);

    u64 StaticSynthAddr(u64 staticVa);

private:
    bool EnsureSetup();
    u64 WindowStart(const std::vector<Ins>& ins, size_t callIdx);
    void ApplySeeds(const SeedChoice& sc);
    void RestoreDirty();
    void ZeroRegs();
    u64 ReadRegByName(const std::string& reg);
    bool ReadPtr(u64 va, u64* out);
    bool IsExecVa(u64 va) const;
    std::string ImportAt(u64 iatVa);
    void BuildStaticIndex();

    Analyzer& az_;
    DevirtPro& dp_;
    const MsvcRtti& rtti_;
    std::unique_ptr<class Emulator> emu_;   // döngüsel değil — emulator.h
    MapReport mapRep_{};                   // minimal (shadow bölgesi boş)
    bool tried_ = false;
    bool ok_ = false;
    bool is64_ = false;
    u64 thisSynth_ = 0;
    std::map<u64, u64> synthOf_;            // statik VA -> sentetik nesne VA
    std::set<u64> staticSlots_;             // hızlı "statik yuvası mı?" sorgusu
    std::map<u64, std::string> importByIat_;
};

} // namespace gt
