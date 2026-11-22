// ============================================================================
//  i4M GodTier Engine — analysis/msvcrtti.h
//  MSVC RTTI atlası: sembolsiz MSVC binary'lerinden C++ sınıf evrenini
//  geri kazan. IDA'nın "RTTI scanner" eklentisinin ve Ghidra'nın
//  "Recover Classes from RTTI" betiğinin motor-hali.
//
//  Ne bulur (hepsi STATİK — binary çalışmaz, debugger açılmaz):
//    1. TypeDescriptor'lar: ".?AVCPythonPlayer@@" isimli type_info kalıntıları
//    2. _RTTICompleteObjectLocator (COL): vftable[-1] işaretçisinin hedefi
//    3. vftable'lar: [COL işaretçisi][slot0][slot1]... düzeninde .rdata dizileri
//    4. Sınıf hiyerarşisi (BaseClassDescriptorArray → kalıtım grafiği)
//
//  Gerçek savaş alanı: metin2client.exe üzerinde kanıtlandı —
//    vftable 0x805054 → COL 0x820CAC → ".?AVCPythonPlayer@@"
//    slot 4  (+0x10) = CPythonPlayer::GetStatus      (0x4E2F60)
//    slot 34 (+0x88) = CPythonPlayer::NEW_GetMainActorPtr (0x4E26F0)
//
//  Bu atlas devirt-pro zincirinin ilk halkasıdır: "call [edx+0x88]" ancak
//  vftable'ın KİM olduğunu bilirsek çözülür.
// ============================================================================
#pragma once
#include "disasm/analyzer.h"
#include <map>
#include <string>
#include <vector>

namespace gt {

struct RttiClass {
    std::string name;            // "CPythonPlayer" (demangle edilmis)
    std::string rawName;         // ".?AVCPythonPlayer@@"
    u64 tdVa = 0;                // TypeDescriptor VA
    u64 colVa = 0;               // CompleteObjectLocator VA
    u64 vftVa = 0;               // vftable'in ILK SLOTunun VA'si (COL'dan sonra)
    u32 objectOffset = 0;        // COL.offset: tam nesne icindeki alt-nesne ofseti
    u32 numBases = 0;            // COL hiyerarsi sayisi
    std::vector<u64> slots;      // slot i -> hedef fonksiyon VA
    std::vector<std::string> slotNames;  // PDB/sembol varsa gercek adlar
    bool slotsComplete = true;   // false: son slot siniri net degil (kesildi)
};

class MsvcRtti {
public:
    explicit MsvcRtti(const Analyzer& az) : az_(az) {}

    // Taramayi kos (RunFull'dan sonra). Sadece okunur bolumleri gezer.
    void Build();

    const std::vector<RttiClass>& Classes() const { return classes_; }
    size_t SlotCount() const { return totalSlots_; }

    // vftable VA'sindan sinif (ilk slotun adresi ile sorgula)
    const RttiClass* ByVftable(u64 vftVa) const;
    // Isimden sinif
    const RttiClass* ByName(const std::string& demangled) const;
    // vftable + slot ofseti -> hedef (0 = cozulemedi)
    u64 ResolveSlot(u64 vftVa, u32 slotByteOff, std::string* why) const;
    // v8: ATLAS İNVERSİYONU — "hangi fonksiyon hangi vftable'larda metot?"
    // Devirt tier-1/tier-3 için: sanal metod gövdesinde this'in dinamik
    // tipi, metodun bulunduğu vftable kümesiyle kısıtlanır (CHA).
    const std::vector<const RttiClass*>* VtablesContaining(u64 methodVa) const;

    // MSVC tip adi demangle: ".?AVCPythonPlayer@@" -> "CPythonPlayer"
    // sablonlar: ".?AV?$CSingleton@VCPythonPlayer@@@@"
    //            -> "CSingleton<CPythonPlayer>"
    static std::string DemangleTypeId(const std::string& raw);

    // sinif hiyerarsi (CHA icin): taban -> alt siniflar
    const std::map<std::string, std::set<std::string>>& Children() const {
        return children_;
    }

private:
    bool ValidCol(u64 colVa, u64* tdVaOut, u32* objOffOut, u32* nBasesOut,
                  std::vector<std::string>* baseNamesOut) const;
    bool IsExecPtr(u64 va) const;
    bool IsDataPtr(u64 va) const;

    const Analyzer& az_;
    std::vector<RttiClass> classes_;
    std::map<u64, const RttiClass*> byVft_;      // vftable VA -> sinif
    std::map<u64, std::vector<const RttiClass*>> byCol_;  // ayni COL'a bakanlar
    std::map<std::string, std::set<std::string>> children_;
    std::map<u64, std::vector<const RttiClass*>> methodOwners_;  // v8: metot -> vftable'lar
    size_t totalSlots_ = 0;
};

} // namespace gt
