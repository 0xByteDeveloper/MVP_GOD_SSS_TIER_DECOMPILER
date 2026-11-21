// ============================================================================
//  i4M GodTier Engine — mapper/mapper.h
//  CROSS-PLATFORM WINDOWS LOADER EMÜLASYONU.
//
//  i4MConsoleLoader'ın PEManualMapper'ının (Windows API'lerine bağımlı:
//  VirtualAlloc/LoadLibrary/VirtualProtect) GOD hali:
//   - Linux'ta da çalışır: bellek = kendi MappedImage vektörümüz
//   - Relocation'lar ELLE uygulanır (DIR64/HIGHLOW) — işletim sistemine
//     sorulmaz, Windows'un LdrRelocateImageWithBias akışı birebir taklit edilir
//   - Import çözümü: Gerçek LoadLibrary YOK. Bunun yerine SHADOW IAT:
//     her import için emülatörde bir sahte adres ayrılır (Qiling/Speakeasy
//     dersi). Kod bu adrese call edince API shim katmanı devreye girer.
//   - TLS callback'ler raporlanır, ASLA çalıştırılmaz.
//
//  Akış (Windows loader'ınkiyle birebir adım adım):
//   [1/7] DOS/NT doğrulama          [2/7] Görüntüyü kur (VirtualAlloc yerine)
//   [3/7] Header kopyala            [4/7] Section'ları map et
//   [5/7] Base relocation           [6/7] Shadow IAT (import snap)
//   [7/7] Koruma bayrakları (rapor) + TLS raporu
// ============================================================================
#pragma once
#include "format/binary.h"
#include "format/image.h"
#include <vector>
#include <string>

namespace gt {

// Emülatörde sahte API adreslerinin yaşadığı bölge
static const u64 SHADOW_IAT_BASE = 0x77000000ull;
static const u64 SHADOW_IAT_SIZE = 0x00100000ull; // 1 MB

struct ShadowApi {
    u64 stubVa = 0;            // sahte giriş adresi (emülatörde)
    std::string dllName;       // "kernel32.dll"
    std::string funcName;      // "CreateFileA" / "ord123"
    u64 iatSlotVa = 0;         // doldurulan IAT yuvası
};

struct MapOptions {
    bool applyRelocations = true;
    bool resolveImports   = true;   // shadow IAT
    bool continueOnMissingImport = true;
    u64  forceBase = 0;             // 0 = ImageBase kullan
};

struct MapReport {
    bool success = false;
    u64  mappedBase = 0;
    u64  mappedSize = 0;
    bool relocated = false;
    size_t relocsApplied = 0, relocsSkipped = 0;
    size_t importsResolved = 0, importsMissing = 0;
    std::vector<std::string> log;   // adım adım loader günlüğü (i4M Loader Log'un mirası)
    std::vector<ShadowApi> shadowApis;
    std::vector<u64> tlsCallbacks;
    std::string entrySymbol;
};

class Mapper {
public:
    // Dosyayı belleğe "Windows gibi" çevirir (kod ÇALIŞTIRILMAZ)
    // Çıktı: görüntü (out) + rapor. Görüntü, emülatöre ya da hexdump'a verilir.
    MapReport MapPE(const PE& pe, MappedImage& out, const MapOptions& opt = {});
    MapReport MapELF(const ELF& elf, MappedImage& out, const MapOptions& opt = {});

    // Shadow IAT bölgesinin içeriği: her API için 1 baytlık "ret" kancası
    // (emülatör bunu görünce shim'i çağırır) — emulate modülü bunu map eder.
    const std::vector<ShadowApi>& ShadowApis() const { return shadow_; }

private:
    std::vector<ShadowApi> shadow_;
    u64 nextShadow_ = SHADOW_IAT_BASE;

    u64 AllocShadow(const std::string& dll, const std::string& fn, u64 iatSlot);
    void ApplyRelocsPE(const PE& pe, MappedImage& img, u64 delta, MapReport& rep,
                       const MapOptions& opt);
};

} // namespace gt
