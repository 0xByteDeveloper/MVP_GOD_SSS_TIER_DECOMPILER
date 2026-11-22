// ============================================================================
//  i4M GodTier Engine — decomp/pseudocode.h
//  Hibrit decompiler v2:
//   - Faz 1: TypeInferer global tip analizi (imzalar + struct'lar)
//   - Faz 2: fonksiyon başına ifade katlama (register dataflow),
//     koşul yapılaştırma (while / do-while / if-else / if), return değerleri,
//     derleyici idiom katlama (magic-number bölme, % sabit, imm string),
//     SysV + Win64 çağrı kuralları, PLT/İAT isimleri, string ek açıklamaları.
//  Üslubu Hex-Rays: tek satır bileşik ifadeler, blok başı yerel tanımları.
//  Köprüler: RetDec/Ghidra headless (bridge).
// ============================================================================
#pragma once
#include "analysis/msvcrtti.h"
#include "decomp/cfg.h"
#include "decomp/devirtpro.h"
#include "decomp/types.h"
#include "format/pdb.h"
#include "disasm/analyzer.h"
#include <memory>
#include <string>

namespace gt {

struct DecompOptions {
    bool showAddresses = false;   // satır sonunda ; 0x401000 (v2: kapalı default)
    bool annotateStrings = true;
    bool annotateApi = true;
    int maxInsPerFunc = 4000;
};

class Pseudocoder {
public:
    Pseudocoder(Analyzer& az, const DecompOptions& opt = {}) : az_(az), opt_(opt) {}

    // Tek fonksiyon için pseudocode üret
    std::string DecompileFunction(u64 start);

    // Tüm fonksiyonları tek dosyaya yaz (rapor modu)
    std::string DecompileAll(size_t limit = 0); // 0 = hepsi

    // Global tip veritabanı (ilk kullanımda otomatik koşar)
    TypeInferer& TI();
    void InvalidateTI() { ti_.reset(); devirtPro_.reset(); rtti_.reset(); }
    // PDB kanalı: InvalidateTI sonrası bile hayatta kalır (pending olarak taşınır)
    void SetPdb(std::unique_ptr<PdbInfo> p) {
        if (ti_) ti_->SetPdb(std::move(p));
        else pendingPdb_ = std::move(p);
        devirtPro_.reset();   // isimler değişti — kanıt taraması yenilensin
    }

    // v7: MSVC RTTI atlası (lazy — ilk kullanımda tarar)
    MsvcRtti& Rtti();
    // v7: DEVRİT-PRO motoru (lazy — Rtti + TI hazır olduktan sonra Build)
    DevirtPro& Devirt();

    // Harici decompiler köprüleri
    static std::string BridgeRetDec(const std::string& pePath, const std::string& outPath);
    static std::string BridgeGhidra(const std::string& filePath, const std::string& outPath);

private:
    Analyzer& az_;
    DecompOptions opt_;
    std::unique_ptr<TypeInferer> ti_;
    std::unique_ptr<PdbInfo> pendingPdb_;   // TI kurulana dek bekleyen PDB
    std::unique_ptr<MsvcRtti> rtti_;
    std::unique_ptr<DevirtPro> devirtPro_;
    std::string Decompile32(u64 start);     // v7: PE32 (x86) pseudocode yolu
};

} // namespace gt
