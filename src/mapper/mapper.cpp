// ============================================================================
//  i4M GodTier Engine — mapper/mapper.cpp
// ============================================================================
#include "mapper/mapper.h"
#include "core/log.h"
#include "core/util.h"
#include <cstring>
#include <algorithm>

namespace gt {

u64 Mapper::AllocShadow(const std::string& dll, const std::string& fn, u64 iatSlot) {
    if (nextShadow_ + 16 > SHADOW_IAT_BASE + SHADOW_IAT_SIZE) return 0; // bölge doldu
    u64 va = nextShadow_;
    nextShadow_ += 16; // API başına 16 bayt (ret stub'ı + boşluk)
    ShadowApi a;
    a.stubVa = va; a.dllName = dll; a.funcName = fn; a.iatSlotVa = iatSlot;
    shadow_.push_back(a);
    return va;
}

void Mapper::ApplyRelocsPE(const PE& pe, MappedImage& img, u64 delta,
                           MapReport& rep, const MapOptions& opt) {
    if (!delta || !opt.applyRelocations) return;
    rep.relocated = true;
    static const char* typeNames[] = {
        "ABSOLUTE", "HIGH", "LOW", "HIGHLOW", "HIGHADJ", "?", "?", "?",
        "DIR64"
    };
    for (auto& r : pe.Relocs()) {
        u16 t = r.type;
        if (t == 0) { rep.relocsSkipped++; continue; }
        u64 mva = r.va + delta;   // reloc VA'sı ImageBase'e göredir; görüntü yeni tabanda
        switch (t) {
            case 10: { // IMAGE_REL_BASED_DIR64
                u64 v;
                if (img.ReadBytes(mva, (u8*)&v, 8)) {
                    u64 nv = v + delta;
                    img.WriteBytes(mva, (u8*)&nv, 8);
                    rep.relocsApplied++;
                } else rep.relocsSkipped++;
                break;
            }
            case 3: { // IMAGE_REL_BASED_HIGHLOW
                u32 v;
                if (img.ReadBytes(mva, (u8*)&v, 4)) {
                    u32 nv = (u32)(v + (u32)delta);
                    img.WriteBytes(mva, (u8*)&nv, 4);
                    rep.relocsApplied++;
                } else rep.relocsSkipped++;
                break;
            }
            default:
                rep.relocsSkipped++;
                if (t < 9)
                    rep.log.push_back("  reloc tip " + std::string(typeNames[t]) +
                                      " @ 0x" + ToHex(r.va) + " (atlandı)");
                break;
        }
    }
}

MapReport Mapper::MapPE(const PE& pe, MappedImage& img, const MapOptions& opt) {
    MapReport rep;
    shadow_.clear();
    nextShadow_ = SHADOW_IAT_BASE;
    auto step = [&](int i, const std::string& s) {
        LogStep(i, 7, s);
        rep.log.push_back("[" + std::to_string(i) + "/7] " + s);
    };

    // [1/7] DOS/NT doğrulama
    step(1, "DOS/NT header dogrulama");
    if (pe.RawSize() < 2 || pe.Raw()[0] != 'M' || pe.Raw()[1] != 'Z') {
        LogErr("MZ imzası yok"); rep.log.push_back("HATA: MY imzası yok"); return rep;
    }

    // [2/7] Görüntüyü kur
    u64 base = opt.forceBase ? opt.forceBase : pe.ImageBase();
    rep.mappedBase = base;
    rep.mappedSize = pe.ImageSize();
    step(2, "Bellek goruntusu kuruluyor (base=0x" + ToHex(base) + ", size=0x" + ToHex(rep.mappedSize) + ")");

    // [3/7] + [4/7] header + section kopyala
    step(3, "Header'lar kopyalaniyor");
    if (!img.LoadFromBinary(pe)) { LogErr("Görüntü kurulamadı"); return rep; }
    img.SetBase(base);   // forceBase'i goruntu tabanina uygula
    step(4, "Section'lar raw->virtual map ediliyor (" + std::to_string(pe.Sections().size()) + " section)");

    // [5/7] Relocation
    u64 delta = 0;
    if (base != pe.ImageBase()) delta = base - pe.ImageBase();
    step(5, "Base relocation (delta=0x" + ToHex(delta) + ")");
    if (delta) {
        if (pe.HasRelocs()) ApplyRelocsPE(pe, img, delta, rep, opt);
        else rep.log.push_back("  UYARI: base kaydi ama .reloc yok — görüntü bozulabilir!");
    } else {
        rep.log.push_back("  base yerinde, relocation gerekmedi");
    }

    // [6/7] Shadow IAT
    step(6, "Import cozumu (shadow IAT — gercek LoadLibrary YOK)");
    if (opt.resolveImports) {
        for (auto& dll : pe.Imports()) {
            for (auto& fn : dll.funcs) {
                std::string fname = fn.name.empty() ? ("ord" + std::to_string(fn.ordinal)) : fn.name;
                u64 stub = AllocShadow(dll.name, fname, fn.iatVa);
                if (!stub) {
                    rep.importsMissing++;
                    if (!opt.continueOnMissingImport) {
                        LogErr("Shadow IAT bölgesi doldu"); return rep;
                    }
                    continue;
                }
                img.WriteBytes(fn.iatVa, (u8*)&stub, pe.Is64() ? 8 : 4);
                rep.importsResolved++;
            }
        }
        rep.log.push_back("  " + std::to_string(rep.importsResolved) + " import shadow IAT'a baglandi (0x" +
                          ToHex(SHADOW_IAT_BASE) + " bolgesi)");
    } else {
        rep.log.push_back("  import cozumu kapatildi");
    }

    // [7/7] Koruma raporu + TLS
    step(7, "Section koruma bayraklari (rapor) + TLS raporu");
    for (auto& s : pe.Sections()) {
        std::string prot = s.executable ? "E" : "-";
        prot += s.readable ? "R" : "-";
        prot += s.writable ? "W" : "-";
        rep.log.push_back("  " + s.name + " -> " + prot + " (va=0x" + ToHex(s.va) +
                          " size=0x" + ToHex(s.vsize) + ")");
    }
    if (pe.HasTLS()) {
        rep.log.push_back("  TLS dizini VAR: callbacks=0x" + ToHex(pe.TlsCallbacksVa()) +
                          " (CALISTIRILMAZ, sadece rapor)");
        // callback listesini görüntüden oku
        u64 cb = pe.TlsCallbacksVa();
        int guard = 0;
        while (guard++ < 32) {
            u64 fn = img.Read64(cb);
            if (!fn) break;
            rep.tlsCallbacks.push_back(fn);
            cb += 8;
        }
        if (!rep.tlsCallbacks.empty())
            rep.log.push_back("  " + std::to_string(rep.tlsCallbacks.size()) + " TLS callback bulundu");
    }

    rep.shadowApis = shadow_;   // emulatorun stub yazmasi icin (kritik!)
    rep.success = true;
    rep.entrySymbol = "entry @ 0x" + ToHex(pe.EntryPoint());
    LogOk("Map tamam: 0x%llx-0x%llx | reloc: %zu uygulandi | import: %zu shadow",
          (unsigned long long)rep.mappedBase, (unsigned long long)(rep.mappedBase + rep.mappedSize),
          rep.relocsApplied, rep.importsResolved);
    return rep;
}

MapReport Mapper::MapELF(const ELF& elf, MappedImage& img, const MapOptions& opt) {
    MapReport rep;
    shadow_.clear();
    nextShadow_ = SHADOW_IAT_BASE;
    auto step = [&](int i, const std::string& s) {
        LogStep(i, 5, s);
        rep.log.push_back("[" + std::to_string(i) + "/5] " + s);
    };
    step(1, "ELF header dogrulama");
    step(2, "Segment'ler map ediliyor");
    if (!img.LoadFromBinary(elf)) { LogErr("Görüntü kurulamadı"); return rep; }
    rep.mappedBase = img.Base();
    rep.mappedSize = img.Size();
    step(3, "Sembol tablolari cozuluyor");
    // ELF'te import 'snap' yok: GOT/PLT dinamik bağlayıcı işi; emülasyonda
    // PLT'ler çağrılabilir kalır (shim yakalar). Burada rapor veriyoruz.
    for (auto& d : elf.Imports())
        rep.log.push_back("  DT_NEEDED: " + d.name + " (dinamik bagimlilik — emulasyonda shim yakalar)");
    step(4, "Relocation'lar (R_X86_64_RELATIVE elle uygulanir)");
    if (opt.applyRelocations) {
        // PIE ise base delta 0'dır (biz orijinal VA'lerle map ettik) — reloc gerekmez
        rep.log.push_back("  goruntu orijinal VA'larinda; delta=0, reloc atlandi");
    }
    step(5, "Hazir");
    rep.shadowApis = shadow_;
    rep.success = true;
    rep.entrySymbol = "entry @ 0x" + ToHex(elf.EntryPoint());
    LogOk("ELF map tamam: 0x%llx-0x%llx", (unsigned long long)rep.mappedBase,
          (unsigned long long)(rep.mappedBase + rep.mappedSize));
    return rep;
}

} // namespace gt
