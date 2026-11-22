// ============================================================================
//  i4M GodTier Engine — decomp/types.h
//  TypeInferer: IDA/Ghidra tarzı İKİ FAZLI GLOBAL TİP ANALİZİ.
//
//  Faz A (fonksiyon başına gövde taraması):
//    - argüman register'larının canlılığı (spill + okuma)  -> argüman sayısı
//    - dönüş değeri kanıtı (eax/rax, xmm0 yazımı)          -> dönüş tipi
//    - pointer kökeni (provenance) izleme: hangi register hangi argümandan
//      türedi -> bellek erişimlerini (arg + offset, boyut, tip) toplar
//  Faz B (global yayılım):
//    - çağrı grafiği: çağıran'ın geçtiği ifade <-> çağrılan'ın argümanı
//    - union-find ile "aynı nesneye bakan tüm yerler" birleştirilir
//    - >= 2 farklı offset erişimi görülen küme -> STRUCT GERİ KAZANIMI
//    - bilinen libc imzaları (printf/memset/...) ile zenginleştirme
//
//  Sonuç: her fonksiyon için (isim, arg tipleri, dönüş tipi) + struct
//  tanımları. Pseudocoder bunları Hex-Rays üslubunda imza/üye erişimi
//  olarak kullanır.
// ============================================================================
#pragma once
#include "disasm/analyzer.h"
#include "format/dwarf.h"
#include "format/pdb.h"
#include <map>
#include <set>
#include <memory>
#include <string>
#include <vector>

namespace gt {

enum class ArgKind : u8 { None, Int, Ptr, Float, Unknown };

struct StructMember {
    u64 offset = 0;
    u32 size = 0;               // 1/2/4/8 (0 = bilinmiyor)
    ArgKind kind = ArgKind::Int;
    bool isArray = false;
    u32 stride = 0;             // index'li erişim varsa adım boyu
    u64 arrayLen = 0;           // 0 = bilinmiyor (memset boyu / sayaç ipucu)
    bool isString = false;      // char dizisi kanıtı (memset/%s/strcpy)
    std::string name;           // DWARF/PDB'den gerçek ad (boş = field_XX)
    std::string typeName;       // DWARF/PDB tip metni (boş = bilinmiyor)
};

struct StructInfo {
    int id = 0;
    std::string name;                       // struct_1 ... veya DWARF gerçek adı
    std::map<u64, StructMember> members;    // offset -> üye
    bool fromDwarf = false;                 // DWARF/PDB'den giydirildi
    std::string Decl() const;               // C tanımı
    const StructMember* MemberAt(u64 off) const;
    // v6: aralık çözümü — off bir dizi üyesinin İÇİNE düşüyorsa üyeyi ve
    // eleman indeksini verir (off=0xc, üye notlar@+4 int[8] -> notlar, idx=2)
    const StructMember* MemberContaining(u64 off, u64* idxOut = nullptr) const;
};

struct FuncSig {
    u64 addr = 0;
    std::string name;
    int nArgs = 0;
    ArgKind argKinds[6] = {ArgKind::None, ArgKind::None, ArgKind::None,
                           ArgKind::None, ArgKind::None, ArgKind::None};
    int argStruct[6] = {-1, -1, -1, -1, -1, -1};   // struct küme no
    u32 argStride[6] = {};                          // int* eleman adımı
    ArgKind retKind = ArgKind::None;                // None = void
    bool variadic = false;
    bool noreturn = false;
    // DWARF/PDB kanıtı (varsa): gerçek ad/tipler
    bool fromDwarf = false;
    std::string argNames[6];
    std::string argTypeNames[6];
    std::string argStructNames[6];   // struct arg ise gerçek ad ("Ogrenci")
    std::string retTypeName;
    // ELF'te SysV (rdi,rsi,rdx,rcx,r8,r9), PE'de Win64 (rcx,rdx,r8,r9)
    static const char** ArgRegs(bool elf);
    std::string SignatureLine() const;              // "int toplama(int *a1, int a2)"
};

class TypeInferer {
public:
    explicit TypeInferer(Analyzer& az) : az_(az) {}

    // Global iki fazlı analizi koş (RunFull'dan sonra çağrılmalı)
    void Run();

    const FuncSig* SigOf(u64 funcVa) const;
    const std::vector<StructInfo>& Structs() const { return structs_; }
    // (funcVa, argIdx) site'ının struct'ı (yoksa nullptr)
    const StructInfo* StructOfArg(u64 funcVa, int argIdx) const;
    // (funcVa, stackDisp) yerel nesnesinin struct'ı
    const StructInfo* StructOfLocal(u64 funcVa, i64 rbpDisp) const;
    // imza metni (struct adlarıyla)
    std::string SignatureLine(u64 funcVa) const;

    // --- DWARF/PDB import ---
    const DwarfInfo* Dwarf() const { return dwarfValid_ ? &dwarf_ : nullptr; }
    // PDB kanalı: shell 'pdb <dosya>' komutundan beslenir (MSVC binaryler)
    void SetPdb(std::unique_ptr<PdbInfo> p) { pdb_ = std::move(p); }
    const PdbInfo* Pdb() const { return pdb_.get(); }

    // --- vtable veritabanı (Itanium ABI + PDB ??_7) ---
    struct VTable {
        u64 va = 0;
        std::string className;
        std::vector<u64> methods;       // slot i -> fonksiyon VA'sı
        std::vector<std::string> methodNames;
    };
    const std::vector<VTable>& VTables() const { return vtables_; }
    // slot k'nın kanonik metot adı (çoğunluk oyu; boş = bilinmiyor)
    std::string VirtSlotName(int slot) const;
    // slot k metotlarının dönüş tipi (DWARF kanıtından)
    ArgKind VirtSlotRet(int slot) const;
    // slot k'da sınıf listesi (ek açıklama için)
    std::string VirtSlotClasses(int slot) const;

    // --- sanal çağrı tespiti (call reg / call [reg+K]) ---
    struct VirtCall {
        int slot = 0;              // vtable slot no
        bool isArg = true;         // nesne argüman mı (a1) yoksa yerel mi
        int argIdx = 0;            // isArg ise kaçıncı arg
        i64 localDisp = 0;         // değilse nesne işaretçisinin yığın ofseti
        std::string callReg;       // metot işaretçisinin yüklendiği register
        u64 callerVa = 0;          // v5: çağıran fonksiyon (CHA tip kanıtı için)
    };
    const VirtCall* VirtCallAt(u64 callAddr) const;

    // --- v5: DEVIRTUALİZASYON ---
    // Sanal çağrıyı statik hedefe çözmeye çalışır. Üst üste stratejiler:
    //   1) Yerel nesne + kurucuda vtable saklama kanıtı (stripped bile çalışır)
    //   2) DWARF sınıf hiyerarşisi (CHA): statik tip + tüm alt sınıflar
    //      üzerinden slot implantları TEK ise çözüm kesindir
    //   3) Slot tek implant (tüm vtable'larda): spekülatif çözüm
    struct DevirtResult {
        u64 target = 0;           // çözülen hedef VA (0 = çözülemedi)
        std::string methodName;   // "Kopek::oyun" üslubu kısa ad
        std::string why;          // kanıt açıklaması (ek açıklama için)
        // v8.1: vfN SÖZLÜĞÜ — PDB'siz "vf4" adlandırmasının NE olduğunu
        // çıktıda göstermek için kanıt koordinatları (vfN = vtable slotu):
        //   vf4 = <className> vftable[<vftVa>] + slot*ptrSize -> <target>
        u64 vftVa = 0;            // kanıt vftable'ı (0 = vtable'sız çözüm)
        int slot = -1;            // vtable slot indeksi
        std::string className;    // RTTI sınıf adı
        std::string proofKind;    // "kurucu" / "atlas" / "tier-3" / "IAT" / "pencere"
    };
    DevirtResult TryDevirtualize(u64 callAddr) const;

    // v7: DEVRİT-PRO kanıtları (PE32 RTTI + singleton zincirleri).
    // Pseudocoder'ın dolaylı çağrı render'ı önce buraya bakar.
    void RegisterDevirtFact(u64 callAddr, u64 target, const std::string& name,
                            const std::string& why, u64 vftVa = 0, int slot = -1,
                            const std::string& className = "",
                            const std::string& proofKind = "");
    const DevirtResult* DevirtFactAt(u64 callAddr) const;
    bool HasDevirtFacts() const { return !devirtFacts_.empty(); }

private:
    // --- Faz A: gövde taraması ---
    struct Access { u64 off; u32 size; ArgKind kind; bool write; bool indexed; u32 stride; };
    struct SiteData {
        std::vector<Access> accesses;
        bool ptrTaken = false;
    };
    struct CallEdge {
        u64 callAddr = 0, callee = 0;
        // çağrı anındaki argüman kökenleri:
        //   argIdx -> (isLocal, localDisp | argIdx, offset)
        struct Prov { bool isLocal; i64 localDisp; int srcArg; u64 off; bool valid; };
        std::vector<Prov> argProv;   // index = arg sırası
        std::vector<bool> argIsFloat;
        std::vector<u64> argImm;     // hazır değer (0 = hazır değil)
    };
    struct BodyInfo {
        bool argAlive[6] = {};
        bool writesEax = false, writesXmm0 = false;
        std::map<int, SiteData> argSites;         // argIdx -> erişimler
        std::map<i64, SiteData> localSites;       // rbp/rsp disp -> erişimler (nesne)
        std::vector<CallEdge> calls;
        std::set<i64> stackObjects;               // lea rax,[rbp-X] ile adresi alınanlar
    };
    BodyInfo ScanBody(u64 funcVa);

    // --- DWARF entegrasyonu ---
    void ImportDwarfStructs();   // struct giydirme (imzalardan önce)
    void ImportDwarfSigs();      // imza zenginleştirme (imzalardan sonra)
    // v6: DWARF tanımından AUTHORITATIVE StructInfo kur (parametre tipi
    // struct* ise heuristik buluşu DEVRALIR — yanlış FILE/struct_N giydirmeyi ezer)
    int EnsureDwarfStruct(const DwarfStruct* ds);
    // --- PDB entegrasyonu (DWARF ile aynı iki aşama) ---
    void ImportPdbStructs();
    void ImportPdbSigs();
    // --- vtable ---
    void BuildVTables();
    void DetectVirtualCalls(const std::map<u64, BodyInfo>& bodies);
    void BuildClassHierarchy();          // v5: alt sınıf haritası (DWARF kalıtım)
    const VTable* VTableOfClass(const std::string& className) const;
    void CollectDescendants(const std::string& cls, std::set<std::string>& out) const;
    // v5: kurucuda vtable saklama kanıtı: localDisp -> somut sınıf
    std::map<std::pair<u64, i64>, std::string> vtableStores_;
    std::map<std::string, std::set<std::string>> children_;   // taban -> alt sınıflar

    // --- union-find ---
    struct NodeKey { u64 func; bool isLocal; int arg; i64 disp;
                     bool operator<(const NodeKey& o) const {
                         return func != o.func ? func < o.func :
                                isLocal != o.isLocal ? isLocal < o.isLocal :
                                arg != o.arg ? arg < o.arg : disp < o.disp; } };
    int Find(int x);
    void Unite(int a, int b);

    Analyzer& az_;
    std::map<u64, FuncSig> sigs_;
    std::vector<StructInfo> structs_;
    std::map<NodeKey, int> nodeId_;         // site -> küme no
    std::vector<int> parent_;
    // küme no -> erişim birleşimi (Faz B'de doldurulur)
    struct AggMember { StructMember m; };
    std::map<int, std::map<u64, StructMember>> agg_;
    std::map<int, bool> aggPtrTaken_;
    std::map<int, int> rootToStruct_;       // union-find kökü -> struct no
    // DWARF + vtable + sanal çağrı
    DwarfInfo dwarf_;
    bool dwarfValid_ = false;
    std::unique_ptr<PdbInfo> pdb_;
    std::vector<VTable> vtables_;
    std::map<u64, VirtCall> virtCalls_;     // call adresi -> sanal çağrı
    std::map<u64, DevirtResult> devirtFacts_;  // v7: devirt-pro kanıtları
};

} // namespace gt
