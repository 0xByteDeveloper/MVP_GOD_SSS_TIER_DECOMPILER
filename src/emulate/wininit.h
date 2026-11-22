// ============================================================================
//  i4M GodTier Engine — emulate/wininit.h
//  DEVRİT TIER-5a: WİNINIT — Windows process-initialization benzetimi.
//
//  Kullanıcının öngörüsü ("Windows exe açılınca ne yapıyorsa aynısını
//  simüle edelim: yığını, TLS'i, CRT init'i, handle'ları") Tier-3'ün yanına
//  EK ARAÇ olarak inşa edildi. Windows process başlangıcının gerçek sırası:
//    [1] kernel: süreç nesnesi + adres alanı + PEB (bizim: MappedImage+PEB)
//    [2] kernel: ilk thread + 1 MB ayrılmış yığın (bizim: Emulator stack)
//    [3] ntdll Ldr: statik import çözümü (bizim: shadow-IAT, Mapper'dan)
//    [4] TLS: __tls_index yazımı + TLS callback'ler (Reason=PROCESS_ATTACH)
//        — EP'DEN ÖNCE koşar (Windows bunu yapar; statik tarayıcılar GÖREMEZ)
//    [5] EP: CRT init (security cookie, _initterm, global kurucular) → WinMain
//        — bizim: Unicorn'da gerçek yürütme, DUVAR API'sinde temiz duruş
//    [6] DUVAR: mesaj döngüsü / ağ / pencere — oyun mantığı kullanıcı ve
//        sunucu ister; burada dürüstçe dururuz ve ANLIK GÖRÜNTÜ alırız
//
//  ÇIKTI: initFacts overlay (VA -> pointer-slot değeri):
//    - CRT init'in yazdığı tüm statik yuvalar (kurucu kanıtı OLMAYANLAR dahil)
//    - heap'e yazılmış vptr'ler (tekil çalıştırma gözlemi — RTTI ile doğrulanır)
//  Bu overlay DevirtPro/DevirtEmu'ya tohum olarak verilir: statik kanıt
//  YOKSA devirt artık init-anlık-görüntüsüyle çözer (proofKind="init").
//
//  KONTROLLÜLÜK: kendi MappedImage kopyası üzerinde çalışır — Shell'in
//  görüntüsüne/analizine DOKUNMAZ. Overlay verilmedikçe devirt davranışı
//  bit-bitiye aynı kalır (varsayılan: wininit çalıştırılmamış = etkisiz).
//
//  DÜRÜSTLÜK: tek deterministik yürütme (zaman/PID/rand sabit tohumlu).
//  "INIT-SNAPSHOT" bir GÖZLEMDİR; statik kanıt zinciriyle çelişirse statik
//  kanıt kazanır (DevirtPro okuma sırası: IAT > yazıcı > overlay > imaj).
// ============================================================================
#pragma once
#include "format/pe.h"
#include "format/image.h"
#include "mapper/mapper.h"
#include "analysis/msvcrtti.h"
#include "emulate/emulator.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace gt {

struct WinInitConfig {
    size_t maxInstructions = 2'000'000;    // EP bütçesi (komut)
    u64    timeoutUs       = 60'000'000;   // 60 sn
    size_t overlayMax      = 262'144;      // overlay giriş tavanı
    bool   verbose         = false;
};

struct WinInitReport {
    bool ok = false;
    std::string error;
    bool isDll = false;
    u64  entryVa = 0;

    // --- faz 4: TLS ---
    size_t tlsCallbacksTotal = 0;      // PE TLS dizinindekiler
    size_t tlsCallbacksRun = 0;
    bool   tlsPhaseRan = false;

    // --- faz 5: EP / CRT-init ---
    enum class Stop : u8 { None, Wall, Budget, Fault, Ret, Exit };
    Stop  stop = Stop::None;
    std::string stopDetail;            // duvar API adı / hata / exit kodu
    u64   stopPc = 0;
    size_t instructions = 0;
    size_t apiCalls = 0;
    size_t apiUnknown = 0;             // shim tablosunda olmayan API sayısı
    size_t stackCleanupUnknown = 0;    // stdcall bayt sayısı bulunamayan çağrı

    // --- faz 6: kanıt çıktıları ---
    size_t staticSlotsChanged = 0;     // yazılabilir bölümde değişen slot
    size_t heapVptrSlots = 0;          // heap'te vftable-benzeri değer
    size_t heapAllocs = 0;
    std::map<u64, u64> overlay;        // VA -> değer (devirt tohumları)
    std::vector<std::string> apiTail;  // teşhis: son API çağrıları (dll.func -> ret)
    std::vector<std::string> traceTail;  // teşhis (verbose): son komutlar

    const char* StopName() const;
    std::string Summary() const;
};

class WinInit {
public:
    WinInit(const PE& pe, const MsvcRtti* rtti);

    // Tüm Windows-init benzetimini koştur (kendi görüntü kopyasında)
    WinInitReport Run(Arch arch, const WinInitConfig& cfg = {});

private:
    bool SetupEnv(Arch arch, const WinInitConfig& cfg);
    bool RunTlsCallbacks(const WinInitConfig& cfg);
    void RunEntryPoint(const WinInitConfig& cfg);
    void BuildOverlay(const WinInitConfig& cfg);
    bool IsVftableLike(u64 v);
    bool IsExecVa(u64 va) const;
    bool InImage(u64 va) const;
    bool IsIatSlot(u64 va) const;
    u64  PtrSize() const { return is64_ ? 8 : 4; }

    const PE& pe_;
    const MsvcRtti* rtti_;
    Mapper mapper_;
    MappedImage wimg_;                    // wininit'e özel eşlenmiş kopya
    MapReport mapRep_{};
    std::unique_ptr<Emulator> emu_;
    WinInitReport rep_;
    bool is64_ = false;
    u64  entryVa_ = 0;
};

} // namespace gt
