// ============================================================================
//  i4M GodTier Engine — emulate/apishim.cpp
// ============================================================================
#include "emulate/apishim.h"
#include "emulate/emulator.h"
#include "core/log.h"
#include "core/util.h"
#include <cstring>
#include <cstdio>

namespace gt {
namespace {

// emülatör belleğinden null-sonlu string oku (max 260)
std::string ReadStr(const ApiShim& shim, u64 va, size_t maxLen = 260) {
    if (!va || !shim.readMem) return "";
    std::vector<u8> buf(maxLen + 1, 0);
    if (!shim.readMem(va, buf.data(), maxLen)) return "";
    buf[maxLen] = 0;
    return std::string((const char*)buf.data());
}

bool WriteU32(const ApiShim& shim, u64 va, u32 v) {
    return shim.writeMem && shim.writeMem(va, (const u8*)&v, 4);
}
bool WriteU64(const ApiShim& shim, u64 va, u64 v) {
    return shim.writeMem && shim.writeMem(va, (const u8*)&v, 8);
}
bool WriteU16(const ApiShim& shim, u64 va, u16 v) {
    return shim.writeMem && shim.writeMem(va, (const u8*)&v, 2);
}
bool WriteU8(const ApiShim& shim, u64 va, u8 v) {
    return shim.writeMem && shim.writeMem(va, &v, 1);
}

// deterministik çevre sabitleri (WinInit sözleşmesi — wininit.cpp ile aynı)
constexpr u64 kFakeHeapHandle_ = 0x00AB1000ull;
constexpr u32 kFakeTick_ = 0x11223344;
constexpr u64 kFakeQpc_ = 0x1234567890ull;
constexpr u64 kFakeFileTime_ = 0x01DB000000000000ull;
u64 kFakeHeapHandleFor() { return kFakeHeapHandle_; }
u32 kFakeTickFor() { return kFakeTick_; }
u64 kFakeQpcFor() { return kFakeQpc_; }
u64 kFakeFileTimeFor() { return kFakeFileTime_; }
u64 pe_ImageBase_Fallback() { return 0; }

// Win32 stdcall argüman bayt tablosu — WinInit duvar/init yollarının
// kalabalığı (Qiling prototip-DB fikrinin el yapımı MVP'si; olmayan API
// cdecl kabul edilir ve raporlanır — sessiz yanlış YOK)
struct StdcallEntry { const char* n; u32 bytes; };
const StdcallEntry kStdcall[] = {
    // heap / bellek
    {"heapcreate", 12}, {"heapdestroy", 4}, {"heapalloc", 12}, {"heapfree", 12},
    {"heaprealloc", 16}, {"heapsize", 12}, {"heapvalidate", 16}, {"heapcompact", 8},
    {"heaplock", 4}, {"heapunlock", 4}, {"heapsetinformation", 16},
    {"heapqueryinformation", 20}, {"getprocessheap", 0},
    {"virtualalloc", 16}, {"virtualfree", 12}, {"virtualprotect", 16},
    {"virtualquery", 12}, {"virtuallock", 8}, {"virtualunlock", 8},
    {"globalalloc", 8}, {"globalfree", 4}, {"globallock", 4}, {"globalunlock", 4},
    {"globalhandle", 4}, {"globalrealloc", 12}, {"globalsize", 4},
    {"localalloc", 8}, {"localfree", 4}, {"locallock", 4}, {"localunlock", 4},
    {"localrealloc", 12}, {"localsize", 4}, {"localhandle", 4},
    // modül / proc
    {"getmodulehandlea", 4}, {"getmodulehandlew", 4},
    {"getmodulehandleexa", 8}, {"getmodulehandleexw", 8},
    {"getmodulefilenamea", 12}, {"getmodulefilenamew", 12},
    {"getprocaddress", 8}, {"loadlibrarya", 4}, {"loadlibraryw", 4},
    {"loadlibraryexa", 12}, {"loadlibraryexw", 12},
    {"freelibrary", 4}, {"freelibraryandexitthread", 8},
    // süreç / thread
    {"exitprocess", 4}, {"exitthread", 4}, {"terminateprocess", 8},
    {"createthread", 24}, {"createthreadex", 44}, {"resumethread", 4},
    {"suspendthread", 4}, {"terminatethread", 8}, {"getexitcodethread", 8},
    {"getexitcodeprocess", 8}, {"getcurrentprocess", 0}, {"getcurrentthread", 0},
    {"getcurrentprocessid", 0}, {"getcurrentthreadid", 0},
    {"getprocessaffinitymask", 12}, {"setprocessaffinitymask", 8},
    {"setthreadaffinitymask", 8}, {"getthreadpriority", 4},
    {"setthreadpriority", 8}, {"switchtothread", 0},
    // zaman
    {"sleep", 4}, {"sleepex", 8}, {"gettickcount", 0}, {"gettickcount64", 0},
    {"getsystemtime", 4}, {"getlocaltime", 4}, {"getsystemtimeasfiletime", 4},
    {"queryperformancecounter", 4}, {"queryperformancefrequency", 4},
    {"timegettime", 0}, {"timebeginperiod", 4}, {"timeendperiod", 4},
    // sürüm / bilgi
    {"getversion", 0}, {"getversionexa", 4}, {"getversionexw", 4},
    {"isdebuggerpresent", 0}, {"checkremotedebuggerpresent", 8},
    {"isprocessorfeaturepresent", 4}, {"getsysteminfo", 4},
    {"getnative.systeminfo", 4}, {"getproductinfo", 16},
    // dosya
    {"createfilea", 28}, {"createfilew", 28}, {"readfile", 20}, {"writefile", 20},
    {"closehandle", 4}, {"getfiletype", 4}, {"setfilepointer", 16},
    {"setfilepointerex", 20}, {"flushfilebuffers", 4}, {"getfilesize", 8},
    {"getfilesizeex", 8}, {"getfileattributesa", 4}, {"getfileattributesw", 4},
    {"getfileattributesexa", 12}, {"getfileattributesexw", 12},
    {"findfirstfilea", 8}, {"findfirstfilew", 8}, {"findnextfilea", 8},
    {"findnextfilew", 8}, {"findclose", 4}, {"deletedirectorya" , 4},
    {"createdirectorya", 8}, {"createdirectoryw", 8},
    {"removedirectorya", 4}, {"removedirectoryw", 4},
    {"movefilea", 8}, {"copyfilea", 12}, {"deletefilea", 4}, {"deletefilew", 4},
    {"getdiskfreespaceexa", 16}, {"getdiskfreespaceexw", 16},
    {"getlogicaldrivestringsa", 8}, {"getlogicaldrivestringsw", 8},
    {"getfinalpathnamebyhandlea", 16}, {"setfiletime", 16},
    // konsol / std
    {"getstdhandle", 4}, {"sethandlecount", 4}, {"writeconsolea", 20},
    {"writeconsolew", 20}, {"readconsolea", 20}, {"readconsolew", 20},
    {"setconsolectrlhandler", 8}, {"getconsolemode", 8}, {"setconsolemode", 8},
    {"getnumberofconsoleinputevents", 8},
    // yerel ayar / kod sayfası
    {"getacp", 0}, {"getoemcp", 0}, {"getcpinfo", 8}, {"getcpinfoexa", 12},
    {"getlocaleinfoa", 16}, {"getlocaleinfow", 16},
    {"getuserdefaultlcid", 0}, {"getsystemdefaultlcid", 0},
    {"getuserdefaultlangid", 0}, {"getsystemdefaultlangid", 0},
    {"getuserdefaultuilanguage", 0}, {"getsystemdefaultuilanguage", 0},
    {"enumsystemlocalesa", 12}, {"isvalidlocale", 8},
    {"comparestringa", 24}, {"comparestringw", 24},
    {"lctomapstringa", 24}, {"foldstringa", 20},
    // ortam
    {"getenvironmentstringsa", 0}, {"getenvironmentstringsw", 0},
    {"freeenvironmentstringsa", 4}, {"freeenvironmentstringsw", 4},
    {"getenvironmentvariablea", 12}, {"getenvironmentvariablew", 12},
    {"setenvironmentvariablea", 8}, {"expandenvironmentstringsa", 16},
    // TLS/FLS + senkron
    {"tlsalloc", 0}, {"tlsgetvalue", 4}, {"tlssetvalue", 8}, {"tlsfree", 4},
    {"flsalloc", 4}, {"flsgetvalue", 4}, {"flssetvalue", 8}, {"flsfree", 4},
    {"initializesrwlock", 4}, {"acquiresrwlockexclusive", 4},
    {"releasesrwlockexclusive", 4}, {"acquiresrwlockshared", 4},
    {"releasesrwlockshared", 4}, {"tryacquiresrwlockexclusive", 4},
    {"tryacquiresrwlockshared", 4},
    {"wakeconditionvariable", 4}, {"wakeallconditionvariable", 4},
    {"sleepconditionvariablecs", 16}, {"sleepconditionvariablesrw", 24},
    {"initializecriticalsection", 4}, {"deletecriticalsection", 4},
    {"entercriticalsection", 4}, {"leavecriticalsection", 4},
    {"initializecriticalsectionandspincount", 8},
    {"setcriticalsectionspincount", 8}, {"tryentercriticalsection", 4},
    {"initonceexecuteonce", 16}, {"initoncebegininitialize", 16},
    {"initoncecomplete", 12},
    {"initializecriticalsectionex", 12},
    {"waitforonaddress", 16}, {"wakebyaddressall", 4},
    {"wakebyaddresssingle", 4},
    {"waitforsingleobject", 8}, {"waitforsingleobjectex", 12},
    {"waitformultipleobjects", 16}, {"waitformultipleobjectsex", 20},
    {"signalobjectandwait", 16},
    {"createmutexa", 12}, {"createmutexw", 12}, {"releasemutex", 4},
    {"createeventa", 16}, {"createeventw", 16}, {"setevent", 4}, {"resetevent", 4},
    {"createsemaphorea", 16}, {"releasesemaphore", 12},
    {"openeventa", 12},
    // hata / istisna
    {"getlasterror", 0}, {"setlasterror", 4}, {"formatmessagea", 28},
    {"formatmessagew", 28}, {"seterrormode", 4},
    {"setunhandledexceptionfilter", 4}, {"unhandledexceptionfilter", 4},
    {"rtladdfunctiontable", 16}, {"rtlremovefunctiontable", 8},
    {"rtlunwind", 20},
    // kayıt defteri
    {"regopenkeyexa", 20}, {"regopenkeyexw", 20}, {"regclosekey", 4},
    {"regqueryvalueexa", 24}, {"regqueryvalueexw", 24},
    {"regcreatekeyexa", 36}, {"regsetvalueexa", 24},
    {"regenumkeyexa", 28}, {"regdeletekeya", 8},
    // pencere / mesaj (duvar ailesi — çağrılırsa zaten dururuz; doğruluk için)
    {"getmessagea", 16}, {"getmessagew", 16}, {"peekmessagea", 20},
    {"peekmessagew", 20}, {"translatemessage", 4}, {"dispatchmessagea", 4},
    {"dispatchmessagew", 4}, {"postquitmessage", 4}, {"postmessagea", 16},
    {"sendmessagea", 16}, {"sendmessagew", 16},
    {"messageboxa", 16}, {"messageboxw", 16}, {"messagebeep", 4},
    {"registerclassa", 4}, {"registerclassw", 4}, {"registerclassexw", 4},
    {"unregisterclassa", 8}, {"createwindowexa", 48}, {"createwindowexw", 48},
    {"destroywindow", 4}, {"showwindow", 8}, {"updatewindow", 4},
    {"getdc", 4}, {"releasedc", 8}, {"defwindowproca", 20},
    {"defwindowprocw", 20}, {"getwindowrect", 8}, {"invalidaterect", 16},
    {"getsystemmetrics", 4}, {"adjustwindowrect", 12},
    {"setwindowpos", 28}, {"beginpaint", 8}, {"endpaint", 8},
    {"getkeyboardstate", 4}, {"getkeystate", 4}, {"getasynckeystate", 4},
    {"settimer", 16}, {"killtimer", 8}, {"getcursorpos", 4},
    // ağ (duvar ailesi)
    {"wsastartup", 8}, {"wsacleanup", 0}, {"wsagetlasterror", 0},
    {"socket", 12}, {"connect", 12}, {"closesocket", 4}, {"send", 16},
    {"sendto", 24}, {"recv", 16}, {"recvfrom", 24}, {"select", 20},
    {"bind", 12}, {"listen", 8}, {"accept", 12}, {"shutdown", 8},
    {"ioctlsocket", 12}, {"gethostbyname", 4}, {"getpeername", 12},
    {"getsockname", 12}, {"setsockopt", 20}, {"getsockopt", 20},
    {"htons", 4}, {"htonl", 4}, {"ntohs", 4}, {"ntohl", 4},
    {"inet_addr", 4}, {"inet_ntoa", 4}, {"wsasocket", 24},
    // süreç başlatma (duvar ailesi)
    {"createprocessa", 40}, {"createprocessw", 40},
    {"shellexecutea", 24}, {"shellexecutew", 24}, {"winexec", 8},
    // gdi / diğer
    {"getdcex", 12}, {"createdca", 16}, {"createcompatibledc", 4},
    {"deletedc", 4}, {"deleteobject", 4}, {"getstockobject", 4},
    {"selectobject", 8}, {"setpixel", 16}, {"getdevicecaps", 8},
    {"gettextmetricsa", 8}, {"gettextextentpoint32a", 16},
    {"coinitialize", 4}, {"couninitialize", 0}, {"cotaskmemalloc", 4},
    {"cotaskmemfree", 4}, {"sysfreestring", 4},
    {"lstrlena", 0}, {"lstrlenw", 0}, {"lstrcmpia", 8}, {"lstrcmpiw", 8},
    {"lstrcpya", 8}, {"lstrcpynw", 12},
    {"outputdebugstringa", 4}, {"outputdebugstringw", 4},
    {"getcomputernamea", 8}, {"getcomputernameexa", 12},
    {"getusernamea", 8}, {"getusernameexa", 16},
    {"interlockedincrement", 4}, {"interlockeddecrement", 4},
    {"interlockedexchange", 8}, {"interlockedcompareexchange", 12},
    {"initializeprocessforall", 0},
    {"getcurrentactctx", 4}, {"activateactctx", 8},
    {"queryactctxw", 20}, {"deactivateactctx", 8},
    {"addrefactctx", 4}, {"releaseactctx", 4},
    {"findresourcea", 12}, {"findresourcew", 12}, {"loadresource", 8},
    {"lockresource", 4}, {"sizeofresource", 8}, {"freeresource", 4},
    {"beginupdateresourcea", 12}, {"updateresourcea", 28},
    {"getstartupinfoa", 4}, {"getstartupinfow", 4},
    {"lockfile", 20}, {"unlockfile", 20}, {"lockfileex", 24},
    {"flushviewoffile", 8}, {"mapviewoffile", 24}, {"mapviewoffileex", 28},
    {"unmapviewoffile", 4}, {"createfilemappinga", 24}, {"openfilemappinga", 12},
    {"setendoffile", 4}, {"getfileinformationbyhandle", 8},
    {"getfileinformationbyhandleex", 16},
    {"setfileinformationbyhandle", 16},
    {"setfilevaliddata", 12}, {"setfileshortnamea", 12},
    {"queryperformancecounter", 4},
    {"getvolumeinformationa", 32}, {"getvolumemountpointa", 12},
    {"createtoolhelp32snapshot", 8},
    {"process32first", 8}, {"process32next", 8},
    {"thread32first", 8}, {"thread32next", 8},
    {"module32first", 8}, {"module32next", 8},
    {"openprocess", 12}, {"openprocesstoken", 12},
    {"gettokeninformation", 20}, {"adjusttokenprivileges", 24},
    {"lookupprivilegevaluea", 12}, {"initiateshutdown", 24},
    {"getuserobjectinformationa", 20},
    {"msgwaitformultipleobjects", 20},
    {"msgwaitformultipleobjectsex", 24},
    {"waitforinputidle", 8}, {"gettickedcount64", 0},
    {"setthreadpooltimer" , 16}, {"closethreadpooltimer", 4},
    {"createthreadpooltimer", 12}, {"waitforthreadpooltimercallbacks", 8},
    {"closethreadpoolwait", 4}, {"createthreadpoolwait", 12},
    {"setthreadpoolwait", 16}, {"createthreadpoolwork", 4},
    {"submittreadpoolwork", 8}, {"closethreadpoolwork", 4},
    {"trysubmitthreadpoolcallback", 16},
    {"registerwaitforsingleobject", 24},
    {"unregisterwait", 4}, {"unregisterwaitex", 8},
    {"queueuserworkitem", 12}, {"queueuserapc", 8},
    {"createntmsmediaa", 20}, {"getlastactivepopup", 4},
    {"getprocesswindowstation", 0}, {"getthreaddesktop", 4},
    {"getuserobjectsecurity", 20}, {"impersonateself", 4},
};

} // namespace

u32 ApiShim::Win32StdcallBytes(const std::string& lowerFunc) {
    for (auto& e : kStdcall)
        if (lowerFunc == e.n) return e.bytes;
    return 0xFFFFFFFFu;    // tabloda yok (çağıran taraf cdecl-probe ile karar verir)
}

void ApiShim::SetWallMode() {
    wallMode_ = true;
    wallHit_ = false;
    wallApiName_.clear();
    // duvar-API'leri: oyun mantığı / kullanıcı bekleme / ağ / pencere —
    // init kanıtı için daha ileri gitmek anlamsız VE dürüst değil
    wallApis_ = {
        "getmessagea", "getmessagew", "peekmessagea", "peekmessagew",
        "waitmessage", "msgwaitformultipleobjects", "msgwaitformultipleobjectsex",
        "sleep", "sleepex", "waitforsingleobject", "waitforsingleobjectex",
        "waitformultipleobjects", "waitformultipleobjectsex", "waitforinputidle",
        "signalobjectandwait", "sleepconditionvariablecs",
        "sleepconditionvariablesrw",
        "waitforonaddress",
        "connect", "wsastartup", "socket", "select", "send", "sendto",
        "recv", "recvfrom", "accept", "listen", "bind", "shutdown",
        "messageboxa", "messageboxw", "messagebeep", "fatalappexit",
        "createwindowexa", "createwindowexw", "createdialogparama",
        "createdialogparamw", "dialogboxparama", "dialogboxparamw",
        "createprocessa", "createprocessw", "shellexecutea", "shellexecutew",
        "winexec", "showwindow", "setwindowpos",
    };
}

u64 ApiShim::Handle(Emulator& emu, const std::string& dll, const std::string& func,
                    const u64 args[4], u64 rsp, u64& retAddr, bool& stopEmu) {
    (void)emu;
    retAddr = 0;
    if (readMem) {
        // v9.2 DÜZELTME: dönüş adresi mimariye göre okunur — x86-32'de 4 bayt.
        // (önceden hep 8 bayt okunuyordu: arg1 retAddr'e taşıp EIP'ı zehirliyordu)
        u8 tmp[8] = {};
        size_t ps = emu.GetArch() == Arch::X86_64 ? 8 : 4;
        if (readMem(rsp, tmp, ps))
            memcpy(&retAddr, tmp, ps);
    }

    std::string lname = ToLower(func);

    // ---- v9.2 DUVAR: oyun mantığına girdik — dürüstçe dur -----------------
    if (wallMode_ && wallApis_.count(lname)) {
        ApiCall call;
        call.dll = dll; call.func = func;
        for (int i = 0; i < 4; i++) call.args[i] = args[i];
        call.caller = retAddr;
        call.note = "DUVAR — oyun mantigi (init kaniti burada durur)";
        if (calls_.size() < logLimit_) calls_.push_back(call);
        wallHit_ = true;
        wallApiName_ = dll + "." + func;
        stopEmu = true;
        return 0;
    }

    ApiCall call;
    call.dll = dll; call.func = func;
    for (int i = 0; i < 4; i++) call.args[i] = args[i];
    call.caller = retAddr;
    u64 ret = 0;

    // ------------------------------------------------------------------
    // Yaygın API'ler için gerçekçi davranış
    // ------------------------------------------------------------------
    if (lname == "exitprocess" || lname == "exitthread" ||
        lname == "terminateprocess" || lname == "fatalappexita") {
        call.note = "process sonlandirildi (kod=" + std::to_string((u32)args[0]) + ")";
        stopEmu = true;
        ret = 0;
    }
    else if (lname == "heapalloc") {
        size_t sz = (size_t)args[2];
        ret = allocHeap ? allocHeap(sz) : 0;
        call.note = "size=" + std::to_string(sz) + " -> 0x" + ToHex(ret);
    }
    else if (lname == "heapfree" || lname == "heapdestroy" ||
             lname == "heaplock" || lname == "heapunlock" ||
             lname == "heapcompact" || lname == "heapvalidate" ||
             lname == "heapsetinformation" || lname == "heapqueryinformation" ||
             lname == "heapwalk") {
        ret = 1; // başarı
    }
    else if (lname == "heapcreate") {
        ret = kFakeHeapHandleFor();
        call.note = "sahte heap handle (CRT malloc bunun üstünde çalışır)";
    }
    else if (lname == "getprocessheap") {
        ret = kFakeHeapHandleFor();
    }
    else if (lname == "globalalloc" || lname == "localalloc") {
        // (uFlags, dwBytes) — x64'te args[1], x86 stdcall'da args[1]
        size_t sz = (size_t)args[1];
        ret = allocHeap ? allocHeap(sz) : 0;
        call.note = "size=" + std::to_string(sz) + " -> 0x" + ToHex(ret);
    }
    else if (lname == "globalfree" || lname == "localfree" ||
             lname == "globalunlock" || lname == "localunlock" ||
             lname == "globalrealloc" || lname == "localrealloc") {
        ret = 1;
    }
    else if (lname == "globallock" || lname == "locallock" || lname == "globalhandle") {
        ret = args[0]; // bloğun kendisi (GMEM_FIXED varsayımı)
    }
    else if (lname == "virtualalloc" || lname == "mapviewoffile" ||
             lname == "mapviewoffileex" || lname == "createfilemappinga" ||
             lname == "createfilemappingw" || lname == "virtualallocex") {
        size_t sz = (size_t)args[1];
        ret = allocHeap ? allocHeap(sz ? sz : 0x1000) : 0;
        call.note = "size=0x" + ToHex((u64)sz) + " -> 0x" + ToHex(ret);
    }
    else if (lname == "virtualfree" || lname == "virtualprotect" ||
             lname == "unmapviewoffile" || lname == "virtuallock" ||
             lname == "virtualunlock" || lname == "flushviewoffile" ||
             lname == "closehandle" || lname == "freelibrary" ||
             lname == "setevent" || lname == "resetevent" ||
             lname == "releasemutex" || lname == "releasesemaphore" ||
             lname == "releasesrwlockexclusive" || lname == "releasesrwlockshared") {
        ret = 1;
    }
    else if (lname == "getmodulehandlea" || lname == "getmodulehandlew" ||
             lname == "getmodulehandleexa" || lname == "getmodulehandleexw") {
        std::string name = ReadStr(*this, args[0]);
        if (name.empty() || (lname.size() > 2 && name == "0")) {
            // NULL → exe'nin kendisi: GERÇEK ImageBase (v9.2)
            ret = imageBaseOverride ? imageBaseOverride : pe_ImageBase_Fallback();
            if (!ret) {
                fakeHandleCounter_ += 0x10000;
                moduleHandles_[""] = fakeHandleCounter_;
                ret = fakeHandleCounter_;
            }
            call.note = "(exe kendisi, ImageBase)";
        } else {
            std::string key = ToLower(name);
            auto it = moduleHandles_.find(key);
            if (it == moduleHandles_.end()) {
                fakeHandleCounter_ += 0x10000;
                moduleHandles_[key] = fakeHandleCounter_;
                it = moduleHandles_.find(key);
            }
            ret = it->second;
            call.note = name;
        }
    }
    else if (lname == "loadlibraryexa" || lname == "loadlibraryexw") {
        // statik UCRT açılışta api-ms-win-crt-* / vcruntime yükleme dener —
        // BAŞARISIZLIK CRT'yi erken çıkışa sokar. Sahte modul handle döndür
        // (gerçek DLL kodu YÜKLENMEZ; içe aktarımları zaten exe'nin IAT'ında)
        std::string name = ReadStr(*this, args[0]);
        std::string key = "ex:" + ToLower(name);
        auto it = moduleHandles_.find(key);
        if (it == moduleHandles_.end()) {
            fakeHandleCounter_ += 0x10000;
            moduleHandles_[key] = fakeHandleCounter_;
            it = moduleHandles_.find(key);
        }
        ret = it->second;
        call.note = name.empty() ? "(exe)" : (name + " -> sahte handle");
    }
    else if (lname == "getprocaddress") {
        // rcx = module, rdx = proc name (string ya da ordinal)
        std::string name = ReadStr(*this, args[1]);
        std::string key = ToLower(name);
        auto it = procAddresses_.find(key);
        if (it == procAddresses_.end()) {
            // v9.2: CAĞRILABİLİR stub üret (statik UCRT dönen adresi ÇAĞIRIYOR —
            // sahte sayı dönersek 0xACxxxx'e düşüp çöküyor)
            u64 stub = makeDynStub ? makeDynStub(dll, name) : 0;
            if (!stub) {
                fakeHandleCounter_ += 0x100;
                stub = fakeHandleCounter_;
            }
            procAddresses_[key] = stub;
            it = procAddresses_.find(key);
        }
        ret = it->second;
        call.note = name + (makeDynStub ? " (dinamik stub)" : "");
    }
    else if (lname == "isdebuggerpresent") {
        ret = 0; // Anti-debug: her zaman temiz — GOD mod
        call.note = "false (temiz)";
    }
    else if (lname == "checkremotedebuggerpresent") {
        if (writeMem) WriteU32(*this, args[1], 0);
        ret = 1;
        call.note = "false (temiz)";
    }
    else if (lname == "getversion" || lname == "getversionexa" || lname == "getversionexw") {
        ret = 0x0A000004; // Win10 benzeri 10.0 major
        call.note = "Windows 10 sahtesi";
    }
    else if (lname == "messageboxa" || lname == "messageboxw") {
        std::string text = ReadStr(*this, args[1]);
        std::string caption = ReadStr(*this, args[2]);
        call.note = "\"" + (text.size() > 60 ? text.substr(0, 60) + "..." : text) +
                    "\" / \"" + caption + "\"";
        if (out) out("[MessageBox] " + text + (caption.empty() ? "" : "  (caption: " + caption + ")"));
        ret = 1; // IDOK
    }
    else if (lname == "outputdebugstringa" || lname == "outputdebugstringw") {
        std::string text = ReadStr(*this, args[0]);
        call.note = text;
        if (out && !text.empty()) out("[OutputDebugString] " + text);
        ret = 0;
    }
    else if (lname == "getlasterror" || lname == "wsagetlasterror") { ret = 0; }
    else if (lname == "setlasterror") { call.note = "dwError=" + ToHex(args[0]); ret = 0; }
    else if (lname == "lstrlena" || lname == "lstrlenw" || lname == "strlen" ||
             lname == "lstrlena" || lname == "wcslen") {
        std::string s = ReadStr(*this, args[0], 4096);
        ret = lname == "lstrlenw" || lname == "wcslen" ? s.size() / 2 : s.size();
    }
    else if (lname == "getcommandlinea" || lname == "getcommandlinew") {
        ret = allocHeap ? allocHeap(64) : 0;
        if (ret && readMem) {
            const char* cmd = "\"godtier_wininit.exe\"";
            if (lname == "getcommandlinew") {
                std::vector<u8> w;
                for (const char* p = cmd; *p; p++) { w.push_back((u8)*p); w.push_back(0); }
                w.push_back(0); w.push_back(0);
                readMem(ret, w.data(), w.size());
            } else {
                readMem(ret, (u8*)cmd, strlen(cmd) + 1);
            }
        }
        call.note = "sabit komut satırı (determinizm)";
    }
    else if (lname == "getstartupinfoa" || lname == "getstartupinfow") {
        // STARTUPINFO doldur: cb, wShowWindow=SW_SHOWNORMAL — CRT __getstartinfo
        if (writeMem) {
            WriteU32(*this, args[0] + 0x00, 0x44);      // cb (68)
            WriteU32(*this, args[0] + 0x28, 1);         // wShowWindow
        }
        call.note = "cb=68, wShowWindow=SW_SHOWNORMAL";
        ret = 0;
    }
    else if (lname == "getsysteminfo") {
        if (writeMem) {
            WriteU16(*this, args[0] + 0x00, 0);          // wProcessorArchitecture (x86)
            WriteU32(*this, args[0] + 0x04, 0x1000);     // dwPageSize
            WriteU64(*this, args[0] + 0x08, 0x10000);    // lpMinimumApplicationAddress
            WriteU64(*this, args[0] + 0x10, 0x7FFEFFFF); // lpMaximumApplicationAddress
            WriteU64(*this, args[0] + 0x18, 1);          // dwActiveProcessorMask
            WriteU32(*this, args[0] + 0x20, 1);          // dwNumberOfProcessors
            WriteU32(*this, args[0] + 0x24, 586);        // dwProcessorType
        }
        call.note = "1 CPU, x86";
        ret = 0;
    }
    else if (lname == "isprocessorfeaturepresent") { ret = 1; call.note = "her özellik VAR"; }
    else if (lname == "getprocessaffinitymask") {
        if (writeMem) { WriteU64(*this, args[1], 1); WriteU64(*this, args[2], 1); }
        ret = 1;
    }
    else if (lname == "getsystemtimeasfiletime") {
        if (writeMem) WriteU64(*this, args[0], kFakeFileTimeFor());
        call.note = "sabit FILETIME (determinizm)";
        ret = 0;
    }
    else if (lname == "queryperformancecounter") {
        if (writeMem) WriteU64(*this, args[0], kFakeQpcFor());
        ret = 1;
    }
    else if (lname == "queryperformancefrequency") {
        if (writeMem) WriteU64(*this, args[0], 10'000'000ull);
        ret = 1;
    }
    else if (lname == "gettickcount" || lname == "timegettime") { ret = kFakeTickFor(); }
    else if (lname == "gettickcount64") { ret = kFakeTickFor(); }
    else if (lname == "getsystemtime" || lname == "getlocaltime") {
        if (writeMem) {
            // SYSTEMTIME: y2026-01-01 00:00:00, sabit
            WriteU16(*this, args[0] + 0x00, 2026);
            WriteU16(*this, args[0] + 0x02, 1);   // ay
            WriteU16(*this, args[0] + 0x04, 4);   // haftanın günü
            WriteU16(*this, args[0] + 0x06, 1);   // gün
            for (int i = 0; i < 6; i++) WriteU16(*this, args[0] + 0x08 + i * 2, 0);
        }
        ret = 0;
    }
    else if (lname == "getcurrentprocessid") { ret = 0x1A2B; call.note = "sabit PID"; }
    else if (lname == "getcurrentthreadid") { ret = 0x1A2C; call.note = "sabit TID"; }
    else if (lname == "getcurrentprocess") { ret = (u64)-1; call.note = "pseudo handle"; }
    else if (lname == "getcurrentthread") { ret = (u64)-2; call.note = "pseudo handle"; }
    else if (lname == "getstdhandle") { ret = 0x00AB2000 + (u32)args[0]; call.note = "sahte std handle"; }
    else if (lname == "sethandlecount") { ret = 32; }
    else if (lname == "getfiletype") { ret = 0; call.note = "bilinmeyen tip (konsol değil)"; }
    else if (lname == "setfilepointer" || lname == "setfilepointerex") { ret = 0; }
    else if (lname == "readfile" || lname == "readfileex") {
        if (writeMem && args[3]) WriteU32(*this, args[3], 0);  // lpNumberOfBytesRead=0
        ret = 0; call.note = "okuma başarısız (dosya yok — deterministik)";
    }
    else if (lname == "writefile" || lname == "writefileex") {
        if (writeMem && args[3]) WriteU32(*this, args[3], (u32)args[2]);
        ret = 1; call.note = "yazma yutuldu";
    }
    else if (lname == "createfilea" || lname == "createfilew" ||
             lname == "openfilea" || lname == "lopen") {
        std::string name = ReadStr(*this, args[0]);
        ret = (u64)-1;   // INVALID_HANDLE_VALUE: dosya yok (deterministik)
        call.note = "\"" + name + "\" -> YOK";
    }
    else if (lname == "getfileattributesa" || lname == "getfileattributesw" ||
             lname == "getfileattributesexa" || lname == "getfileattributesexw") {
        ret = 0xFFFFFFFF;  // INVALID_FILE_ATTRIBUTES
    }
    else if (lname == "getfilesize" || lname == "getfilesizeex") {
        if (lname == "getfilesizeex" && writeMem) WriteU64(*this, args[1], 0);
        ret = 0;
    }
    else if (lname == "getvolumeinformationa" || lname == "getvolumeinformationw") { ret = 0; }
    else if (lname == "getacp") { ret = 1252; }
    else if (lname == "getoemcp") { ret = 437; }
    else if (lname == "getcpinfo" || lname == "getcpinfoexa") {
        if (writeMem) {
            WriteU32(*this, args[1] + 0x00, 1);       // MaxCharSize
            WriteU8(*this, args[1] + 0x04, 1);        // bLeadByte[0]=1? — tek bayt kod sayfası
        }
        ret = 1;
    }
    else if (lname == "getlocaleinfoa" || lname == "getlocaleinfow") { ret = 0; }
    else if (lname == "getuserdefaultlcid" || lname == "getsystemdefaultlcid") { ret = 0x0409; }
    else if (lname == "getuserdefaultlangid" || lname == "getsystemdefaultlangid") { ret = 0x0409; }
    else if (lname == "getuserdefaultuilanguage" || lname == "getsystemdefaultuilanguage") { ret = 0x0409; }
    else if (lname == "comparestringa" || lname == "comparestringw") { ret = 2; } // CSTR_EQUAL
    else if (lname == "getenvironmentstringsa" || lname == "getenvironmentstringsw" ||
             lname == "getenvironmentvariablea" || lname == "getenvironmentvariablew" ||
             lname == "expandenvironmentstringsa") {
        ret = 0; call.note = "boş ortam (determinizm)";
    }
    else if (lname == "freeenvironmentstringsa" || lname == "freeenvironmentstringsw") { ret = 1; }
    else if (lname == "tlsalloc" || lname == "flsalloc") { ret = 1; }
    else if (lname == "tlsgetvalue" || lname == "flsgetvalue") { ret = 0; }
    else if (lname == "tlssetvalue" || lname == "flssetvalue" ||
             lname == "tlsfree" || lname == "flsfree") { ret = 1; }
    else if (lname == "wakebyaddressall" || lname == "wakebyaddresssingle") {
        ret = 0; call.note = "uyandirma (tek thread — kimse beklemede degil)";
    }
    else if (lname == "initializecriticalsectionex") {
        // InitializeCriticalSectionEx: BOOL — BAŞARI döndür (CRT kontrol eder!)
        if (writeMem) WriteU32(*this, args[0] + 0x04, 0x10000000); // SpinCount alanı
        ret = 1; call.note = "kritik bölüm hazır (tek thread)";
    }
    else if (lname == "initializesrwlock" || lname == "initializesrwlockshared" ||
             lname == "initializecriticalsection" || lname == "deletecriticalsection" ||
             lname == "entercriticalsection" || lname == "leavecriticalsection" ||
             lname == "initializecriticalsectionandspincount" ||
             lname == "tryacquiresrwlockexclusive" || lname == "tryacquiresrwlockshared" ||
             lname == "tryentercriticalsection" ||
             lname == "acquiresrwlockexclusive" || lname == "acquiresrwlockshared") {
        ret = 0; call.note = "kritik bölüm: tek thread — anında geç";
    }
    else if (lname == "initonceexecuteonce" || lname == "initoncebegininitialize" ||
             lname == "initoncecomplete") {
        ret = 1; call.note = "once-init: tamamlandı say (callback koşulmaz — determinizm)";
    }
    else if (lname == "createthread" || lname == "createthreadex" ||
             lname == "queueuserworkitem" || lname == "trysubmitthreadpoolcallback" ||
             lname == "registerwaitforsingleobject") {
        // thread BAŞLATILMAZ (tek thread determinizmi); kayıt + sahte handle
        threadHandleCounter_ += 4;
        ret = threadHandleCounter_;
        call.note = "thread kaydedildi AMA koşurulmadı (determinizm)";
    }
    else if (lname == "resumethread") {
        if (writeMem && args[1]) WriteU32(*this, args[1], 0);  // önceki suspend sayısı
        ret = 0;
    }
    else if (lname == "suspendthread") { ret = 0; }
    else if (lname == "getexitcodethread" || lname == "getexitcodeprocess") {
        if (writeMem) WriteU32(*this, args[1], 259);  // STILL_ACTIVE
        ret = 1;
    }
    else if (lname == "seterrormode" || lname == "setunhandledexceptionfilter" ||
             lname == "unhandledexceptionfilter" || lname == "rtladdfunctiontable" ||
             lname == "rtlremovefunctiontable" || lname == "setthreadpriority" ||
             lname == "setthreadaffinitymask" || lname == "setprocessaffinitymask" ||
             lname == "timebeginperiod" || lname == "timeendperiod" ||
             lname == "deactivateactctx" || lname == "releasethreadpooltimer" ||
             lname == "releasethreadpoolwait" || lname == "closethreadpooltimer" ||
             lname == "closethreadpoolwait" || lname == "setthreadpooltimer" ||
             lname == "setthreadpoolwait" || lname == "unregisterwait" ||
             lname == "unregisterwaitex") {
        ret = 0;   // (setunhandledexceptionfilter eski filtreyi döndürür: NULL)
    }
    else if (lname == "getmodulefilenamea" || lname == "getmodulefilenamew") {
        // "C:\game\godtier_wininit.exe" — deterministik
        const char* path = "C:\\game\\godtier_wininit.exe";
        ret = strlen(path);
        if (writeMem && args[1]) {
            if (lname.back() == 'w') {
                std::vector<u8> w;
                for (const char* p = path; *p; p++) { w.push_back((u8)*p); w.push_back(0); }
                w.push_back(0); w.push_back(0);
                writeMem(args[1], w.data(), w.size());
                ret = w.size() / 2 - 1;
            } else {
                writeMem(args[1], (const u8*)path, strlen(path) + 1);
            }
        }
        call.note = path;
    }
    else if (lname == "interlockedincrement" || lname == "interlockeddecrement") {
        ret = 2;  // 1'den artırılmış/decrement edilmiş — deterministik
    }
    else if (lname == "interlockedexchange" || lname == "interlockedcompareexchange") {
        ret = 0;  // eski değer: sıfır (bump-başlangıç)
    }
    else if (lname == "regopenkeyexa" || lname == "regopenkeyexw" ||
             lname == "regcreatekeyexa" || lname == "regqueryvalueexa" ||
             lname == "regqueryvalueexw" || lname == "regsetvalueexa" ||
             lname == "regenumkeyexa" || lname == "regdeletekeya") {
        ret = 2;   // ERROR_FILE_NOT_FOUND — kayıt yok (deterministik)
        call.note = "ERROR_FILE_NOT_FOUND";
    }
    else if (lname == "regclosekey") { ret = 0; }
    else if (lname == "getcomputernamea" || lname == "getcomputernameexa" ||
             lname == "getusernamea" || lname == "getusernameexa") {
        const char* v = "GODTIER";
        if (writeMem && args[0]) writeMem(args[0], (const u8*)v, strlen(v) + 1);
        ret = strlen(v);
        if (lname == "getcomputernamea" || lname == "getusernamea") {
            if (writeMem && args[1]) WriteU32(*this, args[1], (u32)strlen(v) + 1);
        }
    }
    else if (lname == "createmutexa" || lname == "createmutexw" ||
             lname == "createeventa" || lname == "createeventw" ||
             lname == "createsemaphorea" || lname == "openeventa") {
        fakeHandleCounter_ += 0x100;
        ret = fakeHandleCounter_;
        call.note = "sahte senkron nesnesi";
    }
    else if (lname == "createmountpoint" || lname == "getvolumemountpointa") { ret = 0; }
    else {
        // bilinmeyen API: güvenli log (v9.2: sayacı da tut — WinInit raporlar)
        unknownCount_++;
        call.note = "(shim: bilinmeyen API, 0 dondu)";
        ret = 0;
    }

    call.ret = ret;
    if (calls_.size() < logLimit_) calls_.push_back(call);
    return ret;
}

} // namespace gt
