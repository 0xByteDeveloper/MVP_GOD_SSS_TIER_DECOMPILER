// ============================================================================
//  i4M GodTier Engine — proc/process.cpp
// ============================================================================
#include "proc/process.h"
#include "core/log.h"
#include "core/util.h"
#include <cstring>
#include <cstdio>
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace gt {

// ----------------------------------------------------------------------------
// Process listesi
// ----------------------------------------------------------------------------
std::vector<ProcessAccess::ProcEntry> ProcessAccess::ListProcesses(const std::string& filter) {
    std::vector<ProcEntry> out;
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            if (filter.empty() || ToLower(name).find(ToLower(filter)) != std::string::npos)
                out.push_back({pe.th32ProcessID, name});
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
#else
    DIR* d = opendir("/proc");
    if (!d) return out;
    struct dirent* e;
    while ((e = readdir(d))) {
        // yalnız sayısal (pid) dizinler
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        u32 pid = (u32)std::strtoul(e->d_name, nullptr, 10);
        std::string comm;
        FILE* f = std::fopen(("/proc/" + std::string(e->d_name) + "/comm").c_str(), "r");
        if (f) {
            char buf[256] = {};
            if (std::fgets(buf, sizeof(buf), f)) {
                comm = buf;
                while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) comm.pop_back();
            }
            std::fclose(f);
        }
        if (filter.empty() || ToLower(comm).find(ToLower(filter)) != std::string::npos)
            out.push_back({pid, comm});
    }
    closedir(d);
#endif
    return out;
}

// ----------------------------------------------------------------------------
// Attach / Detach
// ----------------------------------------------------------------------------
bool ProcessAccess::Attach(u32 pid) {
    Detach();
    pid_ = pid;
#ifdef _WIN32
    hProc_ = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                         FALSE, pid);
    if (!hProc_) {
        LogErr("OpenProcess(%u) basarisiz (yonetici hakki?)", pid);
        return false;
    }
#endif
    attached_ = true;
    if (!RefreshModules()) {
        LogWarn("Modul listesi alinamadi (izniniz olmayabilir)");
    }
    LogOk("Process %u'ye baglanildi (%zu modul)", pid, modules_.size());
    return true;
}

void ProcessAccess::Detach() {
#ifdef _WIN32
    if (hProc_) { CloseHandle((HANDLE)hProc_); hProc_ = nullptr; }
#endif
    attached_ = false;
    modules_.clear();
    ranges_.clear();
    pid_ = 0;
}

// ----------------------------------------------------------------------------
// Modüller
// ----------------------------------------------------------------------------
bool ProcessAccess::RefreshModules() {
    modules_.clear();
    ranges_.clear();
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModuleInfo mi;
            mi.base = (u64)(uintptr_t)me.modBaseAddr;
            mi.size = me.modBaseSize;
            mi.path = me.szExePath;
            mi.name = me.szModule;
            modules_.push_back(mi);
            ranges_.push_back({mi.base, mi.base + mi.size});
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return !modules_.empty();
#else
    FILE* f = std::fopen(("/proc/" + std::to_string(pid_) + "/maps").c_str(), "r");
    if (!f) return false;
    char line[1024];
    std::string lastName;
    while (std::fgets(line, sizeof(line), f)) {
        u64 lo, hi;
        char perms[8] = {};
        char path[512] = {};
        // format: lo-hi perms offset dev inode path
        if (std::sscanf(line, "%llx-%llx %7s %*s %*s %*s %511s", &lo, &hi, perms, path) >= 3) {
            ranges_.push_back({lo, hi});
            if (path[0]) lastName = path;
            // yürütülebilir eşleme ve (yeni) dosya adı -> modül başlangıcı kabul et
            if (perms[2] == 'x' && path[0]) {
                bool exists = false;
                for (auto& m : modules_) if (m.path == lastName) { exists = true; break; }
                if (!exists) {
                    ModuleInfo mi;
                    mi.base = lo;
                    mi.size = hi - lo;
                    mi.path = lastName;
                    auto slash = lastName.rfind('/');
                    mi.name = slash != std::string::npos ? lastName.substr(slash + 1) : lastName;
                    modules_.push_back(mi);
                }
            }
        }
    }
    std::fclose(f);
    return true;
#endif
}

const ModuleInfo* ProcessAccess::FindModule(const std::string& namePart) const {
    for (auto& m : modules_)
        if (ToLower(m.name).find(ToLower(namePart)) != std::string::npos)
            return &m;
    return nullptr;
}

bool ProcessAccess::IsMapped(u64 addr) const {
    for (auto& r : ranges_)
        if (addr >= r.lo && addr < r.hi) return true;
    return false;
}

// ----------------------------------------------------------------------------
// Read / Write
// ----------------------------------------------------------------------------
bool ProcessAccess::Read(u64 addr, u8* out, size_t n) const {
    if (!attached_ || !out) return false;
#ifdef _WIN32
    SIZE_T got = 0;
    return ReadProcessMemory((HANDLE)hProc_, (LPCVOID)(uintptr_t)addr, out, n, &got) && got == n;
#else
    int fd = ::open(("/proc/" + std::to_string(pid_) + "/mem").c_str(), O_RDONLY);
    if (fd < 0) return false;
    bool ok = ::pread(fd, out, n, (off_t)addr) == (ssize_t)n;
    ::close(fd);
    return ok;
#endif
}

bool ProcessAccess::Write(u64 addr, const u8* p, size_t n) {
    if (!attached_) return false;
#ifdef _WIN32
    SIZE_T put = 0;
    return WriteProcessMemory((HANDLE)hProc_, (LPVOID)(uintptr_t)addr, p, n, &put) && put == n;
#else
    int fd = ::open(("/proc/" + std::to_string(pid_) + "/mem").c_str(), O_WRONLY);
    if (fd < 0) {
        LogErr("/proc/%u/mem yazma icin acilamadi (ptrace izni gerekir)", pid_);
        return false;
    }
    bool ok = ::pwrite(fd, p, n, (off_t)addr) == (ssize_t)n;
    ::close(fd);
    return ok;
#endif
}

} // namespace gt
