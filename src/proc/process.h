// ============================================================================
//  i4M GodTier Engine — proc/process.h
//  Process bellek erişimi — CROSS-PLATFORM:
//   - Windows: ReadProcessMemory/WriteProcessMemory (i4M InstanceManager mirası)
//   - Linux:   /proc/<pid>/mem + /proc/<pid>/maps (pwndbg dersi)
// ============================================================================
#pragma once
#include "core/types.h"
#include <string>
#include <vector>

namespace gt {

struct ModuleInfo {
    u64 base = 0, size = 0;
    std::string path, name;
};

class ProcessAccess {
public:
    bool Attach(u32 pid);
    void Detach();
    bool Ok() const { return attached_; }
    u32 Pid() const { return pid_; }

    bool Read(u64 addr, u8* out, size_t n) const;
    bool Write(u64 addr, const u8* p, size_t n);
    u64  Read64(u64 addr) const { u64 v = 0; Read(addr, (u8*)&v, 8); return v; }
    u32  Read32(u64 addr) const { u32 v = 0; Read(addr, (u8*)&v, 4); return v; }

    const std::vector<ModuleInfo>& Modules() const { return modules_; }
    bool RefreshModules();
    const ModuleInfo* FindModule(const std::string& namePart) const;
    bool IsMapped(u64 addr) const;

    // sistemdeki process listesi (ad filtreli) — "proc list" komutu
    struct ProcEntry { u32 pid; std::string name; };
    static std::vector<ProcEntry> ListProcesses(const std::string& filter = "");

private:
    bool attached_ = false;
    u32 pid_ = 0;
    std::vector<ModuleInfo> modules_;
#ifdef _WIN32
    void* hProc_ = nullptr; // HANDLE
#endif
    // Linux'ta maps satırlarından adres aralıkları
    struct Range { u64 lo, hi; };
    std::vector<Range> ranges_;
};

} // namespace gt
