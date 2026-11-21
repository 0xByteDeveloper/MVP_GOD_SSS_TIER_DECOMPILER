// ============================================================================
//  i4M GodTier Engine — core/log.cpp
// ============================================================================
#include "core/log.h"
#include <cstdarg>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

namespace gt {

void LogInit() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif
}

static const char* Code(LogColor c) {
    switch (c) {
        case LogColor::Gray:    return "\x1b[90m";
        case LogColor::White:   return "\x1b[97m";
        case LogColor::Green:   return "\x1b[92m";
        case LogColor::Red:     return "\x1b[91m";
        case LogColor::Cyan:    return "\x1b[96m";
        case LogColor::Yellow:  return "\x1b[93m";
        case LogColor::Magenta: return "\x1b[95m";
        default:                return "\x1b[0m";
    }
}

void LogSetColor(LogColor c) { std::fputs(Code(c), stdout); }

static void vprintf_(const char* fmt, va_list ap) {
    std::vfprintf(stdout, fmt, ap);
}

void Log(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); vprintf_(fmt, ap); va_end(ap);
}

void LogLine(LogColor c, const char* fmt, ...) {
    std::fputs(Code(c), stdout);
    va_list ap; va_start(ap, fmt); vprintf_(fmt, ap); va_end(ap);
    std::fputs("\x1b[0m\n", stdout);
}

void LogInfo(const char* fmt, ...) {
    std::fputs("\x1b[96m[*]\x1b[0m ", stdout);
    va_list ap; va_start(ap, fmt); vprintf_(fmt, ap); va_end(ap);
    std::fputc('\n', stdout);
}

void LogOk(const char* fmt, ...) {
    std::fputs("\x1b[92m[+]\x1b[0m ", stdout);
    va_list ap; va_start(ap, fmt); vprintf_(fmt, ap); va_end(ap);
    std::fputc('\n', stdout);
}

void LogWarn(const char* fmt, ...) {
    std::fputs("\x1b[93m[!]\x1b[0m ", stdout);
    va_list ap; va_start(ap, fmt); vprintf_(fmt, ap); va_end(ap);
    std::fputc('\n', stdout);
}

void LogErr(const char* fmt, ...) {
    std::fputs("\x1b[91m[x]\x1b[0m ", stdout);
    va_list ap; va_start(ap, fmt); vprintf_(fmt, ap); va_end(ap);
    std::fputc('\n', stdout);
}

void LogStep(int step, int total, const std::string& msg) {
    std::printf("\x1b[95m[%d/%d]\x1b[0m %s\n", step, total, msg.c_str());
}

} // namespace gt
