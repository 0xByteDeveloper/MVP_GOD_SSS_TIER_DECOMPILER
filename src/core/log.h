// ============================================================================
//  i4M GodTier Engine — core/log.h
//  Renkli konsol çıktısı (ANSI; Windows 10+ VT otomatik açılır).
//  İlham: rizin'in renk paleti + x64dbg'nin log akışı.
// ============================================================================
#pragma once
#include <string>
#include <cstdio>

namespace gt {

enum class LogColor { Default, Gray, White, Green, Red, Cyan, Yellow, Magenta };

void LogInit();                                  // Windows'ta VT100 modunu açar
void LogSetColor(LogColor c);
void Log(const char* fmt, ...);
void LogLine(LogColor c, const char* fmt, ...);  // renkli satır
void LogInfo(const char* fmt, ...);
void LogOk(const char* fmt, ...);
void LogWarn(const char* fmt, ...);
void LogErr(const char* fmt, ...);

// Loader benzeri adımlı rapor: "[3/8] Section'lar map ediliyor..."
void LogStep(int step, int total, const std::string& msg);

} // namespace gt
