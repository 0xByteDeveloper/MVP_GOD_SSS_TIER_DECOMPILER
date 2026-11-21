// ============================================================================
//  i4M GodTier Engine — src/main.cpp
//  Kullanim:
//    godtier                      interaktif kabuk
//    godtier <dosya.exe|.elf>     dosyayi acip kabuga gir
//    godtier -s <dosya.gt>        script modu
//    godtier --version
// ============================================================================
#include "ui/shell.h"
#include "core/log.h"
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    gt::LogInit();
    gt::Shell shell;

    if (argc >= 2 && (!std::strcmp(argv[1], "--version") || !std::strcmp(argv[1], "-v"))) {
        gt::LogLine(gt::LogColor::Magenta, "i4M GodTier Engine 1.0.0 — MEGA GOD SSS TIER");
        gt::Log("  Capstone %d.%d + Keystone %u.%u + Unicorn %d.%d\n",
                CS_VERSION_MAJOR, CS_VERSION_MINOR,
                KS_VERSION_MAJOR, KS_VERSION_MINOR,
                UC_VERSION_MAJOR, UC_VERSION_MINOR);
        return 0;
    }
    if (argc >= 3 && !std::strcmp(argv[1], "-s")) {
        gt::LogLine(gt::LogColor::Magenta, "i4M GodTier — script modu");
        shell.ExecuteCommand("script " + std::string(argv[2]));
        return 0;
    }
    shell.Run(argc > 1 ? argv[1] : "");
    return 0;
}
