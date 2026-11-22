cmake_minimum_required(VERSION 3.16)
project(i4M-GodTier VERSION 1.0.0 LANGUAGES C CXX)

# ============================================================================
#  i4M GodTier Engine — MEGA GOD SSS TIER Binary Analiz Motoru
#  Capstone (disasm) + Keystone (asm) + Unicorn (emulasyon) + kendi PE/ELF
#  parser'ı + cross-platform mapper + CFG/pseudocode decompiler
#
#  Derleme:
#    cmake -B build && cmake --build build -j
#  GUI (opsiyonel, SDL2 + OpenGL3 + ImGui çeker):
#    cmake -B build -DGODTIER_GUI=ON && cmake --build build -j
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
if (MSVC)
    add_compile_options(/utf-8 /W3)
else()
    add_compile_options(-Wall -Wextra)
endif()

option(GODTIER_GUI "ImGui + SDL2 GUI hedefini derle" OFF)

# ----------------------------------------------------------------------------
# Motor kütüphaneleri: önce third_party/, sonra sistem paketleri
# ----------------------------------------------------------------------------
set(_GT_INC "")
set(_GT_LIB "")
set(_TP ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

if (EXISTS ${_TP}/include/capstone/capstone.h)
    list(APPEND _GT_INC ${_TP}/include)
    if (WIN32)
        list(APPEND _GT_LIB ${_TP}/lib/capstone.lib)
    else()
        list(APPEND _GT_LIB ${_TP}/lib/libcapstone.so)
    endif()
else()
    find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h REQUIRED)
    find_library(CAPSTONE_LIB NAMES capstone REQUIRED)
    list(APPEND _GT_INC ${CAPSTONE_INCLUDE_DIR})
    list(APPEND _GT_LIB ${CAPSTONE_LIB})
endif()

if (EXISTS ${_TP}/include/unicorn/unicorn.h)
    if (WIN32)
        list(APPEND _GT_LIB ${_TP}/lib/unicorn.lib)
    else()
        list(APPEND _GT_LIB ${_TP}/lib/libunicorn.so)
    endif()
else()
    find_path(UNICORN_INCLUDE_DIR unicorn/unicorn.h REQUIRED)
    find_library(UNICORN_LIB NAMES unicorn REQUIRED)
    list(APPEND _GT_INC ${UNICORN_INCLUDE_DIR})
    list(APPEND _GT_LIB ${UNICORN_LIB})
endif()

if (EXISTS ${_TP}/include/keystone/keystone.h)
    if (WIN32)
        list(APPEND _GT_LIB ${_TP}/lib/keystone.lib)
    else()
        list(APPEND _GT_LIB ${_TP}/lib/libkeystone.so)
    endif()
else()
    find_path(KEYSTONE_INCLUDE_DIR keystone/keystone.h REQUIRED)
    find_library(KEYSTONE_LIB NAMES keystone REQUIRED)
    list(APPEND _GT_INC ${KEYSTONE_INCLUDE_DIR})
    list(APPEND _GT_LIB ${KEYSTONE_LIB})
endif()

# Windows'ta DLL'leri bin/ yanına kopyala
if (WIN32 AND EXISTS ${_TP}/lib)
    file(GLOB _TP_DLLS ${_TP}/lib/*.dll)
    if (_TP_DLLS)
        add_custom_command(TARGET godtier POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_TP_DLLS} $<TARGET_FILE_DIR:godtier>)
    endif()
endif()

# ----------------------------------------------------------------------------
# Çekirdek statik kütüphane
# ----------------------------------------------------------------------------
add_library(godtier_core STATIC
    src/core/log.cpp
    src/core/util.cpp
    src/format/pe.cpp
    src/format/elf.cpp
    src/format/dwarf.cpp
    src/format/pdb.cpp
    src/format/image.cpp
    src/disasm/engine.cpp
    src/disasm/analyzer.cpp
    src/asm/assembler.cpp
    src/mapper/mapper.cpp
    src/emulate/emulator.cpp
    src/emulate/apishim.cpp
    src/emulate/wininit.cpp
    src/decomp/cfg.cpp
    src/decomp/pseudocode.cpp
    src/decomp/devirtpro.cpp
    src/decomp/devirtemu.cpp
    src/decomp/types.cpp
    src/analysis/features.cpp
    src/analysis/deepscan.cpp
    src/analysis/sigs.cpp
    src/analysis/obfus.cpp
    src/analysis/msvcrtti.cpp
    src/proc/process.cpp
    src/ui/shell.cpp
    src/ui/shell_analyze.cpp
    src/ui/shell_system.cpp
    src/ui/shell_deep.cpp
)
target_include_directories(godtier_core PUBLIC src ${_GT_INC})
target_link_libraries(godtier_core PUBLIC ${_GT_LIB})
if (UNIX)
    target_link_libraries(godtier_core PUBLIC pthread)
endif()

add_executable(godtier src/main.cpp)
target_link_libraries(godtier PRIVATE godtier_core)

# ----------------------------------------------------------------------------
# Testler
# ----------------------------------------------------------------------------
enable_testing()
add_executable(godtier_tests tests/test_main.cpp)
target_link_libraries(godtier_tests PRIVATE godtier_core)
add_test(NAME godtier_tests COMMAND godtier_tests)

# ----------------------------------------------------------------------------
# GUI (opsiyonel)
# ----------------------------------------------------------------------------
if (GODTIER_GUI)
    add_subdirectory(gui)
endif()
