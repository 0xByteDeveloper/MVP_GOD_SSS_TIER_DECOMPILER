# ============================================================================
#  i4M GodTier Engine — gui/CMakeLists.txt
#  SDL2 + OpenGL3 + ImGui (FetchContent ile otomatik çekilir)
# ============================================================================
include(FetchContent)
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        docking
    GIT_SHALLOW    TRUE)
FetchContent_Declare(SDL2
    GIT_REPOSITORY https://github.com/libsdl-org/SDL.git
    GIT_TAG        release-2.30.9
    GIT_SHALLOW    TRUE)

FetchContent_MakeAvailable(imgui)

# SDL2: sistemde varsa kullan, yoksa çek
find_package(SDL2 QUIET)
if (NOT SDL2_FOUND)
    set(SDL_SHARED OFF CACHE BOOL "" FORCE)
    set(SDL_STATIC ON CACHE BOOL "" FORCE)
    set(SDL_TEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(SDL2)
    set(SDL2_LIBRARIES SDL2-static)
    set(SDL2_INCLUDE_DIRS ${sdl2_SOURCE_DIR}/include)
endif()

add_executable(godtier_gui
    godtier_gui.cpp
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl2.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_sdlrenderer2.cpp)
target_include_directories(godtier_gui PRIVATE
    ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends ${SDL2_INCLUDE_DIRS})
target_link_libraries(godtier_gui PRIVATE godtier_core ${SDL2_LIBRARIES})

if (MSVC)
    target_compile_options(godtier_gui PRIVATE /utf-8)
else()
    target_compile_options(godtier_gui PRIVATE -Wno-unused-parameter)
endif()
