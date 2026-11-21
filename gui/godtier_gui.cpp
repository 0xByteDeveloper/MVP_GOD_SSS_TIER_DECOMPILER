// ============================================================================
//  i4M GodTier Engine — gui/godtier_gui.cpp
//  ImGui + SDL2 + OpenGL3 arayüzü (eski i4MGUILoader'ın ruhu, yeni motor).
//  Paneller: Binary bilgisi, Sections, Imports, Strings, Functions,
//            Disassembly, Pseudocode, Hexdump, Emulator (regs/trace/API),
//            Analysis (entropi/packer/crypto/capa).
//  Derleme: cmake -DGODTIER_GUI=ON ..  (SDL2 + imgui FetchContent ile çekilir)
// ============================================================================
#include "ui/shell.h"
#include "imgui.h"
#include "imgui_impl_sdl2.h"
#include "imgui_impl_sdlrenderer2.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <SDL.h>

using namespace gt;

// ----------------------------------------------------------------------------
// GUI, Shell motorunu "driver" olarak kullanır: komut dizisi yürütür ve
// motor nesnelerine Shell üzerinden erişir. Basit ve sağlam bir yaklaşım:
// aynı çekirdek, iki arayüz (CLI + GUI) — GOD mimari.
// ----------------------------------------------------------------------------
class GuiApp {
public:
    void Run() {
        if (!Init()) return;
        MainLoop();
        Shutdown();
    }

private:
    SDL_Window* window_ = nullptr;
    SDL_Renderer* renderer_ = nullptr;
    bool quit_ = false;

    // motor durumu (Shell ile paylaşılır)
    Shell shell_;
    std::string loadedPath_;
    // --- panellerin veri tamponları ---
    char fileBuf_[512] = "";
    char addrBuf_[32] = "entry";
    char asmBuf_[256] = "mov rax, 0x1337";
    char strFilter_[64] = "";
    std::vector<std::string> console_;
    char consoleInput_[256] = "";

    bool Init();
    void MainLoop();
    void Shutdown();
    void UiMain();
    void UiBinaryInfo();
    void UiSections();
    void UiImports();
    void UiStrings();
    void UiFunctions();
    void UiDisassembly();
    void UiPseudocode();
    void UiHexdump();
    void UiEmulator();
    void UiAnalysis();
    void UiConsole();
    void Exec(const std::string& cmd);   // shell'e komut ver + konsola düşür
};

bool GuiApp::Init() {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
        std::printf("SDL hatasi: %s\n", SDL_GetError());
        return false;
    }
    // SDL_Renderer: platformun en iyi arka ucunu secer (Windows: D3D, digerleri: GL)
    // OpenGL baslik dosyasi gerektirmez — her ortamda derlenir (GOD karar)
    SDL_WindowFlags flags = (SDL_WindowFlags)(SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI | SDL_WINDOW_MAXIMIZED);
    window_ = SDL_CreateWindow("i4M GodTier Engine — MEGA GOD SSS TIER",
                               SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1600, 900, flags);
    renderer_ = SDL_CreateRenderer(window_, -1, SDL_RENDERER_PRESENTVSYNC | SDL_RENDERER_ACCELERATED);
    if (!renderer_)
        renderer_ = SDL_CreateRenderer(window_, -1, SDL_RENDERER_SOFTWARE);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    ImGui_ImplSDL2_InitForSDLRenderer(window_, renderer_);
    ImGui_ImplSDLRenderer2_Init(renderer_);
    return true;
}

void GuiApp::Shutdown() {
    ImGui_ImplSDLRenderer2_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_DestroyRenderer(renderer_);
    SDL_DestroyWindow(window_);
    SDL_Quit();
}

void GuiApp::MainLoop() {
    while (!quit_) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            ImGui_ImplSDL2_ProcessEvent(&ev);
            if (ev.type == SDL_QUIT) quit_ = true;
            if (ev.type == SDL_WINDOWEVENT && ev.window.event == SDL_WINDOWEVENT_CLOSE &&
                ev.window.windowID == SDL_GetWindowID(window_)) quit_ = true;
        }
        ImGui_ImplSDLRenderer2_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();
        UiMain();
        ImGui::Render();
        SDL_SetRenderDrawColor(renderer_, 20, 20, 26, 255);
        SDL_RenderClear(renderer_);
        ImGui_ImplSDLRenderer2_RenderDrawData(ImGui::GetDrawData(), renderer_);
        SDL_RenderPresent(renderer_);
    }
}

// ----------------------------------------------------------------------------
void GuiApp::Exec(const std::string& cmd) {
    console_.push_back("gt> " + cmd);
    // Not: Shell çıktısı stdout'a gider; GUI modunda ileride log callback
    // bağlanacak (v1.1). Komut yan etkileri (load/map/emu) panellere yansır.
    shell_.ExecuteCommand(cmd);
    if (console_.size() > 500) console_.erase(console_.begin(), console_.begin() + 250);
}

void GuiApp::UiMain() {
    ImGui::DockSpaceOverViewport(ImGui::GetID("GodTierDock"), ImGui::GetMainViewport());
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("Dosya")) {
            ImGui::InputText("##path", fileBuf_, sizeof(fileBuf_));
            ImGui::SameLine();
            if (ImGui::Button("Ac")) { loadedPath_ = fileBuf_; Exec("load " + loadedPath_); }
            if (ImGui::MenuItem("Cikis")) quit_ = true;
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Motor")) {
            if (ImGui::MenuItem("Map (loader emulasyonu)")) Exec("map");
            if (ImGui::MenuItem("Emulator: entry'den baslat")) Exec("emu setup");
            if (ImGui::MenuItem("ApiTrace")) Exec("apitrace");
            if (ImGui::MenuItem("Komut izi")) Exec("trace 40");
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Analiz")) {
            if (ImGui::MenuItem("Tum analiz")) Exec("analysis all");
            if (ImGui::MenuItem("Pseudocode (tum fonksiyonlar)")) Exec("decomp");
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }
    UiBinaryInfo();
    UiSections();
    UiImports();
    UiStrings();
    UiFunctions();
    UiDisassembly();
    UiPseudocode();
    UiHexdump();
    UiEmulator();
    UiAnalysis();
    UiConsole();
}

void GuiApp::UiBinaryInfo() {
    if (!ImGui::Begin("Binary Bilgisi")) { ImGui::End(); return; }
    ImGui::Text("i4M GodTier Engine — ImGui GUI");
    ImGui::Separator();
    ImGui::TextWrapped("Dosya yuklemek icin: Dosya menusu veya konsola 'load dosya.exe'");
    ImGui::TextWrapped("Motor: Capstone (disasm) + Keystone (asm) + Unicorn (emulasyon)");
    if (!loadedPath_.empty()) {
        ImGui::Separator();
        ImGui::Text("Yuklu: %s", loadedPath_.c_str());
    }
    ImGui::Separator();
    if (ImGui::Button("Banner'i goster")) Exec("info");
    ImGui::End();
}

void GuiApp::UiSections() {
    if (!ImGui::Begin("Sections")) { ImGui::End(); return; }
    ImGui::TextWrapped("'sections' komutu ile guncellenir (analiz motoruna konsoldan erisilir)");
    ImGui::End();
}

void GuiApp::UiImports() {
    if (!ImGui::Begin("Imports")) { ImGui::End(); return; }
    ImGui::TextWrapped("'imports' komutu ile guncellenir");
    ImGui::End();
}

void GuiApp::UiStrings() {
    if (!ImGui::Begin("Strings")) { ImGui::End(); return; }
    ImGui::InputText("filtre", strFilter_, sizeof(strFilter_));
    ImGui::SameLine();
    if (ImGui::Button("Tara")) Exec(std::string("strings ") + strFilter_);
    ImGui::End();
}

void GuiApp::UiFunctions() {
    if (!ImGui::Begin("Functions")) { ImGui::End(); return; }
    ImGui::TextWrapped("'funcs' komutu ile guncellenir");
    ImGui::End();
}

void GuiApp::UiDisassembly() {
    if (!ImGui::Begin("Disassembly")) { ImGui::End(); return; }
    ImGui::InputText("adres", addrBuf_, sizeof(addrBuf_));
    ImGui::SameLine();
    if (ImGui::Button("Dis")) Exec(std::string("dis ") + addrBuf_ + " 32");
    ImGui::Separator();
    ImGui::TextWrapped("Capstone motoru ile disassembly (detay API acik)");
    ImGui::End();
}

void GuiApp::UiPseudocode() {
    if (!ImGui::Begin("Pseudocode")) { ImGui::End(); return; }
    if (ImGui::Button("Bu fonksiyonu decompile et"))
        Exec(std::string("decomp ") + addrBuf_);
    ImGui::SameLine();
    if (ImGui::Button("Tumu")) Exec("decomp all");
    ImGui::TextWrapped("CFG + kalip kutuphanesi ile C-benzeri cikti (Ghidra/IDA uslubi)");
    ImGui::End();
}

void GuiApp::UiHexdump() {
    if (!ImGui::Begin("Hexdump")) { ImGui::End(); return; }
    if (ImGui::Button("Goster")) Exec(std::string("hex ") + addrBuf_ + " 16");
    ImGui::End();
}

void GuiApp::UiEmulator() {
    if (!ImGui::Begin("Emulator (Unicorn)")) { ImGui::End(); return; }
    if (ImGui::Button("Kur + Calistir")) Exec("emu setup");
    ImGui::SameLine();
    if (ImGui::Button("Step 1")) Exec("emu step 1");
    ImGui::SameLine();
    if (ImGui::Button("Stop")) Exec("emu stop");
    ImGui::Separator();
    if (ImGui::Button("Register'lar")) Exec("regs");
    if (ImGui::Button("API cagrilari")) Exec("apitrace");
    if (ImGui::Button("Komut izi (son 40)")) Exec("trace 40");
    ImGui::End();
}

void GuiApp::UiAnalysis() {
    if (!ImGui::Begin("Analysis")) { ImGui::End(); return; }
    if (ImGui::Button("imphash")) Exec("analysis imphash");
    ImGui::SameLine();
    if (ImGui::Button("entropi")) Exec("analysis entropy");
    if (ImGui::Button("packer")) Exec("analysis packer");
    ImGui::SameLine();
    if (ImGui::Button("kripto sabitleri")) Exec("analysis crypto");
    if (ImGui::Button("yetenekler (capa-lite)")) Exec("analysis capa");
    ImGui::End();
}

void GuiApp::UiConsole() {
    if (!ImGui::Begin("Konsol")) { ImGui::End(); return; }
    for (auto& l : console_) ImGui::TextWrapped("%s", l.c_str());
    ImGui::Separator();
    ImGuiInputTextFlags flags = ImGuiInputTextFlags_EnterReturnsTrue;
    if (ImGui::InputText("komut", consoleInput_, sizeof(consoleInput_), flags)) {
        Exec(consoleInput_);
        consoleInput_[0] = 0;
        ImGui::SetKeyboardFocusHere(-1);
    }
    ImGui::End();
}

int main(int, char**) {
    GuiApp app;
    app.Run();
    return 0;
}
