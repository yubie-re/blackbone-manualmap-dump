#include "inc.hpp"
#include "scan.hpp"

void *g_map_from_memory = nullptr;
void *g_map_from_file = nullptr;

void hook_func(void **orig, void *address, void *hook)
{
    auto res = MH_CreateHook(address, hook, orig);
    if (res != MH_OK)
    {
        printf("CreateHook failed: %s\n", MH_StatusToString(res));
    }
    res = MH_EnableHook(address);
    if (res != MH_OK)
    {
        printf("EnableHook failed: %s\n", MH_StatusToString(res));
    }
}

void unhook_func(void *address)
{
    auto res = MH_DisableHook(address);
    if (res != MH_OK)
    {
        printf("DisableHook failed: %s\n", MH_StatusToString(res));
    }
}

uintptr_t (__fastcall*o_map_from_file)(void *ts, wchar_t* file, char flag);

uintptr_t __fastcall map_from_file(void *ts, wchar_t* file, char flag)
{
    if(std::filesystem::exists(file))
    {
        std::filesystem::copy_file(file, std::format("./Image_{}.bin", (void*)file));
        printf("Copied disk image to Image_%p.bin\n", file);
    }
    return o_map_from_file(ts, file, flag);
}

uintptr_t (__fastcall*o_map_from_memory)(void *ts, void *buffer, uintptr_t size, char flag);

uintptr_t __fastcall map_from_memory(void *ts, void *buffer, uintptr_t size, char flag)
{
    std::ofstream image_file(std::format("Image_{}.bin", buffer), std::ios::out | std::ios::binary | std::ios::trunc);
    image_file.write((char *)buffer, size);
    image_file.close();
    printf("Dumped memory image stored to Image_%p.bin\n", buffer);
    return o_map_from_memory(ts, buffer, size, flag);
}

void hook()
{
    MH_Initialize();

#if _WIN64
    g_map_from_memory = scanner::scan("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B D9 33 F6 48 8B 49 10 41 0F B6 E9 48 8B FA 48 85 C9 74 0C 7E 06 FF 15", "map_from_memory", GetModuleHandleA(nullptr)); // Not sure if these sigs are accurate for different versions, if failed find PEImage::Load
    g_map_from_file = scanner::scan("48 89 5C 24 ? 55 56 57 41 54 41 57 48 83 EC 40 48 8D 71 10 48 8B F9 48 8B 0E 33 ED 45 0F B6 E0 48 8B DA 48 85 C9 74 0B 7E 06 FF 15", "map_from_file", GetModuleHandleA(nullptr));
#else
    g_map_from_memory = scanner::scan("55 8B EC 56 57 6A 01 8B F1 E8 ? ? ? ? 8B 7D 08 C6 46 10 01 8B 46 08", "map_from_memory", GetModuleHandleA(nullptr));
    g_map_from_file = scanner::scan("55 8B EC 53 56 57 6A 01 8B F9 E8 ? ? ? ? 8B 75 08 8D 9F ? ? ? ? 3B DE", "map_from_file", GetModuleHandleA(nullptr));
#endif

    //g_map_from_memory = (void*)((uintptr_t)GetModuleHandleA(nullptr) + 0xFFFFFF); // Replace offset if you want to hardcode it
    //g_map_from_file = (void*)((uintptr_t)GetModuleHandleA(nullptr) + 0xFFFFFF); // Replace offset if you want to hardcode it

    if (g_map_from_memory)
        hook_func((void **)&o_map_from_memory, g_map_from_memory, map_from_memory);
    if (g_map_from_file)
        hook_func((void **)&o_map_from_file, g_map_from_file, map_from_file);
}

void unhook()
{
    if (g_map_from_memory)
        unhook_func(g_map_from_memory);
    if (g_map_from_file)
        unhook_func(g_map_from_file);
}

DWORD WINAPI main_thread(PVOID module)
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    hook();
    while (!GetAsyncKeyState(VK_DELETE))
    {
        std::this_thread::yield();
    }
    unhook();
    fclose(stdout);
    FreeConsole();
    FreeLibraryAndExitThread((HMODULE)module, 0);
    return 1;
}

// Entrypoint
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        CreateThread(nullptr, 0, &main_thread, (void *)module, 0, nullptr);
    }
    return TRUE;
}