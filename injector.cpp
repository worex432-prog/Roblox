#include <windows.h>
#include <tlhelp32.h>

#include <cwchar>
#include <iostream>
#include <string>
#include <vector>

struct ProcessInfo { DWORD pid; std::wstring name; };

std::vector<ProcessInfo> FindProcesses(const wchar_t* processName) {
    std::vector<ProcessInfo> matches;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return matches;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0)
                matches.push_back({entry.th32ProcessID, entry.szExeFile});
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return matches;
}

std::wstring FormatError(DWORD error) {
    wchar_t* message = nullptr;
    const DWORD chars = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::wstring result = chars ? message : L"Unknown error";
    if (message) LocalFree(message);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) result.pop_back();
    return result;
}

bool GetAbsoluteExistingPath(const wchar_t* input, std::wstring& output) {
    const DWORD length = GetFullPathNameW(input, 0, nullptr, nullptr);
    if (!length) return false;
    output.resize(length - 1);
    if (!GetFullPathNameW(input, length, output.data(), nullptr)) return false;
    const DWORD attributes = GetFileAttributesW(output.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool Inject(DWORD pid, const std::wstring& dllPath, std::wstring& failure) {
    const HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!process) { failure = L"OpenProcess: " + FormatError(GetLastError()); return false; }

    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remoteMemory = VirtualAllocEx(process, nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMemory) {
        failure = L"VirtualAllocEx: " + FormatError(GetLastError());
        CloseHandle(process); return false;
    }
    if (!WriteProcessMemory(process, remoteMemory, dllPath.c_str(), bytes, nullptr)) {
        failure = L"WriteProcessMemory: " + FormatError(GetLastError());
        VirtualFreeEx(process, remoteMemory, 0, MEM_RELEASE); CloseHandle(process); return false;
    }
    const auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    const HANDLE thread = loadLibrary ? CreateRemoteThread(process, nullptr, 0, loadLibrary, remoteMemory, 0, nullptr) : nullptr;
    if (!thread) {
        failure = L"CreateRemoteThread: " + FormatError(GetLastError());
        VirtualFreeEx(process, remoteMemory, 0, MEM_RELEASE); CloseHandle(process); return false;
    }

    const DWORD wait = WaitForSingleObject(thread, 15000);
    DWORD remoteResult = 0;
    const bool loaded = wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &remoteResult) && remoteResult != 0;
    if (!loaded) failure = wait == WAIT_TIMEOUT ? L"LoadLibraryW timed out." :
        L"LoadLibraryW returned null. Check that the DLL is x64 and its dependencies are available.";
    CloseHandle(thread);
    VirtualFreeEx(process, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(process);
    return loaded;
}

bool ParsePid(const wchar_t* value, DWORD& pid) {
    wchar_t* end = nullptr;
    const unsigned long number = wcstoul(value, &end, 10);
    if (!*value || *end || number == 0 || number > MAXDWORD) return false;
    pid = static_cast<DWORD>(number);
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcerr << L"Usage: injector.exe <pid|process.exe> <path-to-dll>\n"
                      L"Example: injector.exe 1234 C:\\mods\\test_overlay.dll\n";
        return 2;
    }
    std::wstring dllPath;
    if (!GetAbsoluteExistingPath(argv[2], dllPath)) {
        std::wcerr << L"DLL path does not exist or is invalid: " << argv[2] << L'\n'; return 2;
    }
    DWORD pid = 0;
    if (!ParsePid(argv[1], pid)) {
        const auto matches = FindProcesses(argv[1]);
        if (matches.empty()) { std::wcerr << L"Process not found: " << argv[1] << L'\n'; return 1; }
        if (matches.size() > 1) {
            std::wcerr << L"More than one matching process was found. Use its PID instead:\n";
            for (const auto& match : matches) std::wcerr << L"  " << match.pid << L"  " << match.name << L'\n';
            return 2;
        }
        pid = matches.front().pid;
    }
    std::wstring failure;
    if (!Inject(pid, dllPath, failure)) {
        std::wcerr << L"Injection into PID " << pid << L" failed: " << failure << L'\n'; return 1;
    }
    std::wcout << L"Injected " << dllPath << L" into PID " << pid << L".\n";
    return 0;
}
