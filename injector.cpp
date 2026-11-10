#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <map>
#include <string>
#include <vector>

// Memory-only injector.
//
// The DLL is read from a file or from stdin, mapped into the target process by
// hand (headers, sections, relocations, imports and unwind table) and its entry
// point is called there. No DLL file is created on disk.
//
// Usage:
//   injector.exe <pid|process.exe> <path-to-dll>
//   injector.exe <pid|process.exe> --stdin    (DLL bytes on stdin)

struct ProcessInfo { DWORD pid; std::wstring name; };

static std::vector<ProcessInfo> FindProcesses(const wchar_t* processName) {
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

static std::wstring FormatError(DWORD error) {
    wchar_t* message = nullptr;
    const DWORD chars = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::wstring result = chars ? message : L"Unknown error";
    if (message) LocalFree(message);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) result.pop_back();
    return result;
}

static bool GetAbsoluteExistingPath(const wchar_t* input, std::wstring& output) {
    const DWORD length = GetFullPathNameW(input, 0, nullptr, nullptr);
    if (!length) return false;
    output.resize(length - 1);
    if (!GetFullPathNameW(input, length, output.data(), nullptr)) return false;
    const DWORD attributes = GetFileAttributesW(output.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static bool ParsePid(const wchar_t* value, DWORD& pid) {
    wchar_t* end = nullptr;
    const unsigned long number = wcstoul(value, &end, 10);
    if (!*value || *end || number == 0 || number > MAXDWORD) return false;
    pid = static_cast<DWORD>(number);
    return true;
}

static bool ResolveTarget(const wchar_t* value, DWORD& pid, std::wstring& failure) {
    if (ParsePid(value, pid)) return true;
    const auto matches = FindProcesses(value);
    if (matches.empty()) { failure = L"Process not found: " + std::wstring(value); return false; }
    if (matches.size() > 1) {
        failure = L"More than one matching process was found. Use its PID instead.";
        return false;
    }
    pid = matches.front().pid;
    return true;
}

static std::wstring Lower(const std::wstring& text) {
    std::wstring result = text;
    for (wchar_t& c : result) c = static_cast<wchar_t>(towlower(c));
    return result;
}

static std::wstring PathFileName(const std::wstring& path) {
    const wchar_t* file = wcsrchr(path.c_str(), L'\\');
    return file ? std::wstring(file + 1) : path;
}

class RemoteModules {
public:
    RemoteModules(HANDLE process, DWORD pid) : process_(process) {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE) return;
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot, &entry)) {
            do {
                cache_[Lower(entry.szModule)] = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
            } while (Module32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    uintptr_t ByName(const std::wstring& name) {
        const auto it = cache_.find(Lower(name));
        return it == cache_.end() ? 0 : it->second;
    }

    uintptr_t Load(const std::wstring& path, std::wstring& failure) {
        const std::wstring name = PathFileName(path);
        if (const uintptr_t existing = ByName(name)) return existing;

        const SIZE_T bytes = (path.size() + 1) * sizeof(wchar_t);
        void* remote = VirtualAllocEx(process_, nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!remote) { failure = L"VirtualAllocEx failed for a dependency path."; return 0; }
        const auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        bool ok = WriteProcessMemory(process_, remote, path.c_str(), bytes, nullptr) != FALSE;
        HANDLE thread = ok && loadLibrary
            ? CreateRemoteThread(process_, nullptr, 0, loadLibrary, remote, 0, nullptr) : nullptr;
        DWORD moduleBase = 0;
        if (!thread) {
            failure = L"CreateRemoteThread(LoadLibraryW) failed: " + FormatError(GetLastError());
            ok = false;
        } else {
            const DWORD wait = WaitForSingleObject(thread, 15000);
            if (wait != WAIT_OBJECT_0 || !GetExitCodeThread(thread, &moduleBase) || !moduleBase) {
                failure = L"Could not load dependency " + name + L" in the target process.";
                ok = false;
            }
            CloseHandle(thread);
        }
        VirtualFreeEx(process_, remote, 0, MEM_RELEASE);
        if (!ok) return 0;
        cache_[Lower(name)] = moduleBase;
        return moduleBase;
    }

private:
    HANDLE process_;
    std::map<std::wstring, uintptr_t> cache_;
};

struct PeView {
    std::vector<uint8_t> data;
    IMAGE_DOS_HEADER* dos = nullptr;
    IMAGE_NT_HEADERS64* nt = nullptr;
    IMAGE_SECTION_HEADER* sections = nullptr;
    size_t sectionCount = 0;

    bool Parse(std::wstring& failure) {
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) { failure = L"File is too small to be a DLL."; return false; }
        dos = reinterpret_cast<IMAGE_DOS_HEADER*>(data.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { failure = L"Missing MZ header."; return false; }
        if (dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > data.size()) {
            failure = L"Invalid PE header offset."; return false;
        }
        nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { failure = L"Missing PE signature."; return false; }
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            !(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
            failure = L"Expected an x64 Windows DLL."; return false;
        }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            failure = L"Expected an x64 PE32+ image."; return false;
        }
        if (nt->OptionalHeader.SizeOfImage == 0 || nt->OptionalHeader.SizeOfImage > 512u * 1024u * 1024u) {
            failure = L"Invalid image size."; return false;
        }
        sections = IMAGE_FIRST_SECTION(nt);
        sectionCount = nt->FileHeader.NumberOfSections;
        if (sectionCount == 0 || sectionCount > 96) { failure = L"Invalid section count."; return false; }
        return true;
    }
};

static bool CopyHeadersAndSections(const PeView& pe, std::vector<uint8_t>& image, std::wstring& failure) {
    if (image.size() != pe.nt->OptionalHeader.SizeOfImage) { failure = L"Invalid image buffer."; return false; }
    const size_t headers = (std::min)(static_cast<size_t>(pe.nt->OptionalHeader.SizeOfHeaders),
                                      (std::min)(image.size(), pe.data.size()));
    std::memcpy(image.data(), pe.data.data(), headers);
    for (size_t i = 0; i < pe.sectionCount; ++i) {
        const IMAGE_SECTION_HEADER& section = pe.sections[i];
        if (section.SizeOfRawData == 0) continue;
        if (section.PointerToRawData + section.SizeOfRawData > pe.data.size()) {
            failure = L"Section data lies outside the file."; return false;
        }
        if (section.VirtualAddress >= image.size()) continue;
        const size_t bytes = (std::min)(static_cast<size_t>(section.SizeOfRawData),
                                        image.size() - section.VirtualAddress);
        std::memcpy(image.data() + section.VirtualAddress, pe.data.data() + section.PointerToRawData, bytes);
    }
    return true;
}

static bool ApplyRelocations(const PeView& pe, std::vector<uint8_t>& image, uintptr_t remoteBase,
                             std::wstring& failure) {
    const auto& reloc = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!reloc.VirtualAddress || !reloc.Size) return true;
    if (static_cast<size_t>(reloc.VirtualAddress) + reloc.Size > image.size()) {
        failure = L"Relocation directory lies outside the image."; return false;
    }
    const int64_t delta = static_cast<int64_t>(remoteBase) -
                          static_cast<int64_t>(pe.nt->OptionalHeader.ImageBase);
    size_t offset = 0;
    while (offset + sizeof(IMAGE_BASE_RELOCATION) <= reloc.Size) {
        IMAGE_BASE_RELOCATION* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            image.data() + reloc.VirtualAddress + offset);
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            offset + block->SizeOfBlock > reloc.Size) {
            failure = L"Invalid relocation block."; return false;
        }
        const size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = reinterpret_cast<WORD*>(block + 1);
        for (size_t i = 0; i < count; ++i) {
            const int type = entries[i] >> 12;
            const uint32_t rva = block->VirtualAddress + (entries[i] & 0x0fff);
            if (type == IMAGE_REL_BASED_DIR64) {
                if (static_cast<size_t>(rva) + sizeof(uint64_t) > image.size()) {
                    failure = L"Invalid relocation entry."; return false;
                }
                uint64_t* value = reinterpret_cast<uint64_t*>(image.data() + rva);
                *value = static_cast<uint64_t>(static_cast<int64_t>(*value) + delta);
            } else if (type != IMAGE_REL_BASED_ABSOLUTE) {
                failure = L"Unsupported relocation type in an x64 DLL."; return false;
            }
        }
        offset += block->SizeOfBlock;
    }
    return true;
}

static bool ResolveImports(const PeView& pe, std::vector<uint8_t>& image, RemoteModules& modules,
                           std::wstring& failure) {
    const auto& imports = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imports.VirtualAddress || !imports.Size) return true;
    if (static_cast<size_t>(imports.VirtualAddress) + imports.Size > image.size()) {
        failure = L"Import directory lies outside the image."; return false;
    }

    size_t descriptorOffset = 0;
    for (;;) {
        if (descriptorOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > imports.Size) break;
        IMAGE_IMPORT_DESCRIPTOR* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            image.data() + imports.VirtualAddress + descriptorOffset);
        if (descriptor->Name == 0 && descriptor->FirstThunk == 0) break;

        const char* dllName = reinterpret_cast<const char*>(image.data() + descriptor->Name);
        const std::wstring wideName(dllName, dllName + std::strlen(dllName));
        HMODULE localModule = LoadLibraryW(wideName.c_str());
        if (!localModule) {
            failure = L"Could not load " + wideName + L" for import resolution.";
            return false;
        }
        const uint32_t thunkRva = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk
                                                                 : descriptor->FirstThunk;
        if (thunkRva == 0 || descriptor->FirstThunk == 0) {
            failure = L"Import descriptor without a thunk table."; return false;
        }
        for (size_t index = 0;; ++index) {
            const size_t thunkOffset = static_cast<size_t>(thunkRva) + index * sizeof(uint64_t);
            if (thunkOffset + sizeof(uint64_t) > image.size()) {
                failure = L"Import thunk lies outside the image."; return false;
            }
            const uint64_t thunk = *reinterpret_cast<const uint64_t*>(image.data() + thunkOffset);
            if (thunk == 0) break;
            FARPROC proc = nullptr;
            std::string importName;
            if (IMAGE_SNAP_BY_ORDINAL64(thunk)) {
                importName = "#" + std::to_string(static_cast<unsigned>(IMAGE_ORDINAL64(thunk)));
                proc = GetProcAddress(localModule, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(thunk)));
            } else {
                const uint32_t nameRva = static_cast<uint32_t>(thunk & 0x7fffffff);
                if (static_cast<size_t>(nameRva) + sizeof(WORD) >= image.size()) {
                    failure = L"Import name lies outside the image."; return false;
                }
                // IMAGE_IMPORT_BY_NAME: WORD hint followed by the NUL-terminated name.
                importName = reinterpret_cast<const char*>(image.data() + nameRva + sizeof(WORD));
                proc = GetProcAddress(localModule, importName.c_str());
            }
            if (!proc) {
                failure = L"Could not resolve imported function " +
                    std::wstring(importName.begin(), importName.end()) + L" (index " +
                    std::to_wstring(index) + L") from " + wideName + L".";
                return false;
            }
            HMODULE containing = nullptr;
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(proc), &containing);
            if (!containing) {
                failure = L"Could not identify the module that owns an imported function.";
                return false;
            }
            wchar_t containingPath[MAX_PATH]{};
            if (!GetModuleFileNameW(containing, containingPath, MAX_PATH)) {
                failure = L"Could not read a dependency module path."; return false;
            }
            const uintptr_t remoteContaining = modules.Load(containingPath, failure);
            if (!remoteContaining) return false;
            const uintptr_t address = remoteContaining +
                (reinterpret_cast<uintptr_t>(proc) - reinterpret_cast<uintptr_t>(containing));
            *reinterpret_cast<uint64_t*>(image.data() + descriptor->FirstThunk +
                                         index * sizeof(uint64_t)) = address;
        }
        descriptorOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return true;
}

static bool ApplyProtections(HANDLE process, uintptr_t base, const PeView& pe) {
    DWORD old = 0;
    VirtualProtectEx(process, reinterpret_cast<void*>(base),
                     pe.nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old);
    for (size_t i = 0; i < pe.sectionCount; ++i) {
        const IMAGE_SECTION_HEADER& section = pe.sections[i];
        if (section.SizeOfRawData == 0 && section.Misc.VirtualSize == 0) continue;
        DWORD protection = PAGE_READONLY;
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protection = (section.Characteristics & IMAGE_SCN_MEM_WRITE)
                ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (section.Characteristics & IMAGE_SCN_MEM_WRITE) {
            protection = PAGE_READWRITE;
        }
        const SIZE_T size = (std::max)(static_cast<SIZE_T>(section.Misc.VirtualSize),
                                       static_cast<SIZE_T>(section.SizeOfRawData));
        if (!VirtualProtectEx(process, reinterpret_cast<void*>(base + section.VirtualAddress),
                              size, protection, &old)) return false;
    }
    return true;
}

static void Append32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(value >> (i * 8)));
}

static void Append64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(value >> (i * 8)));
}

static bool Inject(HANDLE process, DWORD pid, const std::vector<uint8_t>& dllBytes,
                   std::wstring& failure) {
    PeView pe;
    pe.data = dllBytes;
    if (!pe.Parse(failure)) return false;

    RemoteModules modules(process, pid);
    void* remote = VirtualAllocEx(process, nullptr, pe.nt->OptionalHeader.SizeOfImage,
                                  MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        const DWORD error = GetLastError();
        failure = L"VirtualAllocEx failed (error " + std::to_wstring(error) + L"): " +
                  FormatError(error);
        return false;
    }
    const uintptr_t remoteBase = reinterpret_cast<uintptr_t>(remote);

    std::vector<uint8_t> image(pe.nt->OptionalHeader.SizeOfImage, 0);
    if (!CopyHeadersAndSections(pe, image, failure) ||
        !ApplyRelocations(pe, image, remoteBase, failure) ||
        !ResolveImports(pe, image, modules, failure)) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(process, remote, image.data(), image.size(), nullptr)) {
        failure = L"WriteProcessMemory: " + FormatError(GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }
    ApplyProtections(process, remoteBase, pe);
    FlushInstructionCache(process, remote, image.size());

    // Register .pdata so C++ exceptions/SEH in the mapped image can unwind.
    const HMODULE ntdllLocal = GetModuleHandleW(L"ntdll.dll");
    const FARPROC rtlAdd = ntdllLocal ? GetProcAddress(ntdllLocal, "RtlAddFunctionTable") : nullptr;
    const uintptr_t remoteNtdll = modules.ByName(L"ntdll.dll");
    const uintptr_t remoteRtlAdd = rtlAdd && remoteNtdll
        ? remoteNtdll + (reinterpret_cast<uintptr_t>(rtlAdd) -
                         reinterpret_cast<uintptr_t>(ntdllLocal)) : 0;
    const auto& exceptionDir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    const uintptr_t remotePdata = exceptionDir.VirtualAddress
        ? remoteBase + exceptionDir.VirtualAddress : 0;
    const uint32_t pdataCount = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

    std::vector<uint8_t> stub;
    stub.reserve(96);
    stub.insert(stub.end(), {0x48, 0x83, 0xEC, 0x28}); // sub rsp, 28h
    if (remoteRtlAdd && remotePdata && pdataCount) {
        stub.insert(stub.end(), {0x48, 0xB9}); Append64(stub, remotePdata);
        stub.insert(stub.end(), {0xBA}); Append32(stub, pdataCount);
        stub.insert(stub.end(), {0x49, 0xB8}); Append64(stub, remoteBase);
        stub.insert(stub.end(), {0x48, 0xB8}); Append64(stub, remoteRtlAdd);
        stub.insert(stub.end(), {0xFF, 0xD0});
    }
    stub.insert(stub.end(), {0x48, 0xB9}); Append64(stub, remoteBase);
    stub.insert(stub.end(), {0xBA, 0x01, 0x00, 0x00, 0x00}); // DLL_PROCESS_ATTACH
    stub.insert(stub.end(), {0x45, 0x33, 0xC0});
    stub.insert(stub.end(), {0x48, 0xB8});
    Append64(stub, remoteBase + pe.nt->OptionalHeader.AddressOfEntryPoint);
    stub.insert(stub.end(), {0xFF, 0xD0});
    stub.insert(stub.end(), {0x48, 0x83, 0xC4, 0x28, 0xC3});

    void* remoteStub = VirtualAllocEx(process, nullptr, stub.size(), MEM_RESERVE | MEM_COMMIT,
                                      PAGE_EXECUTE_READWRITE);
    if (!remoteStub || !WriteProcessMemory(process, remoteStub, stub.data(), stub.size(), nullptr)) {
        failure = L"Could not prepare the bootstrap: " + FormatError(GetLastError());
        if (remoteStub) VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }
    FlushInstructionCache(process, remoteStub, stub.size());

    const HANDLE thread = CreateRemoteThread(process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStub), nullptr, 0, nullptr);
    if (!thread) {
        failure = L"CreateRemoteThread: " + FormatError(GetLastError());
        VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }
    const DWORD wait = WaitForSingleObject(thread, 30000);
    DWORD result = 0;
    GetExitCodeThread(thread, &result);
    CloseHandle(thread);
    VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);

    if (wait == WAIT_TIMEOUT) {
        failure = L"DLL entry point timed out.";
        return false;
    }
    if (result == 0) {
        failure = L"DLL entry point returned FALSE (injection failed).";
        return false;
    }

    std::wcout << L"Mapped " << dllBytes.size() << L" bytes into PID " << pid
               << L" at 0x" << std::hex << remoteBase << std::dec
               << L" (no DLL file on disk).\n";
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcerr << L"Usage: injector.exe <pid|process.exe> <path-to-dll>\n"
                      L"       injector.exe <pid|process.exe> --stdin\n";
        return 2;
    }

    DWORD pid = 0;
    std::wstring failure;
    if (!ResolveTarget(argv[1], pid, failure)) {
        std::wcerr << failure << L'\n';
        return 1;
    }

    std::vector<uint8_t> dllBytes;
    const bool fromStdin = _wcsicmp(argv[2], L"--stdin") == 0;
    if (fromStdin) {
        _setmode(_fileno(stdin), _O_BINARY);
        uint8_t buffer[65536];
        size_t count = 0;
        while ((count = fread(buffer, 1, sizeof(buffer), stdin)) > 0)
            dllBytes.insert(dllBytes.end(), buffer, buffer + count);
        if (dllBytes.empty()) { std::wcerr << L"No DLL bytes were received on stdin.\n"; return 2; }
    } else {
        std::wstring dllPath;
        if (!GetAbsoluteExistingPath(argv[2], dllPath)) {
            std::wcerr << L"DLL path does not exist or is invalid: " << argv[2] << L'\n';
            return 2;
        }
        const HANDLE file = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) { std::wcerr << L"Could not open the DLL.\n"; return 2; }
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 64 * 1024 * 1024) {
            CloseHandle(file); std::wcerr << L"Invalid DLL size.\n"; return 2;
        }
        dllBytes.resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        if (!ReadFile(file, dllBytes.data(), static_cast<DWORD>(dllBytes.size()), &read, nullptr) ||
            read != dllBytes.size()) {
            CloseHandle(file); std::wcerr << L"Could not read the DLL.\n"; return 2;
        }
        CloseHandle(file);
    }

    const HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        std::wcerr << L"OpenProcess: " << FormatError(GetLastError()) << L'\n';
        return 1;
    }

    const bool ok = Inject(process, pid, dllBytes, failure);
    CloseHandle(process);
    if (!ok) { std::wcerr << failure << L'\n'; return 1; }
    return 0;
}
