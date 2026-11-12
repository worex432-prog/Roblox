# Roblox overlay loader

Memory-only loader for the OpenGL overlay DLL (`payload.dll`).

The DLL is **never written to disk**. `inject.py` reads the DLL into a Python
`bytes` buffer and pipes it to `injector.exe --stdin`, which maps the image into
the target process by hand:

1. reads the DLL bytes (local file or an HTTPS URL into memory),
2. validates the PE header (x64 DLL),
3. maps headers and sections into the target,
4. applies base relocations,
5. resolves imports against the target's loaded modules,
6. registers `.pdata` so exceptions can unwind,
7. calls the DLL entry point directly (no `LoadLibraryW`, no file on disk).

Because the image is mapped manually and never loaded by the Windows loader, the
DLL is built with `/Zc:threadSafeInit-` (no TLS directory) and locates its own
module handle for resources itself.

## Usage

```bat
python inject.py javaw.exe
python inject.py 12345
python inject.py javaw.exe --dll C:\path\to\payload.dll
python inject.py javaw.exe --url https://raw.githubusercontent.com/worex432-prog/Roblox/main/payload.dll --sha256 <64 hex>
python inject.py javaw.exe --injector C:\path\to\injector.exe
```

* `target` – target PID or process name (`javaw.exe`, …).
* `--dll` – local DLL to load (default: `payload.dll` next to `inject.py`).
* `--url` + `--sha256` – optional; downloads the DLL into memory only.
* `--injector` – path to `injector.exe` (default: next to `inject.py`, then
  `outputs\`, then `build\Release\`).

The injector can also be used directly:

```bat
injector.exe javaw.exe payload.dll
injector.exe 12345 payload.dll
type payload.dll | injector.exe 12345 --stdin
```

## Default settings

| Feature | Key | Mode | Details |
| --- | --- | --- | --- |
| Triggerbot | `L` | Hold | click delay 50-75 ms, hold 160-200 ms |
| Aim Assist | `L` | Hold | Legit, FOV 30, range 3.5, smoothing 100, random speed on, Y 50–70, X 200–300 |
| Crystal Spam | RMB | Hold | |
| Friend Add | `N` | Toggle | enabled by default, radius 8 |
| GUI | `Ctrl + Right Shift` | – | opens/closes the menu |

## Building

* `payload.dll` – `build_features.bat` in the source tree (`build_features\mob.dll`).
* `injector.exe` – `build_injector.bat` (MSVC x64, `/MT`).

## Files

| File | Purpose |
| --- | --- |
| `payload.dll` | The overlay DLL injected into the target. |
| `injector.exe` | Native x64 manual mapper (maps `--stdin` bytes or a file path). |
| `inject.py` | Python wrapper; streams the DLL to `injector.exe --stdin`. |
| `injector.cpp` | Source of the manual mapper. |
| `build_injector.bat` | Builds `injector.exe` with MSVC. |
