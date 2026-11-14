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
| Triggerbot | `Z` | Toggle | while the module is on, holding LMB attacks the target under the crosshair; the first press stays a real manual swing for ~200 ms (visible in keystrokes), then the trigger takes over with clicks delayed 50-75 ms. Crit policy (panel row "Криты"): **Combo** - never waits for crits, swings as soon as the sword is ready; **Умные криты** (default) - waits for the falling window wherever a crit is possible; **Тупые криты** - hits on the ground immediately and waits at most ~100 ms airborne, so hits may land without a crit |
| Aim Assist | `X` | Toggle | Legit, FOV 30, range 3.5, smoothing 100 ms, random speed on, X 70-100, Y 50-70, aim only after a hit (2 s window), keep target 3 s, only while the mouse moves |
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
