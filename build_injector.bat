@echo off
rem ---------------------------------------------------------------------------
rem  Build injector.exe (memory-only, payload embedded as RCDATA).
rem  No download, no DLL file on disk. GUI subsystem, no console.
rem ---------------------------------------------------------------------------
setlocal
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "GXX=g++"
where g++ >nul 2>&1
if errorlevel 1 set "GXX=C:\Users\worex\AppData\Local\Temp\opencode\overlay-build\w64devkit\w64devkit\bin\g++.exe"
set "WINDRES=%GXX:g++.exe=windres.exe%"

echo [1/2] payload resource
"%WINDRES%" --include-dir "%ROOT%" "%ROOT%\payload.rc" -O coff -o "%ROOT%\payload.res.o"
if errorlevel 1 goto :fail

echo [2/2] injector.exe
"%GXX%" -std=c++17 -O2 -mwindows -municode -static -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN ^
  "%ROOT%\injector.cpp" "%ROOT%\payload.res.o" -o "%ROOT%\injector.exe" ^
  -luser32 -lkernel32
if errorlevel 1 goto :fail

echo Built: %ROOT%\injector.exe
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
