@echo off
rem ---------------------------------------------------------------------------
rem  Build the standalone silent injector (injector.exe).
rem  Downloads payload.dll from GitHub, loads it into Minecraft and registers
rem  it as a JVMTI agent. Uses MinGW (w64devkit) if available.
rem ---------------------------------------------------------------------------
setlocal

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "GXX=g++"
where g++ >nul 2>&1
if errorlevel 1 set "GXX=C:\Users\worex\AppData\Local\Temp\opencode\overlay-build\w64devkit\w64devkit\bin\g++.exe"

echo Building injector.exe ...
"%GXX%" -std=c++17 -O2 -mwindows -municode -static -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN ^
  "%ROOT%\injector_gui.cpp" -o "%ROOT%\injector.exe" ^
  -lurlmon -lwininet -lshell32 -luser32 -lkernel32
if errorlevel 1 goto :fail

echo Built: %ROOT%\injector.exe
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
