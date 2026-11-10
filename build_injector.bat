@echo off
rem ---------------------------------------------------------------------------
rem  Manual build of injector.exe (memory-only manual mapper).
rem ---------------------------------------------------------------------------
setlocal

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "OUT=%ROOT%\outputs"

set "VS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"
set "VCVER=14.51.36231"
set "MSVC=%VS%\VC\Tools\MSVC\%VCVER%"
set "CLBIN=%MSVC%\bin\Hostx64\x64\cl.exe"
set "LINKBIN=%MSVC%\bin\Hostx64\x64\link.exe"
set "SDKINC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
set "SDKLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0"

if not exist "%OUT%" mkdir "%OUT%"

set "DEFS=/D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN"
set "SYSINC=/I"%MSVC%\include" /I"%SDKINC%\ucrt" /I"%SDKINC%\um" /I"%SDKINC%\shared""
set "CXXOPTS=/nologo /c /std:c++17 /EHsc /utf-8 /O2 /MT %DEFS%"

echo [1/2] injector.cpp
"%CLBIN%" %CXXOPTS% %SYSINC% "%ROOT%\injector.cpp" /Fo"%OUT%\injector.obj" || goto :fail

echo [2/2] link
"%LINKBIN%" /NOLOGO /MACHINE:X64 /SUBSYSTEM:CONSOLE /OUT:"%OUT%\injector.exe" ^
  /LIBPATH:"%MSVC%\lib\x64" /LIBPATH:"%SDKLIB%\ucrt\x64" /LIBPATH:"%SDKLIB%\um\x64" ^
  "%OUT%\injector.obj" || goto :fail

echo.
echo Built: %OUT%\injector.exe
exit /b 0

:fail
echo.
echo BUILD FAILED
exit /b 1
