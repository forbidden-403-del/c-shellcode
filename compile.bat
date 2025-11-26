@echo off
setlocal enabledelayedexpansion

REM ============================================
REM  Configuration
REM ============================================
set "MINGW_DIR=mingw64"

REM Prepend MinGW to PATH (only for this script)
set "PATH=%CD%\%MINGW_DIR%\bin;%PATH%"


REM ============================================
REM  Compile section
REM ============================================
:compile

if "%~1"=="" (
    echo [!] No input files or arguments passed to GCC.
    echo Usage: build.bat file.c [options]
    goto :end
)

mkdir bin 2>nul

gcc -m32 ^
    -nostdlib ^
    -fno-asynchronous-unwind-tables ^
    -fno-unwind-tables ^
    -fno-exceptions ^
    -Wl,-T script.ld ^
    -o bin\raw.exe ^
    %*

if errorlevel 1 (
    echo [!] GCC compilation failed.
    goto :end
)

echo [+] Dumping PE header info...
objcopy -j .text -O binary bin\raw.exe bin\out.bin
:end
endlocal
