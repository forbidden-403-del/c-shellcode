@echo off
setlocal enabledelayedexpansion

@REM REM === Target directory ===
@REM set MINGW_DIR=mingw64
@REM set INSTALL_SCRIPT=install_mingw.bat
@REM call "%INSTALL_SCRIPT%" || (
@REM         echo Install failed.
@REM         exit /b 1
@REM     )
set "PATH=%CD%\%MINGW_DIR%\bin;%PATH%"

:compile
REM ============================
REM Compile with gcc (all args passed to this .bat)
REM Example:
REM   build.bat main.c -o main.exe
REM ============================
if "%~1"=="" (
    echo No files/arguments passed to gcc. Skipping compilation.
    goto :end
)

gcc -m32 -nostdlib -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions -Wl,-T script.ld -o raw.exe %*
if errorlevel 1 (
    echo GCC compilation failed.
    goto :end
)
objdump -x raw.exe
:end
endlocal