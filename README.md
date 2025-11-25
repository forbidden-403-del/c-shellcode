# c-shellcode

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Step-by-Step Guide](#step-by-step-guide)
- [Usage](#usage)
- [Files](#files)
- [Requirements](#requirements)
- [Detection & Ethics Note](#detection--ethics-note)
- [References](#references)

This project demonstrates manual Windows API resolution and shellcode techniques in C, without including any standard Windows headers. All required types and structures (PEB, PE headers, etc.) are defined manually in src/types.h. The code locates the PEB, enumerates loaded modules to find Kernel32.dll, parses PE headers to resolve exported function addresses, and prints a message using only resolved addresses. No standard library or Windows headers are used�making it suitable for shellcode and low-level research. See the expanded README for step-by-step details and code samples.

## Overview
This project shows how to:
- Manually locate the Process Environment Block (PEB)
- Enumerate loaded modules to find the base address of `Kernel32.dll`
- Parse PE headers to resolve the address of exported functions (e.g., `WriteConsoleA`)
- Print a message to the console using only resolved addresses, without standard library calls

## Features
- No reliance on standard Windows headers or libraries
- Custom type definitions and PE/NT structures
- Works on x86 and x64 Windows
- Demonstrates techniques useful for shellcode and low-level Windows internals

## Step-by-Step Guide

### 1. Choose Compiler and Build Environment
- Use MinGW or a compatible C compiler that allows building raw executables without linking standard libraries.
- Example: Install MinGW and use `gcc`.

### 2. Define Custom Types and Structures
- Do not include Windows headers (e.g., `windows.h`).
- Create your own type definitions for basic types (e.g., `DWORD`, `BYTE`, `ULONG_PTR`).
- Define necessary PE/NT structures in your own header (see `src/types.h`).

### 3. Manually Locate PEB and Kernel32.dll
- Use inline assembly or compiler intrinsics to get the PEB address.
- Traverse the PEB to enumerate loaded modules and find the base address of `Kernel32.dll`.

### 4. Parse PE Headers to Resolve API Addresses
- Read the PE export table of `Kernel32.dll` to find function addresses (e.g., `WriteConsoleA`).
- Implement your own PE parsing logic in C.

### 5. Print Message Without Dependencies
- Use the resolved address of `WriteConsoleA` to print "Hello world!".
- Do not use any standard library functions or headers.

### 6. Build and Run
- Use the provided batch files (`build.bat`, `compile.bat`) to compile the project.
- Run the executable. It should print:
  ```
  Hello world!
  ```

## Usage
1. Build the project using the provided batch files:
   - `build.bat` or `compile.bat`
2. Run the resulting executable. It should print:
   ```
   Hello world!
   ```

## Files
- `src/main.c`: Main logic for module/function resolution and message printing
- `src/types.h`: Custom type and structure definitions for Windows internals
- `build.bat`, `compile.bat`, `install_mingw.bat`: Build and setup scripts

## Requirements
- Windows (x86 or x64)
- MinGW or compatible C compiler

## Detection & Ethics Note

**Research-only.**
- This technique does not guarantee stealth. Security products may detect hardware breakpoint usage, VEH patterns, or emulator behavior.
- Do not use to evade detection, run untrusted code, or break laws/policies.
- Always test in isolated, offline VMs and follow responsible disclosure and research ethics.

## References
Add references to documentation, articles, or resources here.