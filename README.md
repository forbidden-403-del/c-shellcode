# c-shellcode

## Table of Contents
- [Overview](#overview)
- [Supported Targets](#supported-targets)
- [Cross-Platform Architecture](#cross-platform-architecture)
- [Step-by-Step Guide](#step-by-step-guide)
- [Usage](#usage)
- [Files](#files)
- [Requirements](#requirements)
- [Detection & Ethics Note](#detection--ethics-note)
- [References](#references)

This project demonstrates Windows API resolution and position-independent shellcode techniques in C, without including any standard Windows headers or libraries. All required types and structures (PEB, PE headers, NT structures, etc.) are defined in custom header files. The code locates the PEB, enumerates loaded modules to find Kernel32.dll, parses PE headers to resolve exported function addresses, and prints a message using only resolved addresses. No standard library, CRT, or Windows headers are used, and the project cross-compiles for multiple architectures (x86, x64, ARM64) and platforms (Windows, Linux) from a single codebase. See below for step-by-step details and code samples.

## Overview

This project demonstrates how to:
- Locate the Process Environment Block (PEB)
- Enumerate loaded modules
- Parse PE headers to resolve exported function addresses
- Print a message to the console using only resolved addresses
- Cross-compile for multiple architectures and platforms
- Extract raw shellcode from the `.text` section

**Key characteristics:**
- No reliance on standard Windows headers, CRT, or library dependencies
- Custom type definitions and PE/NT structures defined from scratch

## Supported Targets

| Platform | Architecture | Target Triple |
|----------|--------------|---------------|
| Windows | x86/x64/ARM64 | `i386-pc-windows-msvc`, `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc` |
| Linux | x86/x64/ARM64 | `i386-pc-linux-gnu`, `x86_64-pc-linux-gnu`, `aarch64-pc-linux-gnu` |

## Cross-Platform Architecture

The project uses compile-time macros to detect and adapt to different architectures:

### Architecture Detection (`src/architecture.h`)
```c
#if defined(__x86_64__) || defined(_M_X64)
    #define ENVIRONMENT_X86_64
#elif defined(__i386__) || defined(_M_IX86)
    #define ENVIRONMENT_I386
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define ENVIRONMENT_ARM64
#endif
```

### Calling Conventions (`src/environment.h`)
```c
#if defined(ENVIRONMENT_I386)
    #define WINAPI __stdcall    // 32-bit uses stdcall
#else
    #define WINAPI              // 64-bit uses Microsoft x64 ABI
#endif
```

### Pointer Sizes (`src/primitives.h`)
```c
#if defined(ENVIRONMENT_X86_64)
    typedef UINT64 USIZE;       // 64-bit pointers
#else
    typedef UINT32 USIZE;       // 32-bit pointers
#endif
```

### PEB Access (`src/peb.c`)
```c
#if defined(ENVIRONMENT_X86_64)
    asm("movq %%gs:0x60, %0" : "=r"(peb));  // GS segment
#elif defined(ENVIRONMENT_I386)
    asm("movl %%fs:0x30, %0" : "=r"(peb));  // FS segment
#elif defined(ENVIRONMENT_ARM64)
    asm("ldr %0, [x18, #0x60]" : "=r"(peb)); // X18 register
#endif
```

## Step-by-Step Guide

### 1. Define Custom Types and Structures
- Do not include Windows headers (e.g., `windows.h`)
- Create your own type definitions for basic types (e.g., `DWORD`, `BYTE`, `HANDLE`)
- Define necessary PE/NT structures in your own headers (see `src/primitives.h`, `src/peb.h`, `src/pe.h`)

### 2. Locate PEB and Kernel32.dll
- Use inline assembly to get the PEB address (architecture-specific)
- Traverse the PEB to enumerate loaded modules and find the base address of `Kernel32.dll`

### 3. Parse PE Headers to Resolve API Addresses
- Read the PE export table of `Kernel32.dll` to find function addresses (e.g., `WriteConsoleA`)
- Implement your own PE parsing logic in C (see `src/pe.c`)

### 4. Print Message Without Dependencies
- Use the resolved address of `WriteConsoleA` to print "Hello, World!"
- Do not use any standard library functions or headers

### 5. Build and Run
- Use `build.bat` to compile for all targets
- Run the executable. It should print:
  ```
  Hello, World!
  ```

## Usage

1. Build the project using the provided batch file:
   ```batch
   build.bat
   ```
2. Run the resulting executable. It should print:
   ```
   Hello, World!
   ```

**Build outputs** (per target in `bin/windows/` and `bin/linux/`):
- `.exe`/`.elf` - Compiled executable
- `.bin` - Raw shellcode (extracted `.text` section)
- `_disasm.txt` - Disassembly of `.text` section
- `_sections.txt` - PE/ELF section headers
- `_strings.txt` - Strings found in shellcode

## Files

- `src/main.c` - Main logic for module/function resolution and message printing
- `src/architecture.h` - Compiler and architecture detection macros
- `src/environment.h` - Platform-specific definitions (calling conventions)
- `src/primitives.h` - Custom type definitions for Windows internals
- `src/peb.h`, `src/peb.c` - PEB/LDR structures and module resolution
- `src/pe.h`, `src/pe.c` - PE header structures and export resolution
- `src/string.h`, `src/string.c` - Custom string comparison functions
- `build.bat` - Main build script (builds all targets)
- `compile-windows.bat`, `compile-linux.bat` - Platform-specific compilation scripts
- `linker.script` - Custom linker script for section ordering
- `orderfile.txt` - Function ordering (entry point first)

## Requirements

- LLVM/Clang toolchain with `lld` linker
- LLVM tools: `llvm-objcopy`, `llvm-objdump`, `llvm-strings`

## Detection & Ethics Note

**Research-only.**
- This technique does not guarantee stealth. Security products may detect PEB walking, API resolution patterns, or similar behaviors.
- Do not use to evade detection, run untrusted code, or break laws/policies.
- Always test in isolated, offline VMs and follow responsible disclosure and research ethics.

## References

