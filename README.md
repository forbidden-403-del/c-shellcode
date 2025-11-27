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

This project demonstrates manual Windows API resolution and shellcode techniques in C, without including any standard Windows headers. All required types and structures (PEB, PE headers, etc.) are defined manually in src/types.h. The code locates the PEB, enumerates loaded modules to find Kernel32.dll, parses PE headers to resolve exported function addresses, and prints a message using only resolved addresses. No standard library or Windows headers are used making it suitable for shellcode and low-level research. See the expanded README for step-by-step details and code samples.

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


## types.h
 This file contains all custom Windows types, macros, calling conventions, and internal structures required for this project. It replaces `windows.h`, `winternl.h`, and `winnt.h`, allowing the code to compile with no external dependencies.

## Compiler, Architecture & Calling Conventions 
 The file begins by detecting the compiler (`MSVC`, `GCC`, `Clang`) and CPU architecture (`x86`, `x64`, `ARM32`, `ARM64`).
   - `ENVIRONMENT_x86_64`, `ENVIRONMENT_I386`, etc.
   - `WINAPI` / `WINAPIV` calling conventions
   - 32‑bit uses `__stdcall` and `__cdecl`
   - 64‑bit leaves them blank (Windows x64 uses a single calling convention)
## Primitive Types
 All primitive Win32 types are recreated manually:

### Void
```
typedef void VOID, * PVOID,** PPVOID;
```
 
### Signed and unsigned
```
typedef signed char INT8, * PINT8;
typedef unsigned char UINT8, * PUINT8, ** PPUINT8;
typedef signed short int INT16, * PINT16;
typedef unsigned short int UINT16, * PUINT16;
typedef signed long int INT32, * PINT32;
typedef unsigned long int UINT32, * PUINT32, ** PPUINT32;
typedef signed long long int INT64, * PINT64;
typedef unsigned long long int UINT64, * PUINT64,** PPUINT64;
```

### Char
```
typedef char CHAR, * PCHAR, ** PPCHAR;
typedef unsigned char UCHAR, * PUCHAR;
```

### Wide char
```
typedef UINT16 WCHAR, * PWCHAR, ** PPWCHAR;
```

### Boolean
```
typedef UINT8 BOOL, * PBOOL,** PPBOOL;
typedef BOOL BOOLEAN;
```

### Handle
```
typedef PVOID HANDLE;
typedef HANDLE* PHANDLE;
typedef HANDLE HMODULE;
```

### String
```
typedef const CHAR* LPCSTR, * PCSTR;
typedef PVOID FARPROC, * PFARPROC;
```

## Struct Types
### Unicode string

```
typedef struct UNICODE_STRING {
    UINT16 Length;
    UINT16 MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
```
Used for identifying module names such as `"KERNEL32.DLL"` inside the PEB loader list.

- `Length` → Length in bytes
- `MaximumLength` → Allocated buffer size
- `Buffer` → Pointer to UTF‑16 characters

### List entry
```
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;
```
Windows uses this in the PEB to maintain lists of loaded modules.
- `Flink` → Pointer to the next entry
- `Blink` → Pointer to the previous entry

### Loader data table entry
```
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY		   InLoadOrderLinks;
	PVOID 			   Reserved2[2];
	PVOID 			   DllBase;
	UNICODE_STRING 	FullDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
```
- `InLoadOrderLinks` → Used to move to the next module
- `DllBase` → Module base address
- `FullDllName` → Module name (“kernel32.dll”)

### Loader module
```
typedef struct _LDR_MODULE {
	LIST_ENTRY						InMemoryOrderModuleList;
	LIST_ENTRY						InLoadOrderModuleList;
	LIST_ENTRY						InInitializationOrderModuleList;
	PVOID							BaseAddress;
	PVOID							EntryPoint;
	UINT32							SizeOfImage;
	UNICODE_STRING		        	FullDllName;
	UNICODE_STRING		        	BaseDllName;
	UINT32							Flags;
	INT16							LoadCount;
	INT16							TlsIndex;
	LIST_ENTRY						HashTableEntry;
	UINT32							TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;
```
- `InMemoryOrderModuleList` → Pointers to previous and next `LDR_MODULE` in memory placement order.
- `InLoadOrderModuleList` → Pointers to previous and next `LDR_MODULE` in load order.
- `InInitializationOrderModuleList` → Pointers to previous and next `LDR_MODULE` in initialization order.
- `BaseAddress` → Module base address, Equivalent to `HMODULE`.
- `EntryPoint` → Module entry point.
- `SizeOfImage` → Sum of all image's sections placed in memory.
- `FullDllName` → Path and name of module.
- `BaseDllName` → Module name only.
- `Flags` → Loader-specific flags describing the module state.
- `LoadCount` → How many times this module has been loaded (reference count).
- `TlsIndex` → Index of the module’s _Thread Local Storage_ entry.
- `HashTableEntry` → Hash table entry of the module.
- `TimeDateStamp` → Timestamp from the PE header.


### PEB loader metadata
```
typedef struct _PEB_LDR_DATA {
	UINT32							Length;
	UINT32							Initialized;
	PVOID	                        SsHandle;
	LIST_ENTRY						InLoadOrderModuleList;
	LIST_ENTRY						InMemoryOrderModuleList;
	LIST_ENTRY						InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
```

Loader metadata inside the PEB:
- `Length` → Size of the `PEB_LDR_DATA` structure in bytes.
- `Initialized` → Boolean-like value indicating whether loader data has been fully initialized.
- `SsHandle` → Subsystem handle.
- `InLoadOrderModuleList` → Pointers to previous and next `LDR_MODULE` in load order.
- `InInitializationOrderModuleList` → Pointers to previous and next `LDR_MODULE` in initialization order.

### Process parameters structure
```
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	UINT32							MaximumLength;
	UINT32							Length;
	UINT32							Flags;
	UINT32							DebugFlags;
	HANDLE							ConsoleHandle;
	UINT32							ConsoleFlags;
	HANDLE							StandardInput;
	HANDLE 							StandardOutput;
	HANDLE							StandardError;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
```
- `MaximumLength` → Total allocated size of the structure in bytes.
- `Length` → The size of the structure currently in use.
- `Flags` → Process parameter flags.
- `DebugFlags` → Flags used internally for debugging.
- `ConsoleHandle` → Handle to the process’s console window (if it has one).
- `ConsoleFlags` → Console mode flags controlling input/output behavior.
- `StandardInput` → Handle to the process’s standard input (`stdin`).
- `StandardOutput` → Handle to standard output (`stdout`).
- `StandardError` → Handle to standard error (`stderr`).

### Process Environment Block
```
typedef struct PEB {
	BOOLEAN							InheritedAddressSpace;
	BOOLEAN							ReadImageFileExecOptions;
	BOOLEAN							BeingDebugged;
	BOOLEAN							Spare;
	HANDLE							Mutant;
	PVOID							ImageBase;
	PPEB_LDR_DATA					LoaderData;
	PRTL_USER_PROCESS_PARAMETERS	ProcessParameters;
} PEB, * PPEB;
```
- `InheritedAddressSpace` → Indicates if the process inherited its address space from its parent.
- `ReadImageFileExecOptions` → Indicates whether image file execution options (`IFEO`) were applied to the process.
- `BeingDebugged` → Nonzero if the process is being debugged (`DebuggerPresent` flag).
- `Spare` → Reserved/unused padding byte.
- `Mutant` → Handle to a synchronization object used during early process startup.
- `ImageBase` → Base address where the main executable image is loaded in memory.
- `LoaderData` → (`PPEB_LDR_DATA`) Pointer to loader metadata (linked lists of loaded modules).
- `ProcessParameters` → (`PRTL_USER_PROCESS_PARAMETERS`)	Pointer to the process’s parameters.


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
