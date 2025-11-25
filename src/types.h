// Check Compiler
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__GNUC__)
	#define COMPILER_MSVC
#elif defined(__GNUC__) 
	#define COMPILER_GCC
#elif defined(__clang__)
	#define COMPILER_CLANG
#endif // Check Compiler

// Check windows
#if defined(COMPILER_MSVC)
	#if defined(_WIN64)
		#define ENVIRONMENT_x86_64
	#else
		#define ENVIRONMENT_I386
	#endif

// Check GCC
#elif defined(COMPILER_GCC) 
    #if defined(__aarch64__) || defined(_M_ARM64)
        #define ENVIRONMENT_ARM64
    #elif defined(__arm__) || defined(_M_ARM)
        #define ENVIRONMENT_ARM32
    #elif defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
        #define ENVIRONMENT_x86_64
    #elif defined(__i386__) || defined(_M_IX86)
        #define ENVIRONMENT_I386
    #else
        #error Unsupported architecture
    #endif

#elif defined(COMPILER_CLANG)
    #if defined(__aarch64__) || defined(_M_ARM64)
        #define ENVIRONMENT_ARM64
    #elif defined(__arm__) || defined(_M_ARM)
        #define ENVIRONMENT_ARM32
    #elif defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
        #define ENVIRONMENT_x86_64
    #elif defined(__i386__) || defined(_M_IX86)
        #define ENVIRONMENT_I386
    #else
        #error Unsupported architecture
    #endif
 #endif	

#if defined(COMPILER_MSVC)

	#if defined(ENVIRONMENT_I386)
		#define WINAPI __stdcall
		#define WINAPIV __cdecl
	#else
		#define WINAPI
		#define WINAPIV
	#endif

#elif defined(COMPILER_GCC) 

	#if defined(ENVIRONMENT_I386)
		#define WINAPI  __stdcall
		#define WINAPIV __cdecl
	#else
		#define WINAPI 
		#define WINAPIV 
	#endif

#elif defined(COMPILER_CLANG)

	#if defined(ENVIRONMENT_I386)

	#define WINAPI  __attribute__((stdcall))
	#define WINAPIV  __attribute__((cdecl))

	#else
		#define WINAPI
		#define WINAPIV
	#endif
#endif // Check Compiler


#ifdef ENVIRONMENT_x86_64
	#define PEB_OFFSET 0x60
#else // WIN32
	#define PEB_OFFSET 0x30
#endif // !WIN32

// Image directory entries count
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    		16
// Boolean values
#define TRUE    ((BOOL)1)
#define FALSE   ((BOOL)0)
// Character conversion macros
#define towlower(c) (((c) >= L'A' && (c) <= L'Z') ? ((c) + (L'a' - L'A')) : (c))
#define tolower(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) + ('a' - 'A')) : (c))
#define NULL ((PVOID)0)

// Types 
typedef void VOID, * PVOID,** PPVOID;

// Signed and unsigned type 
typedef signed char INT8, * PINT8;
typedef unsigned char UINT8, * PUINT8, ** PPUINT8;

typedef signed short int INT16, * PINT16;
typedef unsigned short int UINT16, * PUINT16;

typedef signed long int INT32, * PINT32;
typedef unsigned long int UINT32, * PUINT32, ** PPUINT32;

typedef signed long long int INT64, * PINT64;
typedef unsigned long long int UINT64, * PUINT64,** PPUINT64;

// Char types
typedef char CHAR, * PCHAR, ** PPCHAR;
typedef unsigned char UCHAR, * PUCHAR;

// Wide Char types
typedef UINT16 WCHAR, * PWCHAR, ** PPWCHAR;

// Boolean type
typedef UINT8 BOOL, * PBOOL,** PPBOOL;
typedef BOOL BOOLEAN;

// Handle types
typedef PVOID HANDLE;
typedef HANDLE* PHANDLE;
typedef HANDLE HMODULE;

// String types
typedef const CHAR* LPCSTR, * PCSTR;
typedef PVOID FARPROC, * PFARPROC;

// Unicode string structure
typedef struct UNICODE_STRING{
	UINT16 Length; // Length in bytes
	UINT16 MaximumLength; // Maximum length in bytes
	PWCHAR Buffer; // Pointer to the wide character buffer
} UNICODE_STRING, * PUNICODE_STRING; 

// List entry structure for linked lists
typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY* Flink; // Pointer to the next entry
	struct _LIST_ENTRY* Blink; // Pointer to the previous entry
} LIST_ENTRY, * PLIST_ENTRY;

// Loader data table entry structure
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY		InLoadOrderLinks;
	PVOID 			Reserved2[2];
	PVOID 			DllBase;
	UNICODE_STRING 	FullDllName;
	// Other fields are omitted for brevity
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// Loader module structure
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

// Process Environment Block Loader Data
typedef struct _PEB_LDR_DATA {
	UINT32							Length;
	UINT32							Initialized;
	PVOID							SsHandle;
	LIST_ENTRY						InLoadOrderModuleList;
	LIST_ENTRY						InMemoryOrderModuleList;
	LIST_ENTRY						InInitializationOrderModuleList;
}PEB_LDR_DATA, * PPEB_LDR_DATA;

// Process parameters structure
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
	// Other fields are omitted for brevity
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

// Process Environment Block
typedef struct PEB {
	BOOLEAN							InheritedAddressSpace;
	BOOLEAN							ReadImageFileExecOptions;
	BOOLEAN							BeingDebugged;
	BOOLEAN							Spare;
	HANDLE							Mutant;
	PVOID							ImageBase;
	PPEB_LDR_DATA					LoaderData;
	PRTL_USER_PROCESS_PARAMETERS	ProcessParameters;
	// Other fields are omitted for brevity
} PEB, * PPEB;

// Image export directory structure
typedef struct _IMAGE_EXPORT_DIRECTORY {
	UINT32   Characteristics;
	UINT32   TimeDateStamp;
	UINT16   MajorVersion;
	UINT16   MinorVersion;
	UINT32   Name;
	UINT32   Base;
	UINT32   NumberOfFunctions;
	UINT32   NumberOfNames;
	UINT32   AddressOfFunctions;     // RVA from base of image
	UINT32   AddressOfNames;         // RVA from base of image
	UINT32   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

// Image file header structure
typedef struct _IMAGE_FILE_HEADER {
	UINT16    Machine;
	UINT16    NumberOfSections;
	UINT32    TimeDateStamp;
	UINT32    PointerToSymbolTable;
	UINT32    NumberOfSymbols;
	UINT16    SizeOfOptionalHeader;
	UINT16    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

// Image data directory structure
typedef struct _IMAGE_DATA_DIRECTORY {
	UINT32   VirtualAddress;
	UINT32   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

// Image optional header structures for 64-bit
typedef struct _IMAGE_OPTIONAL_HEADER64 {
	UINT16        Magic;
	UINT8         MajorLinkerVersion;
	UINT8         MinorLinkerVersion;
	UINT32        SizeOfCode;
	UINT32        SizeOfInitializedData;
	UINT32        SizeOfUninitializedData;
	UINT32        AddressOfEntryPoint;
	UINT32        BaseOfCode;
	UINT64   	  ImageBase;
	UINT32        SectionAlignment;
	UINT32        FileAlignment;
	UINT16        MajorOperatingSystemVersion;
	UINT16        MinorOperatingSystemVersion;
	UINT16        MajorImageVersion;
	UINT16        MinorImageVersion;
	UINT16        MajorSubsystemVersion;
	UINT16        MinorSubsystemVersion;
	UINT32        Win32VersionValue;
	UINT32        SizeOfImage;
	UINT32        SizeOfHeaders;
	UINT32        CheckSum;
	UINT16        Subsystem;
	UINT16        DllCharacteristics;
	UINT64        SizeOfStackReserve;
	UINT64        SizeOfStackCommit;
	UINT64        SizeOfHeapReserve;
	UINT64        SizeOfHeapCommit;
	UINT32        LoaderFlags;
	UINT32        NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

// Image optional header structures for 32-bit
typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	UINT16    Magic;
	UINT8     MajorLinkerVersion;
	UINT8     MinorLinkerVersion;
	UINT32    SizeOfCode;
	UINT32    SizeOfInitializedData;
	UINT32    SizeOfUninitializedData;
	UINT32    AddressOfEntryPoint;
	UINT32    BaseOfCode;
	UINT32    BaseOfData;

	//
	// NT additional fields.
	//

	UINT32   ImageBase;
	UINT32   SectionAlignment;
	UINT32   FileAlignment;
	UINT16   MajorOperatingSystemVersion;
	UINT16   MinorOperatingSystemVersion;
	UINT16   MajorImageVersion;
	UINT16   MinorImageVersion;
	UINT16   MajorSubsystemVersion;
	UINT16   MinorSubsystemVersion;
	UINT32   Win32VersionValue;
	UINT32   SizeOfImage;
	UINT32   SizeOfHeaders;
	UINT32   CheckSum;
	UINT16   Subsystem;
	UINT16   DllCharacteristics;
	UINT32   SizeOfStackReserve;
	UINT32   SizeOfStackCommit;
	UINT32   SizeOfHeapReserve;
	UINT32   SizeOfHeapCommit;
	UINT32   LoaderFlags;
	UINT32   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

// Image NT headers structures
typedef struct _IMAGE_NT_HEADERS64 {
	UINT32 Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;


typedef struct _IMAGE_NT_HEADERS {
	UINT32 Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

// Define IMAGE_NT_HEADERS based on architecture
#if defined(ENVIRONMENT_x86_64) || defined(ENVIRONMENT_ARM64)
	typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
	typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
#else
	typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
	typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
#endif

// DOS header structure
typedef struct _IMAGE_DOS_HEADER {        // DOS .EXE header
	UINT16   e_magic;                     // Magic number
	UINT16   e_cblp;                      // Bytes on last page of file
	UINT16   e_cp;                        // Pages in file
	UINT16   e_crlc;                      // Relocations
	UINT16   e_cparhdr;                   // Size of header in paragraphs
	UINT16   e_minalloc;                  // Minimum extra paragraphs needed
	UINT16   e_maxalloc;                  // Maximum extra paragraphs needed
	UINT16   e_ss;                        // Initial (relative) SS value
	UINT16   e_sp;                        // Initial SP value
	UINT16   e_csum;                      // Checksum
	UINT16   e_ip;                        // Initial IP value
	UINT16   e_cs;                        // Initial (relative) CS value
	UINT16   e_lfarlc;                    // File address of relocation table
	UINT16   e_ovno;                      // Overlay number
	UINT16   e_res[4];                    // Reserved words
	UINT16   e_oemid;                     // OEM identifier (for e_oeminfo)
	UINT16   e_oeminfo;                   // OEM information; e_oemid specific
	UINT16   e_res2[10];                  // Reserved words
	INT32   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

// Function pointer type for WriteConsoleA_t function
typedef BOOL(WINAPI* WriteConsoleA_t)(HANDLE hConsoleOutput, LPCSTR lpBuffer, UINT32 nNumberOfCharsToWrite, UINT32* lpNumberOfCharsWritten, UINT32* lpReserved);

