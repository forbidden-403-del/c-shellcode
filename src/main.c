#include "types.h"

// Function to resolve module handle by its name
HMODULE ResolveModuleHandle(PPEB peb, const WCHAR* moduleName);
// Function to resolve function address by its name
FARPROC ResolveFunctionAddress(HANDLE hModule, const CHAR* functionName);
// Case-insensitive wide string comparison
BOOL CompareWideStringIgnoreCase(const WCHAR* str1, const WCHAR* str2);
// Case-insensitive string comparison
BOOL CompareStringIgnoreCase(const CHAR* str1, const CHAR* str2);

int mainCRTStartup() {

	PEB* peb;

// Getting the PEB address from the registers
#ifdef _WIN64
	asm("movq %%gs:%1, %0" : "=r" (peb) : "m" (*(PUINT64)(PEB_OFFSET)));
#else // WIN32
	asm("movl %%fs:%1, %0" : "=r" (peb) : "m" (*(PUINT32)(PEB_OFFSET)));
#endif // WIN32
	// Name of the module to resolve
	WCHAR moduleName[] = {L'K',L'e',L'r',L'n',L'e',L'l',L' ',L'3',L'2',L'.',L'd',L'l',L'l',0};
	// Resolve the module handle
	HANDLE kernel32Base = ResolveModuleHandle(peb,	moduleName);
	// Validate the module handle
	if (kernel32Base == NULL)
		return -2;
		
	// Name of the function to resolve
	CHAR functionName[] = {'W','r','i','t','e','C','o','n','s','o','l','e','A',0};
	// Resolve the function address
	WriteConsoleA_t WriteConsoleAFunc = (WriteConsoleA_t)ResolveFunctionAddress(kernel32Base, functionName);
	// Validate the function address
	if (WriteConsoleAFunc == NULL)
		return -1;
	// Message to print
	CHAR message[] = {'H','e','l','l','o',',',' ','W','o','r','l','d','!','\n',0};
	// Call the resolved function to print the message
	WriteConsoleAFunc(peb->ProcessParameters->StandardOutput, message, sizeof(message), NULL, NULL);

	return 0;
}

// Get the base address of a module by its name
HMODULE ResolveModuleHandle(PPEB peb,const WCHAR* moduleName) {
	PLIST_ENTRY entry = peb->LoaderData->InMemoryOrderModuleList.Flink; // Getting the first entry in the InMemoryOrderModuleList
	PVOID firstEntry = entry; // Save the first entry to detect when we loop back to it

	do {
		PLDR_MODULE entryData = (PLDR_MODULE)entry; // Cast the entry to a PLDR_MODULE structure
		// Check if the FullDllName.Buffer is NULL
		if (entryData->FullDllName.Buffer == NULL)
			break;
		// Compare the module name with the target module name
		if (CompareWideStringIgnoreCase(entryData->FullDllName.Buffer, moduleName)) { 
			return (HMODULE)((PLDR_DATA_TABLE_ENTRY)entry)->DllBase;; // Return the base address if a match is found
		}
		entry = entry->Flink; // Move to the next entry in the list
	} while (entry != NULL && entry != firstEntry); // Loop until we either find the module or loop back to the first entry

	return NULL; // Return NULL if the module was not found
}

// Get the address of a function by its name from a module base address
FARPROC ResolveFunctionAddress(HANDLE hModule, const CHAR* functionName) {
	// Getting the export directory from the module base address
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PCHAR)hModule + ((PIMAGE_NT_HEADERS)((PCHAR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.DataDirectory[0].VirtualAddress);
	// Loop through the names rin the export directoy
	for (UINT32 i = 0; i < exportDirectory->NumberOfNames; ++i) {
		// Getting the address of the function name
		PCHAR pszVar = (PCHAR)hModule + ((INT32*)((PCHAR)hModule + exportDirectory->AddressOfNames))[i];
		// Compare the function name with the target function name
		if (CompareStringIgnoreCase(pszVar, functionName)) {
			// Return the address of the function if a match is found
			return (FARPROC)((PCHAR)hModule + ((INT32*)((PCHAR)hModule + exportDirectory->AddressOfFunctions))[((PUINT16)((PCHAR)hModule + exportDirectory->AddressOfNameOrdinals))[i]]);
		}
	}
	return NULL; // Function was not found
}

// Custom case-insensitive wide string comparison
BOOL CompareWideStringIgnoreCase(const WCHAR* str1, const WCHAR* str2) {
	// Loop through each character in both strings
	while (*str1 && *str2) {
		// Convert to lowercase cause-insensitive comparison
		WCHAR c1 = towlower(*str1); 
		WCHAR c2 = towlower(*str2); 
		// Compare the characters
		if (c1 != c2) {
			return FALSE; // They differ in case-folded form
		}
		// Move to the next characters
		str1++; 
		str2++;
	}
	return (*str1 == *str2); // Both must land on the null terminator together
}

// Custom case-insensitive string comparison
BOOL CompareStringIgnoreCase(const CHAR* str1, const CHAR* str2) {
	// Loop through each character in both strings
	while (*str1 && *str2) {
		// Convert to lowercase for case-insensitive comparison
		CHAR c1 = tolower(*str1);
		CHAR c2 = tolower(*str2);
		// Compare the characters
		if (c1 != c2) {
			return FALSE; // They differ in case-folded form
		}
		// Move to the next characters
		str1++;
		str2++;
	}
	return (*str1 == *str2); // Both must land on the null terminator together
}