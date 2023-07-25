#include "commun.h"


void (WINAPI* pSleep)(
    DWORD dwMilliseconds
) = Sleep;



typedef NTSTATUS(NTAPI* NtQueryInformationThreadPtr)(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );


typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


 


void SuspendThreads(DWORD TheThreadId) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
        return;

    do {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != TheThreadId) {

            SuspendThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID));
        }
    } while (Thread32Next(hSnapshot, &te32));
}


void ResumeThreads(DWORD TheThreadId) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
        return;

    do {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != TheThreadId) {

            ResumeThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID));
        }
    } while (Thread32Next(hSnapshot, &te32));

}


void HeapEncryptDecrypt() {
    
    DWORD numHeaps = GetProcessHeaps(0, NULL);
    HANDLE* heaps = (HANDLE*)malloc(sizeof(HANDLE) * numHeaps);
    GetProcessHeaps(numHeaps, heaps);

    PROCESS_HEAP_ENTRY entry;
    for (DWORD i = 0; i < numHeaps; i++) {
        // skip the default process heap
        if (heaps[i] == GetProcessHeap()) continue;

        SecureZeroMemory(&entry, sizeof(entry));
        while (HeapWalk(heaps[i], &entry)) {
            if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
                xor_aa((BYTE*)entry.lpData, entry.cbData);
            }
        }
    }
    free(heaps);


}






DWORD WINAPI EncryptDecryptThread(LPVOID lpParam) {
    DWORD mainThreadId = *((DWORD*)lpParam);
    DWORD currentThreadId = GetCurrentThreadId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot. Error: %lu\n", GetLastError());
        return 1;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

                if (hThread != NULL) {
                    if (te32.th32ThreadID == mainThreadId) {
                        SuspendThread(hThread);
                    }

                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

                    THREAD_BASIC_INFORMATION tbi;
                    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

                    if (status == 0) {
                        PVOID teb_base_address = tbi.TebBaseAddress;
                        PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
                            PVOID stack_top = tib->StackLimit;
                            PVOID stack_base = tib->StackBase;

                            xor_stack(stack_top, stack_base);
                        }
                        else {
                            printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
                        }

                        free(tib);
                    }
                    else {
                        printf("NtQueryInformationThread failed with status: 0x%X\n", status);
                    }
                }
                else {
                    printf("Failed to open thread. Error: %lu\n", GetLastError());
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    else {
        printf("Thread32First failed. Error:%lu\n", GetLastError());
    }


    Sleep(10000); // Specify number of ms to sleep


    /////

    // Decrypt the stacks and resume threads
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

                    THREAD_BASIC_INFORMATION tbi;
                    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

                    if (status == 0) {
                        PVOID teb_base_address = tbi.TebBaseAddress;
                        PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
                            PVOID stack_top = tib->StackLimit;
                            PVOID stack_base = tib->StackBase;

                            xor_stack(stack_top, stack_base);
                        }
                        else {
                            printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
                        }

                        free(tib);
                    }
                    else {
                        printf("NtQueryInformationThread failed with status: 0x%X\n", status);
                    }

                    if (te32.th32ThreadID == mainThreadId) {
                        ResumeThread(hThread);
                        // delay for the main thread to be resumed
                        Sleep(1000);
                    }
                    CloseHandle(hThread);
                }
                else {
                    printf("Failed to open thread. Error: %lu\n", GetLastError());
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    else {
        printf("Thread32First failed. Error:%lu\n", GetLastError());
    }

    CloseHandle(hSnapshot);
    return 0;
}




void HappySleep(const char* moduleName) {

    
    DWORD mainThreadId = GetCurrentThreadId();

    // Suspend all threads , only the main thread 
    SuspendThreads(mainThreadId);
    // Iterate over all heaps allocations , and do encryption.
    HeapEncryptDecrypt();
    
    
    HANDLE hEncryptDecryptThread = CreateThread(NULL, 0, EncryptDecryptThread, &mainThreadId, 0, NULL);
    if (hEncryptDecryptThread == NULL) {
        printf("Failed to create encrypt/decrypt thread. Error: %lu\n", GetLastError());
        return ;
    }
    WaitForSingleObject(hEncryptDecryptThread, INFINITE);
    CloseHandle(hEncryptDecryptThread);
    

    // Decrypt Allocations
    HeapEncryptDecrypt();
    // Resume Threads
    ResumeThreads(mainThreadId);


}