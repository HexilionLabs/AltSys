#include <windows.h>
#include <stdio.h>

int main() {
    DWORD pid = GetCurrentProcessId();
    printf("[*] PID: %lu (0x%X)\n", pid, pid);

    while (TRUE) {
        void* pMem = VirtualAlloc(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pMem) {
            printf("[+] VirtualAlloc success at address %p\n", pMem);

            VirtualFree(pMem, 0, MEM_RELEASE);
        }
        else {
            printf("[-] VirtualAlloc failed! Error: %lu\n", GetLastError());
        }

        Sleep(1000);
    }

    return 0;
}