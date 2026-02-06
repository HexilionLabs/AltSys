#include "AltSyscall.h"

Pssn_dispatch_table GlobalDispatchTable = NULL;
PspServiceDescriptorGroupTable* GlobalKernelDescriptorTable = NULL;
PspServiceDescriptorRow GlobalOriginalRowBackup = { 0 };
BOOLEAN GlobalIsEngineInstalled = FALSE;
UINT64 GlobalDriverBaseAddress = 0;
ULONG GlobalTargetPID = 0;

void DisableWriteProtection(PULONG_PTR OriginalCr0)
{
    ULONG_PTR cr0 = __readcr0();
    *OriginalCr0 = cr0;
    cr0 &= ~(0x10000);
    __writecr0(cr0);
    _disable();
}

void EnableWriteProtection(ULONG_PTR OriginalCr0)
{
    _enable();
    __writecr0(OriginalCr0);
}

PVOID ScanPattern(PVOID Base, SIZE_T Size, const char* Pattern, const char* Mask)
{
    const unsigned char* pBase = (const unsigned char*)Base;
    size_t patternLen = strlen(Mask);

    for (size_t i = 0; i < Size - patternLen; i++)
    {
        BOOLEAN found = TRUE;
        for (size_t j = 0; j < patternLen; j++)
        {
            if (Mask[j] != '?' && Pattern[j] != (char)pBase[i + j])
            {
                found = FALSE;
                break;
            }
        }
        if (found) return (PVOID)(pBase + i);
    }
    return NULL;
}

PVOID GetKernelModuleBase(const char* ModuleName)
{
    PVOID moduleBase = NULL;
    ULONG bufferSize = 0;
    AuxKlibInitialize();

    if (NT_SUCCESS(AuxKlibQueryModuleInformation(&bufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL)))
    {
        PAUX_MODULE_EXTENDED_INFO modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'ModS');
        if (modules)
        {
            if (NT_SUCCESS(AuxKlibQueryModuleInformation(&bufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules)))
            {
                ULONG count = bufferSize / sizeof(AUX_MODULE_EXTENDED_INFO);
                for (ULONG i = 0; i < count; i++)
                {
                    if (strstr((char*)modules[i].FullPathName, ModuleName))
                    {
                        moduleBase = modules[i].BasicInfo.ImageBase;
                        break;
                    }
                }
            }
            ExFreePoolWithTag(modules, 'ModS');
        }
    }
    return moduleBase;
}

PVOID FindPspServiceDescriptorGroupTable(PVOID KernelBase)
{
    const char Pattern[] = "\x48\x89\x5c\x24\x08\x55\x56\x57\x41\x56\x41\x57\x48\x83\xec\x30\x48\x83\x64\x24\x70\x00\x48\x8b\xf1\x65\x48\x8b\x2c\x25\x88\x01\x00\x00\xf6\x45\x03\x04";
    const char Mask[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(KernelBase);
    if (!NtHeaders) return NULL;

    PVOID MatchAddress = ScanPattern(KernelBase, NtHeaders->OptionalHeader.SizeOfImage, Pattern, Mask);

    if (MatchAddress)
    {
        DbgPrint("[+] Found Pattern at %p\n", MatchAddress);

        PUCHAR InstructionAddress = (PUCHAR)MatchAddress + 0x77;

        INT32 Disp32 = *(INT32*)(InstructionAddress + 3);

        PVOID AbsoluteAddress = InstructionAddress + 7 + Disp32;

        DbgPrint("[+] Resolved PspServiceDescriptorGroupTable at %p\n", AbsoluteAddress);
        return AbsoluteAddress;
    }

    return NULL;
}

void EnableAltSyscallOnThread(PKTHREAD Thread)
{
    if (!Thread) return;

    PUCHAR PtrHeader = (PUCHAR)Thread;

    UCHAR DebugActive = *(PtrHeader + KTHREAD_DEBUG_ACTIVE_OFFSET);

    if (DebugActive & 0x04) return;

    *(PtrHeader + KTHREAD_DEBUG_ACTIVE_OFFSET) |= 0x20;
}

void EnableAltSyscallOnProcess(PEPROCESS Process)
{
    if (!Process) return;

    PUCHAR PtrProcess = (PUCHAR)Process;

    PPspSyscallProviderDispatchContext Context =
        (PPspSyscallProviderDispatchContext)(PtrProcess + EPROCESS_DISPATCH_CONTEXT_OFFSET);

    Context->Slot = ALT_SYSCALL_SLOT_INDEX;
}

void EnableAltSyscallsSystemWide()
{
    const char* TargetName = "dummy.exe";

    PEPROCESS CurrentProcess = IoGetCurrentProcess();
    PLIST_ENTRY ListHead = (PLIST_ENTRY)((PUCHAR)CurrentProcess + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET);
    PLIST_ENTRY ListEntry = ListHead->Flink;

    DbgPrint("[*] Scanning active processes for Name: %s...\n", TargetName);

    while (ListEntry != ListHead)
    {
        PEPROCESS TargetProcess = (PEPROCESS)((PUCHAR)ListEntry - EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET);

        PCHAR CurrentName = PsGetProcessImageFileName(TargetProcess);

        if (CurrentName)
        {
            if (strstr(CurrentName, TargetName))
            {
                HANDLE ProcessIdHandle = PsGetProcessId(TargetProcess);
                ULONG CurrentPID = (ULONG)(ULONG_PTR)ProcessIdHandle;

                DbgPrint("[+] Found Target: %s (PID: %d). Enabling Alt Syscalls.\n", CurrentName, CurrentPID);

                EnableAltSyscallOnProcess(TargetProcess);

                PLIST_ENTRY ThreadListHead = (PLIST_ENTRY)((PUCHAR)TargetProcess + EPROCESS_THREAD_LIST_HEAD_OFFSET);
                PLIST_ENTRY ThreadEntry = ThreadListHead->Flink;

                while (ThreadEntry != ThreadListHead)
                {
                    PKTHREAD TargetThread = (PKTHREAD)((PUCHAR)ThreadEntry - KTHREAD_THREAD_LIST_ENTRY_OFFSET);
                    EnableAltSyscallOnThread(TargetThread);
                    ThreadEntry = ThreadEntry->Flink;
                }
            }
        }

        ListEntry = ListEntry->Flink;
    }
}

_KTRAP_FRAME GetCurrentTrapFrame() {
    PKTHREAD Thread = KeGetCurrentThread();
    return *(_KTRAP_FRAME*)((PUCHAR)Thread + KTHREAD_TRAP_FRAME_OFFSET);
}

INT32 AltSyscallHandler(PVOID OriginalFunc, UINT32 Ssn, PVOID ArgStack, PVOID P3Home) {
    UINT64* LocalArgs = (UINT64*)ArgStack;

    if (Ssn == 0x18) {

        UINT64* pBaseAddress = (UINT64*)LocalArgs[1];
        UINT64* pRegionSize = (UINT64*)LocalArgs[3];

        UINT64 RequestedBase = 0;
        UINT64 RequestedSize = 0;
        UINT64 Arg5 = 0;
        UINT64 Arg6 = 0;

        __try {
            if (pBaseAddress) RequestedBase = *pBaseAddress;
            if (pRegionSize)  RequestedSize = *pRegionSize;
        }
        __except (1) {
        }

        UINT64* UserRspPtr = (UINT64*)((UINT64)P3Home + 0x170);
        __try {
            UINT64 UserRsp = *UserRspPtr;
            if (UserRsp) {
                UINT64* StackArgs = (UINT64*)UserRsp;
                Arg5 = StackArgs[5];
                Arg6 = StackArgs[6];
            }
        } __except (1) {}

        DbgPrint("[AltSys] Intercepted! {Ssn 0x18, NtAllocateVirtualMemory} Raw Arguments: Handle=%p, *BaseAddr=%p, *Size=%lld, Type=%llx, Prot=%llx\n",
            (void*)LocalArgs[0],
            (void*)RequestedBase,
            RequestedSize,
            Arg5,
            Arg6
        );

        if (RequestedBase == 0) {
		    NtAllocVirtMemFn originalNtAllocFuntion = (NtAllocVirtMemFn)OriginalFunc;
            
            NTSTATUS status = originalNtAllocFuntion(
                (HANDLE)LocalArgs[0],
                (PVOID*)pBaseAddress,
                0,
                (PSIZE_T)pRegionSize,
                (ULONG)Arg5,
                (ULONG)Arg6
            );
            
            UINT64 AllocatedAddress = 0;
            __try {
                AllocatedAddress = *pBaseAddress;
            }
            __except (1) {}

            DbgPrint("[AltSys] NtAllocateVirtualMemory returned: *BaseAddr=%p (Status: %x)\n",
                (void*)AllocatedAddress,
                status
		    );

            UINT64* pRax = (UINT64*)((UINT64)P3Home + 0x78);
            *pRax = (UINT64)status;
        }
    
        return 0;
    }
    return 1;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (GlobalIsEngineInstalled && GlobalKernelDescriptorTable)
    {
        ULONG_PTR Cr0Old;
        DisableWriteProtection(&Cr0Old);
        {
            GlobalKernelDescriptorTable->rows[ALT_SYSCALL_SLOT_INDEX] = GlobalOriginalRowBackup;
        }
        EnableWriteProtection(Cr0Old);
    }

    LARGE_INTEGER interval;
    interval.QuadPart = -10000 * 50; // 50ms
    KeDelayExecutionThread(KernelMode, FALSE, &interval);

    if (GlobalDispatchTable) {
        ExFreePoolWithTag(GlobalDispatchTable, 'AltS');
    }

    DbgPrint("[*] Driver Unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    if (KD_DEBUGGER_NOT_PRESENT == FALSE) {
        __debugbreak();
    }

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[*] Loading Driver...\n");

    DriverObject->DriverUnload = DriverUnload;

    GlobalDriverBaseAddress = (UINT64)DriverObject->DriverStart;
    DbgPrint("[+] DriverBase: 0x%llX\n", GlobalDriverBaseAddress);

    SIZE_T AllocSize = sizeof(UINT32) + (MAX_SUPPORTED_SSNS * sizeof(UINT32));

    GlobalDispatchTable = (Pssn_dispatch_table)ExAllocatePool2(POOL_FLAG_NON_PAGED, AllocSize, 'AltS');
    if (!GlobalDispatchTable) return STATUS_INSUFFICIENT_RESOURCES;

    GlobalDispatchTable->max_ssn = MAX_SUPPORTED_SSNS;

    UINT64 HandlerAbs = (UINT64)&AltSyscallHandler;
    UINT64 Rva = HandlerAbs - GlobalDriverBaseAddress;

    if (Rva > 0xFFFFFFFF) {
        DbgPrint("[-] Error: Handler RVA too large!\n");
        return STATUS_UNSUCCESSFUL;
    }

    UINT32 EncodedEntry = (UINT32)((Rva << 4) | GENERIC_DISPATCH_FLAG);

    for (UINT32 i = 0; i < MAX_SUPPORTED_SSNS; i++) {
        GlobalDispatchTable->ssn_entry_rva[i] = EncodedEntry;
    }

    PVOID KernelBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!KernelBase) {
        DbgPrint("[-] Failed to find ntoskrnl base.\n");
        return STATUS_NOT_FOUND;
    }

    GlobalKernelDescriptorTable = (PspServiceDescriptorGroupTable*)FindPspServiceDescriptorGroupTable(KernelBase);
    if (!GlobalKernelDescriptorTable) {
        DbgPrint("[-] Failed to find PspServiceDescriptorGroupTable.\n");
        return STATUS_NOT_FOUND;
    }

    PspServiceDescriptorRow NewRow;
    NewRow.DriverBase = (PVOID)GlobalDriverBaseAddress;
    NewRow.AltSyscallDispatchTable = GlobalDispatchTable;
    NewRow.Reserved = NULL;

    GlobalOriginalRowBackup = GlobalKernelDescriptorTable->rows[ALT_SYSCALL_SLOT_INDEX];

    ULONG_PTR Cr0Old;
    DisableWriteProtection(&Cr0Old);
    {
        DbgPrint("[+] Overwriting Kernel Table Slot %d...\n", ALT_SYSCALL_SLOT_INDEX);
        GlobalKernelDescriptorTable->rows[ALT_SYSCALL_SLOT_INDEX] = NewRow;
    }
    EnableWriteProtection(Cr0Old);

    GlobalIsEngineInstalled = TRUE;

    EnableAltSyscallsSystemWide();

    DbgPrint("[+] Driver Loaded Successfully.\n");
    return STATUS_SUCCESS;
}