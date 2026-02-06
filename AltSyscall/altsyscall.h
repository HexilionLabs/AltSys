#pragma once
#include <ntddk.h>
#include <intrin.h>
#include <aux_klib.h>
#include <ntimage.h>

#define MAX_SUPPORTED_SSNS 0x1000
#define ALT_SYSCALL_SLOT_INDEX 0
#define GENERIC_DISPATCH_FLAG 0x10
#define KTHREAD_DEBUG_ACTIVE_OFFSET 0x03
#define DEBUGACTIVE_INSTRUMENTED_FLAGS 0x24

#define EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET 0x1d8
#define EPROCESS_THREAD_LIST_HEAD_OFFSET 0x30
#define EPROCESS_DISPATCH_CONTEXT_OFFSET 0x7D0
#define EPROCESS_UNIQUE_ID_OFFSET 0x1d0
#define KTHREAD_THREAD_LIST_ENTRY_OFFSET 0x2F8
#define KTHREAD_TRAP_FRAME_OFFSET 0x90

extern "C" {
    NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
    NTSYSAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
}

typedef NTSTATUS(*NtAllocVirtMemFn)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef struct {
    UINT32 Level;
    UINT32 Slot;
} PspSyscallProviderDispatchContext, * PPspSyscallProviderDispatchContext;

typedef struct {
    UINT32 max_ssn;
    UINT32 ssn_entry_rva[1];
} ssn_dispatch_table, * Pssn_dispatch_table;

typedef struct {
    PVOID DriverBase;
    Pssn_dispatch_table AltSyscallDispatchTable;
    PVOID Reserved;
} PspServiceDescriptorRow, * PPspServiceDescriptorRow;

typedef struct {
    PspServiceDescriptorRow rows[32];
} PspServiceDescriptorGroupTable, * PPspServiceDescriptorGroupTable;

INT32 AltSyscallHandler(PVOID Wrapper1, UINT32 Ssn, PVOID ArgStack, PVOID P3Home);