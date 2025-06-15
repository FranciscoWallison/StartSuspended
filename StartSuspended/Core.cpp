#include <Ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdm.h>

#include "Undocumented.h"
#include "Shared.h" 

// --- Estruturas e Globais ---

typedef struct _SUSPENDED_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    PEPROCESS Process;
    HANDLE ProcessId;
} SUSPENDED_PROCESS_ENTRY, * PSUSPENDED_PROCESS_ENTRY;

#define DEVICE_NAME       L"\\Device\\StartSuspended"
#define SYMLINK_NAME      L"\\??\\StartSuspended"

LIST_ENTRY g_SuspendedProcessListHead;
FAST_MUTEX g_ListLock;
WCHAR pSzTargetProcess[1024];

// --- Protótipos de Funções ---

VOID cbProcessCreated(PEPROCESS PEProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateNotifyInfo);
VOID Unload(PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
PCREATE_PROCESS_NOTIFY_ROUTINE_EX pProcessNotifyRoutine = cbProcessCreated;

// --- Implementação do Driver ---

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    HANDLE hKey = NULL;
    PDEVICE_OBJECT deviceObject = nullptr;
    PKEY_VALUE_PARTIAL_INFORMATION pValuePartialInfo = NULL;

    // Initialize symLink here, so it's always valid even if an error occurs before its explicit use.
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);

    DriverObject->DriverUnload = Unload;
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Initializing driver!\n"));

    InitializeListHead(&g_SuspendedProcessListHead);
    ExInitializeFastMutex(&g_ListLock);

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to create device: %08X\n", status));
        goto OnError;
    }

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to create symbolic link: %08X\n", status));
        goto OnError;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    OBJECT_ATTRIBUTES objAttrs;
    InitializeObjectAttributes(&objAttrs, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&hKey, KEY_READ, &objAttrs);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to open registry key: %08X\n", status));
        goto OnError;
    }

    ULONG uSize = 0;
    UNICODE_STRING szValueName;
    RtlInitUnicodeString(&szValueName, L"Target");
    status = ZwQueryValueKey(hKey, &szValueName, KeyValuePartialInformation, NULL, 0, &uSize);
    if (!uSize || (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)) {
        status = NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
        goto OnError;
    }

    pValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, uSize, 'kvpi');
    if (pValuePartialInfo == NULL) {
        status = STATUS_NO_MEMORY;
        goto OnError;
    }

    ULONG uLenValue;
    status = ZwQueryValueKey(hKey, &szValueName, KeyValuePartialInformation, pValuePartialInfo, uSize, &uLenValue);
    if (!NT_SUCCESS(status)) { goto OnError; }
    if (pValuePartialInfo->Type != REG_SZ) { status = STATUS_INVALID_PARAMETER; goto OnError; }

    RtlStringCchCopyNW(pSzTargetProcess, pValuePartialInfo->DataLength / sizeof(WCHAR), (PWSTR)pValuePartialInfo->Data, 1024);
    if (!wcslen(pSzTargetProcess)) { status = STATUS_INVALID_PARAMETER; goto OnError; }

    ExFreePoolWithTag(pValuePartialInfo, 'kvpi');
    pValuePartialInfo = NULL;
    ZwClose(hKey);
    hKey = NULL;

    status = PsSetCreateProcessNotifyRoutineEx(pProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to register process notify routine: %08X\n", status));
        goto OnError;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Driver loaded successfully.\n"));
    return STATUS_SUCCESS;

OnError:
    if (hKey) { ZwClose(hKey); }
    if (pValuePartialInfo) { ExFreePoolWithTag(pValuePartialInfo, 'kvpi'); }
    if (deviceObject) {
        // symLink is now guaranteed to be initialized here.
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(deviceObject);
    }
    return status;
}

VOID Unload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Unloading driver.\n"));
    PsSetCreateProcessNotifyRoutineEx(pProcessNotifyRoutine, TRUE);

    ExAcquireFastMutex(&g_ListLock);
    while (!IsListEmpty(&g_SuspendedProcessListHead)) {
        PLIST_ENTRY pEntry = RemoveHeadList(&g_SuspendedProcessListHead);
        PSUSPENDED_PROCESS_ENTRY pSuspendedProcess = CONTAINING_RECORD(pEntry, SUSPENDED_PROCESS_ENTRY, ListEntry);

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Resuming PID %u on unload.\n", HandleToUlong(pSuspendedProcess->ProcessId)));
        PsResumeProcess(pSuspendedProcess->Process);
        ObDereferenceObject(pSuspendedProcess->Process);
        ExFreePool(pSuspendedProcess);
    }
    ExReleaseFastMutex(&g_ListLock);

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);
}

VOID cbProcessCreated(PEPROCESS PEProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateNotifyInfo) {
    if (CreateNotifyInfo != NULL && wcsstr(CreateNotifyInfo->CommandLine->Buffer, pSzTargetProcess) != NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Suspending PID: %u, Name: %S\n", HandleToUlong(ProcessId), pSzTargetProcess));
        PsSuspendProcess(PEProcess);

        PSUSPENDED_PROCESS_ENTRY pNewEntry = (PSUSPENDED_PROCESS_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(SUSPENDED_PROCESS_ENTRY), 'spe');
        if (pNewEntry) {
            ObReferenceObject(PEProcess);
            pNewEntry->Process = PEProcess;
            pNewEntry->ProcessId = ProcessId;

            ExAcquireFastMutex(&g_ListLock);
            InsertTailList(&g_SuspendedProcessListHead, &pNewEntry->ListEntry);
            ExReleaseFastMutex(&g_ListLock);
        }
    }
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_STARTSUSPENDED_RESUME_BY_PID: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG pidToResume = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        BOOLEAN found = FALSE;

        ExAcquireFastMutex(&g_ListLock);
        PLIST_ENTRY current = g_SuspendedProcessListHead.Flink;
        while (current != &g_SuspendedProcessListHead) {
            PSUSPENDED_PROCESS_ENTRY pEntry = CONTAINING_RECORD(current, SUSPENDED_PROCESS_ENTRY, ListEntry);
            PLIST_ENTRY next = current->Flink;
            if (HandleToUlong(pEntry->ProcessId) == pidToResume) {
                PsResumeProcess(pEntry->Process);
                ObDereferenceObject(pEntry->Process);
                RemoveEntryList(&pEntry->ListEntry);
                ExFreePool(pEntry);
                found = TRUE;
                break;
            }
            current = next;
        }
        ExReleaseFastMutex(&g_ListLock);

        if (!found) status = STATUS_NOT_FOUND;
        break;
    }

    case IOCTL_STARTSUSPENDED_RESUME_ALL: {
        ExAcquireFastMutex(&g_ListLock);
        while (!IsListEmpty(&g_SuspendedProcessListHead)) {
            PLIST_ENTRY pEntry = RemoveHeadList(&g_SuspendedProcessListHead);
            PSUSPENDED_PROCESS_ENTRY pSuspendedProcess = CONTAINING_RECORD(pEntry, SUSPENDED_PROCESS_ENTRY, ListEntry);
            PsResumeProcess(pSuspendedProcess->Process);
            ObDereferenceObject(pSuspendedProcess->Process);
            ExFreePool(pSuspendedProcess);
        }
        ExReleaseFastMutex(&g_ListLock);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}