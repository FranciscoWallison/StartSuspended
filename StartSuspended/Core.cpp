#include <Ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdm.h>

#include "Undocumented.h"

// device and IOCTL definitions
#define DEVICE_NAME      L"\\Device\\StartSuspended"
#define SYMLINK_NAME     L"\\??\\StartSuspended"
#define IOCTL_STARTSUSPENDED_RESUME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// global process pointer protected by a fast mutex
static PEPROCESS g_SuspendedProcess = nullptr;
FAST_MUTEX g_ProcessLock;

WCHAR pSzTargetProcess[1024];

VOID cbProcessCreated(PEPROCESS PEProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateNotifyInfo);

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

PCREATE_PROCESS_NOTIFY_ROUTINE_EX pProcessNotifyRoutine = cbProcessCreated;

VOID Unload(PDRIVER_OBJECT DriverObject) {
        UNREFERENCED_PARAMETER(DriverObject);
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Unloading driver\n"));
        PsSetCreateProcessNotifyRoutineEx(pProcessNotifyRoutine, TRUE);

        ExAcquireFastMutex(&g_ProcessLock);
        if (g_SuspendedProcess) {
                PsResumeProcess(g_SuspendedProcess);
                ObDereferenceObject(g_SuspendedProcess);
                g_SuspendedProcess = nullptr;
        }
        ExReleaseFastMutex(&g_ProcessLock);

        UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
        IoDeleteSymbolicLink(&symLink);
        if (DriverObject->DeviceObject)
                IoDeleteDevice(DriverObject->DeviceObject);
}

// Fun��o DriverEntry Corrigida
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;
	HANDLE hKey = NULL;
	PDEVICE_OBJECT deviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
	PKEY_VALUE_PARTIAL_INFORMATION pValuePartialInfo = NULL;

	DriverObject->DriverUnload = Unload;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Initializing kernel driver!\n"));

	ExInitializeFastMutex(&g_ProcessLock);

	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to create device %08X\n", status));
		goto OnError;
	}

	status = IoCreateSymbolicLink(&symLink, &deviceName);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to create symbolic link %08X\n", status));
		goto OnError;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

	OBJECT_ATTRIBUTES objAttrs;
	InitializeObjectAttributes(&objAttrs, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&hKey, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to open registry key\n"));
		goto OnError;
	}

	ULONG uSize = 0;
	UNICODE_STRING szValueName;
	RtlInitUnicodeString(&szValueName, L"Target");
	status = ZwQueryValueKey(hKey, &szValueName, KeyValuePartialInformation, NULL, 0, &uSize);
	if (!uSize || (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to query value information for registry key\n"));
		status = NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
		goto OnError;
	}

	pValuePartialInfo = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, uSize, 'kvpi'));
	if (pValuePartialInfo == NULL) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to allocate memory for partial information\n"));
		status = STATUS_NO_MEMORY;
		goto OnError;
	}

	ULONG uLenValue;
	status = ZwQueryValueKey(hKey, &szValueName, KeyValuePartialInformation, pValuePartialInfo, uSize, &uLenValue);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to query value for registry key\n"));
		goto OnError;
	}

	if (pValuePartialInfo->Type != REG_SZ) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Target has wrong value type\n"));
		status = STATUS_INVALID_PARAMETER;
		goto OnError;
	}

	RtlStringCchCopyNW(pSzTargetProcess, pValuePartialInfo->DataLength / sizeof(WCHAR), reinterpret_cast<PWSTR>(pValuePartialInfo->Data), 1024);
	if (!wcslen(pSzTargetProcess)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Target is invalid\n"));
		status = STATUS_INVALID_PARAMETER;
		goto OnError;
	}

	// Libera a mem�ria e fecha a chave do registro aqui, pois n�o s�o mais necess�rias
	ExFreePoolWithTag(pValuePartialInfo, 'kvpi');
	pValuePartialInfo = NULL; // Evita dupla libera��o no OnError
	ZwClose(hKey);
	hKey = NULL; // Evita duplo fechamento no OnError

	status = PsSetCreateProcessNotifyRoutineEx(pProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StartSuspended] Failed to register process notify routine: %08X\n", status));
		goto OnError;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Successfully registered process notify routine\n"));
	return STATUS_SUCCESS;

OnError:
	// Ponto de limpeza centralizado
	if (hKey) {
		ZwClose(hKey);
	}
	if (pValuePartialInfo) {
		ExFreePoolWithTag(pValuePartialInfo, 'kvpi');
	}
	// Desfaz a cria��o do link simb�lico se ele foi criado
	if (deviceObject) {
		UNICODE_STRING symLinkOnError = RTL_CONSTANT_STRING(SYMLINK_NAME);
		IoDeleteSymbolicLink(&symLinkOnError);
		IoDeleteDevice(deviceObject);
	}

	return status;
}
// Fun��o cbProcessCreated Modificada (Suspende todas as inst�ncias)
VOID cbProcessCreated(PEPROCESS PEProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateNotifyInfo) {
	UNREFERENCED_PARAMETER(ProcessId);
	if (CreateNotifyInfo != NULL && wcsstr(CreateNotifyInfo->CommandLine->Buffer, pSzTargetProcess) != NULL) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[StartSuspended] Suspending %S\n", pSzTargetProcess));
		PsSuspendProcess(PEProcess);

		ExAcquireFastMutex(&g_ProcessLock);

		// Se j� havia um processo suspenso, libera a refer�ncia antiga antes de armazenar a nova.
		if (g_SuspendedProcess) {
			ObDereferenceObject(g_SuspendedProcess);
		}

		ObReferenceObject(PEProcess);
		g_SuspendedProcess = PEProcess; // Armazena o processo mais recente que foi suspenso.

		ExReleaseFastMutex(&g_ProcessLock);
	}
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
        UNREFERENCED_PARAMETER(DeviceObject);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
        UNREFERENCED_PARAMETER(DeviceObject);
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

        if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_STARTSUSPENDED_RESUME) {
                ExAcquireFastMutex(&g_ProcessLock);
                if (g_SuspendedProcess) {
                        PsResumeProcess(g_SuspendedProcess);
                        ObDereferenceObject(g_SuspendedProcess);
                        g_SuspendedProcess = nullptr;
                        status = STATUS_SUCCESS;
                } else {
                        status = STATUS_NOT_FOUND;
                }
                ExReleaseFastMutex(&g_ProcessLock);
        }

        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
}
