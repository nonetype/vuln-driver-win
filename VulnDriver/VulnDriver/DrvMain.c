#include <ntddk.h>
#include <string.h>
#include "DrvIoctl.h"
#include "DrvHdr.h"

#define NT_DEVICE_NAME L"\\Device\\VulnDriver"
#define DOS_DEVICE_NAME L"\\DosDevices\\VulnDriver"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DriverIoctlCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DriverDeviceControl;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    NTSTATUS ntStatus = STATUS_SUCCESS;
    UNICODE_STRING ntUnicodeString;
    UNICODE_STRING ntWin32NameString;
    PDEVICE_OBJECT deviceObject = NULL;

    UNREFERENCED_PARAMETER(pRegistryPath);

    RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);
    ntStatus = IoCreateDevice(   // IoCreateDevice -> Create device object
        pDriverObject,           // PDRIVER_OBJECT  DriverObject
        0,                       // ULONG           DeviceExtensionSize
        &ntUnicodeString,        // PUNICODE_STRING DeviceName
        FILE_DEVICE_UNKNOWN,     // DEVICE_TYPE     DeviceType
        FILE_DEVICE_SECURE_OPEN, // ULONG           DeviceCharacteristics
        FALSE,                   // BOOLEAN         Exclusive
        &deviceObject            // PDEVICE_OBJECT  DeviceObject (save device object here)
    );
    if (!NT_SUCCESS(ntStatus)) {
        KDPRINT(("Error while IoCreateDevice\n"));
        return ntStatus;
    }


    pDriverObject->DriverUnload = DriverUnload;
    // Set driver dispatch routine
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = DriverIoctlCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverIoctlCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

    // Create dos device symlink for user-mode access
    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
    ntStatus = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
    if (!NT_SUCCESS(ntStatus)) {
        KDPRINT(("Error while IoCreateSymbolicLink\n"));
        IoDeleteDevice(deviceObject);
        return ntStatus;
    }

    KDPRINT(("Driver loaded\n"));
    return ntStatus;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING ntWin32NameString;

    UNREFERENCED_PARAMETER(pDriverObject);

    // Remove dos device symlink
    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&ntWin32NameString);

    // Remove device object
    deviceObject = pDriverObject->DeviceObject;
    if (deviceObject != NULL) {
        IoDeleteDevice(deviceObject);
    }

    KDPRINT(("Driver unloaded\n"));
}

NTSTATUS DriverIoctlCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    UNREFERENCED_PARAMETER(pDeviceObject);

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(pIrp);
    UNREFERENCED_PARAMETER(pDeviceObject);

    // PAGED_CODE();
    KDPRINT(("processing IOCTL...\n"));

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_ALLOC:
            AllocateHandler(pIrp, irpSp);
            break;

        case IOCTL_FREE:
            FreeHandler(pIrp, irpSp);
            break;

        case IOCTL_MAKE_NOTE:
            MakeNote(pIrp, irpSp);
            break;

        case IOCTL_READ_NOTE:
            ReadNote(pIrp, irpSp);
            break;

        case IOCTL_WRITE_NOTE:
            WriteNote(pIrp, irpSp);
            break;

        case IOCTL_DELETE_NOTE:
            DeleteNote(pIrp, irpSp);
            break;

        case IOCTL_ECHO:
            EchoHandler(pIrp, irpSp);
            break;

        default:
            KDPRINT(("Cannot handle IOCTL\n"));
            break;
    }

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}