#include <ntddk.h>
#include <string.h>
#include "drv_ioctl.h"

#define NT_DEVICE_NAME L"\\Device\\TestDriver"
#define DOS_DEVICE_NAME L"\\DosDevices\\TestDriver"

#if DBG
#define KDPRINT(_x_) \
    DbgPrint("TestDriver.sys: %s", _x_);
#else
#define KDPRINT(_x_)
#endif

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
    DbgPrint("IOCTL: %lx\n", IOCTL_COMMUNICATE);
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
    PCHAR              inBuf, outBuf = NULL;
    ULONG              inBufLen, outBufLen = 0;
    PCHAR              data = "Hello from kernel driver!";
    size_t             dataLen = strlen(data) + 1;
    UNREFERENCED_PARAMETER(pDeviceObject);
    UNREFERENCED_PARAMETER(inBufLen);

    KDPRINT(("IOCTL called!\n"));

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_COMMUNICATE:

        inBuf = outBuf = pIrp->AssociatedIrp.SystemBuffer;
        outBufLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

        KDPRINT(("user called IOCTL with: "));
        KDPRINT((inBuf));

        RtlCopyBytes(outBuf, data, outBufLen);
        pIrp->IoStatus.Information = ((outBufLen < dataLen) ? outBufLen : dataLen);

        KDPRINT(("outBuf now contains: "));
        KDPRINT((outBuf));

        break;
    }

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}