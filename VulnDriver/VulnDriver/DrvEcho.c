#include <ntddk.h>
#include <string.h>
#include "DrvHdr.h"
#include "DrvEcho.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Echo)
#pragma alloc_text(PAGE, EchoHandler)
#endif

VOID DisableMits() {
	ULONG64 cr4 = __readcr4();
	cr4 &= ~(1ULL << 20ULL);
	cr4 &= ~(1ULL << 21ULL);
	__writecr4(cr4);
}

VOID EnableMits() {
	ULONG64 cr4 = __readcr4();
	cr4 |= ~(1ULL << 20ULL);
	cr4 |= ~(1ULL << 21ULL);
	__writecr4(cr4);
}

VOID EchoCr4() {
	ULONG64 cr4 = __readcr4();
	DbgPrint("My cr4 register is now: %llx\n", cr4);
}

VOID Callback() {
	KDPRINT(("Callback!\n"));
}

__declspec(safebuffers)
NTSTATUS Echo(_In_ PCHAR InBuf, ULONG InBufLen, PCHAR OutBuf, ULONG OutBufLen) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	CHAR KernelBuffer[BUFFER_SIZE] = { 0, };

	// PAGED_CODE();

	__try {
		// [Read]----------
		ProbeForRead(InBuf, InBufLen, (ULONG)__alignof(UCHAR));
		RtlCopyMemory(KernelBuffer, InBuf, InBufLen);
		DbgPrint("Driver input: %s\n", KernelBuffer);

		// [Write]----------
		ProbeForWrite(OutBuf, OutBufLen, (ULONG)__alignof(UCHAR));
		RtlCopyMemory(OutBuf, KernelBuffer, OutBufLen);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ntStatus = GetExceptionCode();
		DbgPrint("Error while handling ioctl: 0x%x", ntStatus);

		return ntStatus;
	}

	DbgBreakPoint();

	return ntStatus;
}

NTSTATUS EchoHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp) {
	// [Init variables]----------
	NTSTATUS ntStatus = STATUS_SUCCESS;

	PCHAR inBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	ULONG inBufferLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	PCHAR outBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	ULONG outBufferLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

	// PAGED_CODE();

	ntStatus = Echo(inBuffer, inBufferLen, outBuffer, outBufferLen);

	return ntStatus;
}