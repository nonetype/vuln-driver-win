#include <Ntifs.h>
#include <ntddk.h>
#include <string.h>
#include "DrvHdr.h"
#include "DrvNote.h"

#define ARRAY_LEN 256

PCHAR PoolArray[ARRAY_LEN] = {0,};

NTSTATUS AllocateHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PWRITE_STRUCT pPageWriteRequest = (PWRITE_STRUCT)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	IDX_STRUCT RequestedIndex = { 0, };
	PCHAR pKernelBuf = NULL;
	PCHAR pToWrite = NULL;
	ULONG ToWriteLen = 0;

	PAGED_CODE();
	UNREFERENCED_PARAMETER(Irp);

	__try {
		KDPRINT(("DrvAllocFree:AllocateHandler\n"));
		ProbeForRead(pPageWriteRequest, sizeof(PWRITE_STRUCT), (ULONG)__alignof(UCHAR));

		RequestedIndex = pPageWriteRequest->NoteIndex;
		pToWrite = pPageWriteRequest->UserBuffer;
		ToWriteLen = pPageWriteRequest->UserBufferLength;

		ProbeForRead(pToWrite, ToWriteLen, (ULONG)__alignof(UCHAR));

		pKernelBuf = (PCHAR)ExAllocatePoolWithTag(PagedPool, ToWriteLen, (ULONG)ALLOC_TAG);

		if (!pKernelBuf) {
			KDPRINT(("Cannot allocate memory\n"));
			return STATUS_NO_MEMORY;
		}

		RtlCopyMemory(pKernelBuf, pToWrite, ToWriteLen);
		// KernelNote->Callback = (fp)&PrintNoteCallback;

		PoolArray[RequestedIndex.idx] = pKernelBuf;

		KDPRINT(("Allocate(arbitrary) done.\n"));
		DbgPrint("[DbgInfo]-----------------------\n");
		DbgPrint("note Index  : %lld\n", RequestedIndex.idx);
		DbgPrint("note Address: %p\n", pKernelBuf);
		DbgPrint("note Size   : 0x%llx\n", sizeof(NOTE_STRUCT));
		DbgPrint("[DbgInfo]-----------------------\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		if (pKernelBuf != NULL) {
			ExFreePoolWithTag(pKernelBuf, (ULONG)ALLOC_TAG);
		}
		ntStatus = GetExceptionCode();
		DbgPrint("Error while handling ioctl: 0x%x\n", ntStatus);
		return ntStatus;
	}

	return ntStatus;
}

NTSTATUS FreeHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIDX_STRUCT RequestedIndex = (PIDX_STRUCT)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	PCHAR toFreePool = NULL;

	PAGED_CODE();
	UNREFERENCED_PARAMETER(Irp);

	__try {
		KDPRINT(("DrvAllocFree:FreeHandler\n"));
		ProbeForRead(RequestedIndex, sizeof(PIDX_STRUCT), (ULONG)__alignof(UCHAR));

		DbgPrint("Freeing index %lld\n", RequestedIndex->idx);
		if (ARRAY_LEN <= RequestedIndex->idx) {
			KDPRINT(("Out-of-bound request\n"));
			return STATUS_FWP_OUT_OF_BOUNDS;
		}

		toFreePool = PoolArray[RequestedIndex->idx];
		if (toFreePool == NULL) {
			KDPRINT(("Requested index Pool is NULL.\n"));
			return STATUS_FWP_NULL_POINTER;
		}

		ExFreePoolWithTag(toFreePool, (ULONG)ALLOC_TAG);
		PoolArray[RequestedIndex->idx] = NULL;

		KDPRINT(("Free(arbitrary) done.\n"));
		DbgPrint("[DbgInfo]-----------------------\n");
		DbgPrint("Pool Index  : %lld\n", RequestedIndex->idx);
		DbgPrint("Pool Address: %p\n", toFreePool);
		DbgPrint("[DbgInfo]-----------------------\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ntStatus = GetExceptionCode();
		
		DbgPrint("Error while handling ioctl: 0x%x\n", ntStatus);
		return ntStatus;
	}

	return ntStatus;
}