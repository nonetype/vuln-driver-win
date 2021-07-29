#include <ntddk.h>
#include <string.h>
#include "DrvHdr.h"
#include "DrvNote.h"

PNOTE_STRUCT Bookshelf[MAX_NOTE] = { 0, };

NTSTATUS MakeNote(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PWRITE_STRUCT pPageWriteRequest = (PWRITE_STRUCT)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	IDX_STRUCT RequestedIndex = {0,};
	PNOTE_STRUCT pNote = NULL;
	PCHAR pToWrite = NULL;
	ULONG ToWriteLen = 0;

	PAGED_CODE();
	UNREFERENCED_PARAMETER(Irp);

	__try {
		ProbeForRead(pPageWriteRequest, sizeof(PWRITE_STRUCT), (ULONG)__alignof(UCHAR));

		RequestedIndex = pPageWriteRequest->NoteIndex;
		pToWrite = pPageWriteRequest->UserBuffer;
		ToWriteLen = pPageWriteRequest->UserBufferLength;

		DbgPrint("Making index %lld\n", RequestedIndex.idx);

		if (NOTE_PAGE_LEN <= ToWriteLen) {
			KDPRINT(("Invalid length\n"));
			return STATUS_BUFFER_OVERFLOW;
		}

		if (MAX_NOTE <= RequestedIndex.idx) {
			KDPRINT(("It's Out-Of-Bound request!\n"));
			return STATUS_FWP_OUT_OF_BOUNDS;
		}

		pNote = Bookshelf[RequestedIndex.idx];
		if (pNote != NULL) {
			KDPRINT(("Cannot place note there\n"));
			return STATUS_DATA_OVERRUN;
		}

		ProbeForRead(pToWrite, ToWriteLen, (ULONG)__alignof(UCHAR));

		pNote = (PNOTE_STRUCT)ExAllocatePoolWithTag(PagedPool, sizeof(NOTE_STRUCT), (ULONG)ALLOC_TAG);

		if (!pNote) {
			KDPRINT(("Cannot allocate note\n"));
			return STATUS_NO_MEMORY;
		}

		RtlCopyMemory(pNote->NoteName, pToWrite, ToWriteLen);
		// KernelNote->Callback = (fp)&PrintNoteCallback;

		Bookshelf[RequestedIndex.idx] = pNote;

		KDPRINT(("Allocate done.\n"));
		DbgPrint("[DbgInfo]-----------------------\n");
		DbgPrint("note Index  : %lld\n", RequestedIndex.idx);
		DbgPrint("note Address: %p\n", pNote);
		DbgPrint("note Size   : 0x%llx\n", sizeof(NOTE_STRUCT));
		DbgPrint("[DbgInfo]-----------------------\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		if (pNote != NULL) {
			ExFreePoolWithTag(pNote, (ULONG)ALLOC_TAG);
		}
		ntStatus = GetExceptionCode();
		DbgPrint("Error while handling ioctl: 0x%x\n", ntStatus);
		return ntStatus;
	}

	return ntStatus;
}

NTSTATUS ReadNote(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIDX_STRUCT RequestedIndex = (PIDX_STRUCT)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	ULONG RequestedLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID UserBuffer = Irp->UserBuffer;
	PNOTE_STRUCT pNote = NULL;
	PPAGE_STRUCT pPage = NULL;

	PAGED_CODE();

	__try {
		ProbeForRead(RequestedIndex, sizeof(PIDX_STRUCT), (ULONG)__alignof(UCHAR));

		DbgPrint("Reading note index %lld\n", RequestedIndex->idx);
		if (MAX_NOTE <= RequestedIndex->idx) {
			KDPRINT(("It's Out-Of-Bound request!\n"));
			return STATUS_FWP_OUT_OF_BOUNDS;
		}

		pNote = Bookshelf[RequestedIndex->idx];
		if (pNote == NULL) {
			KDPRINT(("No note here\n"));
			return STATUS_FWP_NULL_POINTER;
		}
		
		pPage = pNote->pNotePage;
		if (!MmIsAddressValid(pPage)) {
			DbgPrint("No page here: %p\n", pPage);
			return STATUS_FWP_NULL_POINTER;
		}

		if (NOTE_PAGE_LEN <= RequestedLength) {
			KDPRINT(("Invalid buffer length\n"));
			return STATUS_FWP_OUT_OF_BOUNDS;
		}
		
		ProbeForWrite(UserBuffer, RequestedLength, (ULONG)__alignof(UCHAR));
		RtlCopyMemory(UserBuffer, pPage->PageBuffer, RequestedLength);

		KDPRINT(("Read done.\n"));
		DbgPrint("[DbgInfo]-----------------------\n");
		DbgPrint("note Index   : %lld\n", RequestedIndex->idx);
		DbgPrint("note Address : %p\n", pNote);
		DbgPrint("page Address : %p\n", pPage);
		DbgPrint("output buffer: %p\n", UserBuffer);
		DbgPrint("[DbgInfo]-----------------------\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ntStatus = GetExceptionCode();
		DbgPrint("Error while handling ioctl: 0x%x", ntStatus);
		return ntStatus;
	}

	return ntStatus;
}

NTSTATUS WriteNote(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PWRITE_STRUCT pPageWriteRequest = (PWRITE_STRUCT)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	IDX_STRUCT RequestedIndex;
	PNOTE_STRUCT pNote = NULL;
	PPAGE_STRUCT pPage = NULL;
	PCHAR pToWrite = NULL;
	ULONG ToWriteLen = 0;

	PAGED_CODE();
	UNREFERENCED_PARAMETER(Irp);

	__try {
		ProbeForRead(pPageWriteRequest, sizeof(PWRITE_STRUCT), (ULONG)__alignof(UCHAR));

		RequestedIndex = pPageWriteRequest->NoteIndex;
		pToWrite = pPageWriteRequest->UserBuffer;
		ToWriteLen = pPageWriteRequest->UserBufferLength;

		DbgPrint("Writing index %lld\n", RequestedIndex.idx);

		if (NOTE_PAGE_LEN <= ToWriteLen) {
			KDPRINT(("Invalid length\n"));
			return STATUS_BUFFER_OVERFLOW;
		}

		if (MAX_NOTE <= RequestedIndex.idx) {
			KDPRINT(("It's Out-Of-Bound request!\n"));
			return STATUS_FWP_OUT_OF_BOUNDS;
		}

		pNote = Bookshelf[RequestedIndex.idx];
		if (pNote == NULL) {
			KDPRINT(("No note here\n"));
			return STATUS_FWP_NULL_POINTER;
		}

		pPage = pNote->pNotePage;
		DbgBreakPoint();
		if (!MmIsAddressValid(pPage)) {
			DbgPrint("No page here: %p\n", pPage);
			pPage = (PPAGE_STRUCT)ExAllocatePoolWithTag(PagedPool, sizeof(PAGE_STRUCT), (ULONG)ALLOC_TAG);

			if (!pPage) {
				KDPRINT(("Cannot allocate page\n"));
				return STATUS_NO_MEMORY;
			}

			pNote->pNotePage = pPage;
		} else {
			DbgPrint("page found: %p\n", pPage);
		}

		ProbeForRead(pToWrite, ToWriteLen, (ULONG)__alignof(UCHAR));

		RtlCopyMemory(pPage->PageBuffer, pToWrite, ToWriteLen);
		pPage->PageBufferLength = ToWriteLen;

		KDPRINT(("Write done.\n"));
		DbgPrint("[DbgInfo]-----------------------\n");
		DbgPrint("note Index  : %lld\n", RequestedIndex.idx);
		DbgPrint("note Address: %p\n", pNote);
		DbgPrint("page Address: %p\n", pPage);
		DbgPrint("page Buffer : %p\n", pPage->PageBuffer);
		DbgPrint("page Length : 0x%lx\n", ToWriteLen);
		DbgPrint("[DbgInfo]-----------------------\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ntStatus = GetExceptionCode();
		DbgPrint("Error while handling ioctl: 0x%x", ntStatus);
		return ntStatus;
	}

	return ntStatus;
}

NTSTATUS DeleteNote(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIDX_STRUCT RequestedIndex = (PIDX_STRUCT)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	PNOTE_STRUCT pNote = NULL;

	PAGED_CODE();
	UNREFERENCED_PARAMETER(Irp);

	__try {
		ProbeForRead(RequestedIndex, sizeof(PIDX_STRUCT), (ULONG)__alignof(UCHAR));

		DbgPrint("Freeing index %lld\n", RequestedIndex->idx);
		if (MAX_NOTE <= RequestedIndex->idx) {
			KDPRINT(("Out-of-bound request"));
			return STATUS_FWP_OUT_OF_BOUNDS;
		}

		pNote = Bookshelf[RequestedIndex->idx];
		if (pNote == NULL) {
			KDPRINT(("Requested index Pool is NULL.\n"));
			return STATUS_FWP_NULL_POINTER;
		}

		if (MmIsAddressValid(pNote->pNotePage)) {
			// ExFreePoolWithTag(pNote->pNotePage, (ULONG)ALLOC_TAG);
		}

		ExFreePoolWithTag(pNote, (ULONG)ALLOC_TAG);
		Bookshelf[RequestedIndex->idx] = NULL;

		KDPRINT(("Free done.\n"));
		DbgPrint("[DbgInfo]-----------------------\n");
		DbgPrint("note Index  : %lld\n", RequestedIndex->idx);
		DbgPrint("note Address: %p\n", pNote);
		DbgPrint("[DbgInfo]-----------------------\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ntStatus = GetExceptionCode();

		DbgPrint("Error while handling ioctl: 0x%x\n", ntStatus);
		return ntStatus;
	}

	return ntStatus;
}