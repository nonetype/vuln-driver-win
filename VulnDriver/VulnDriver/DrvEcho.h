#pragma once

#define BUFFER_SIZE 256

typedef struct _ECHO_STRUCT {
	CHAR Buffer[BUFFER_SIZE];
	fp Callback;
} ECHO_STRUCT, * PECHO_STRUCT;

NTSTATUS Echo(_In_ PCHAR InBuf, ULONG InBufLen, PCHAR OutBuf, ULONG OutBufLen);