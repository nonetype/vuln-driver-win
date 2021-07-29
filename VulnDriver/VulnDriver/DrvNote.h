#pragma once
#pragma pack(push, 1)

#define MAX_NOTE 8
#define NOTE_NAME_LEN 32
#define NOTE_PAGE_LEN 512

typedef struct _IDX_STRUCT {
	ULONG64 idx;
} IDX_STRUCT, * PIDX_STRUCT;

typedef struct _WRITE_STRUCT {
	IDX_STRUCT NoteIndex;

	ULONG UserBufferLength;
	PCHAR UserBuffer;
} WRITE_STRUCT, * PWRITE_STRUCT;

typedef struct _PAGE_STRUCT {
	ULONG PageBufferLength;
	CHAR PageBuffer[NOTE_PAGE_LEN];
} PAGE_STRUCT, * PPAGE_STRUCT;

typedef struct _NOTE_STRUCT {
	CHAR NoteName[NOTE_NAME_LEN];
	PPAGE_STRUCT pNotePage;
} NOTE_STRUCT, * PNOTE_STRUCT;

#pragma pack(pop)