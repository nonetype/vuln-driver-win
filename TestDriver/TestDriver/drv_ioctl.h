#define IOCTL_TYPE 0x8800

#define IOCTL_SUM \
	CTL_CODE(IOCTL_TYPE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _CALC_STRUCT {
	ULONG64 a;
	ULONG64 b;
} CALC_STRUCT, *PCALC_STRUCT;