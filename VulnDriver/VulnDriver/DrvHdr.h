#pragma once

#if DBG
#define KDPRINT(_x_) \
    DbgPrint("VulnDriver.sys: %s", _x_);
#else
#define KDPRINT(_x_)
#endif

#define ALLOC_TAG 'ffiD'

typedef void (*fp)(void);

NTSTATUS AllocateHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp);
NTSTATUS FreeHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp);

NTSTATUS MakeNote(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp);
NTSTATUS ReadNote(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp);
NTSTATUS WriteNote(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp);
NTSTATUS DeleteNote(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp);

NTSTATUS EchoHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp);