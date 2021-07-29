#pragma once
#define IOCTL_TYPE 0x9000

#define IOCTL_ALLOC CTL_CODE(IOCTL_TYPE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_FREE  CTL_CODE(IOCTL_TYPE, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_MAKE_NOTE   CTL_CODE(IOCTL_TYPE, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_READ_NOTE   CTL_CODE(IOCTL_TYPE, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_WRITE_NOTE  CTL_CODE(IOCTL_TYPE, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DELETE_NOTE CTL_CODE(IOCTL_TYPE, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_ECHO CTL_CODE(IOCTL_TYPE, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)