#include <ntifs.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <ntddk.h>
#include <stdarg.h>
#include "R0Hook.h"
#define dbgFilter "Kvancy:"
typedef ULONG(*FuncPtr) (ULONG ComponentId, ULONG Level, PCSTR Format, ...);
HOOK_MANAGER hookManager;
ULONG myDbgPrintEx(ULONG ComponentId, ULONG Level, PCSTR Format, ...) {
    Unhook(&hookManager);
    FuncPtr func = (FuncPtr)hookManager.target;
    kPrint("%s DbgPrintEx ComponentId:%lu,Level:%lu\n",dbgFilter, ComponentId, Level);
    va_list args;
    va_start(args, Format);
    NTSTATUS s = func(ComponentId, Level, Format, args);
    va_end(args);
    ApplyHook(&hookManager);
    return s;
}

void DriverUnload(PDRIVER_OBJECT pDriver) {
    kPrint("%s DriverUnload\n", dbgFilter);
    Unhook(&hookManager);
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath
) {
    DriverObject->DriverUnload = DriverUnload;
    PVOID dbgPrintEx = DbgPrintEx;
    InitializeHookManager(&hookManager, dbgPrintEx, myDbgPrintEx);
    ApplyHook(&hookManager);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s DriverEntry\n",dbgFilter);
    return STATUS_SUCCESS;
}
