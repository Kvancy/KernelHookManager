//ROHook.h
#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#define kPrint(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, ##__VA_ARGS__)

typedef struct _HOOK_MANAGER {
    char newcode[12];
    char oldcode[12];
    char* target;
} HOOK_MANAGER, * PHOOK_MANAGER;

KIRQL WPOFFx64() {
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    UINT64 cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    __writecr0(cr0);
    _disable();
    return irql;
}

void WPONx64(KIRQL irql) {
    UINT64 cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();
    __writecr0(cr0);
    KeLowerIrql(irql);
}

void InitializeHookManager(PHOOK_MANAGER hookManager, PVOID funcAddress,PVOID hookFunc) {
    hookManager->newcode[0] = 0x48;
    hookManager->newcode[1] = 0xB8;
    memset(hookManager->newcode + 2, 0x00, 8); // mov rax, xxx
    hookManager->newcode[10] = 0xFF;
    hookManager->newcode[11] = 0xE0; // jmp rax
    *(UINT64*)(hookManager->newcode + 2) = (UINT64)hookFunc;
    memset(hookManager->oldcode, 0x00, sizeof(hookManager->oldcode));
    hookManager->target = funcAddress;
    for (int i = 0; i < sizeof(hookManager->oldcode); i++) {
        hookManager->oldcode[i] = hookManager->target[i];
    }
}

NTSTATUS Unhook(PHOOK_MANAGER hookManager) {
    KIRQL irql = WPOFFx64();
    for (int i = 0; i < sizeof(hookManager->newcode); i++) {
        hookManager->target[i] = hookManager->oldcode[i];
    }
    WPONx64(irql);
    return STATUS_SUCCESS;
}

NTSTATUS ApplyHook(PHOOK_MANAGER hookManager) {
    KIRQL irql = WPOFFx64();
    for (int i = 0; i < sizeof(hookManager->newcode); i++) {
        hookManager->target[i] = hookManager->newcode[i];
    }
    WPONx64(irql);
    return STATUS_SUCCESS;
}
