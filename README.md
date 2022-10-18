# getmodulebase
get kernel module base without PsSetLoadImageNotifyRoutine, saving function in this readme for later


NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(IN PEPROCESS Process);

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(IN PEPROCESS Process);

VOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
{
    ASSERT(pProcess != NULL);
    if (pProcess == NULL)
        return NULL;

    // Protect from UserMode AV
    __try
    {
        LARGE_INTEGER time = { 0 };
        time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

        // Wow64 process
        if (isWow64)
        {
            PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
            if (pPeb32 == NULL)
            {
                DebugMessage("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
                return NULL;
            }

            // Wait for loader a bit
            for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
            {
                DebugMessage("BlackBone: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
                KeDelayExecutionThread(KernelMode, TRUE, &time);
            }

            // Still no loader
            if (!pPeb32->Ldr)
            {
                DebugMessage("BlackBone: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
                return NULL;
            }

            // Search in InLoadOrderModuleList
            for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
                pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
                pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
            {
                UNICODE_STRING ustr;
                PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

                RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

                if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
                    return (PVOID)pEntry->DllBase;
            }
        }
        // Native process
        else
        {
            PPEB pPeb = PsGetProcessPeb(pProcess);
            if (!pPeb)
            {
                DebugMessage("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
                return NULL;
            }

            // Wait for loader a bit
            for (INT i = 0; !pPeb->Ldr && i < 10; i++)
            {
                DebugMessage("BlackBone: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
                KeDelayExecutionThread(KernelMode, TRUE, &time);
            }

            // Still no loader
            if (!pPeb->Ldr)
            {
                DebugMessage("BlackBone: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
                return NULL;
            }

            // Search in InLoadOrderModuleList
            for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
                pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
                pListEntry = pListEntry->Flink)
            {
                PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
                    return pEntry->DllBase;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DebugMessage("BlackBone: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
    }

    return NULL;
}
