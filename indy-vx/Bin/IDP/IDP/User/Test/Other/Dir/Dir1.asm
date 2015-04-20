; Директория конфигурации ntdll.dll
;
; \IDP\Public\User\Test\Other\Dir\Dir1.asm
; 
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

; References:
; o LdrQueryProcessModuleInformation
; o LdrQueryProcessModuleInformationEx
; o RtlQueryProcessDebugInformation

; LdrpLockPrefixTable
; Link in load configuration directory.
;
LOCK_PREFIX_TABLE struct
CriticalSectionLocks				PVOID 8 DUP (?)
pLdrQueryInLoadOrderModuleList		PVOID ?
pLdrQueryNextListEntry				PVOID ?
pLdrQueryModuleInfoFromLdrEntry		PVOID ?
pLdrQueryModuleInfoLocalLoaderLock		PVOID ?
pLdrQueryModuleInfoLocalLoaderUnlock	PVOID ?
LOCK_PREFIX_TABLE ends
PLOCK_PREFIX_TABLE typedef ptr LOCK_PREFIX_TABLE

; For LdrQueryModuleInfoFromLdrEntry().
;
RTL_PROCESS_MODULE_INFORMATION struct
Section			ULONG ?
MappedBase		ULONG ?
ImageBase			PVOID ?
ImageSize			ULONG ?
Flags			ULONG ?
LoadOrderIndex		USHORT ?
InitOrderIndex		USHORT ?
LoadCount			USHORT ?
OffsetToFileName	USHORT ?
FullPathName		CHAR 256 DUP (?)
RTL_PROCESS_MODULE_INFORMATION ends
PRTL_PROCESS_MODULE_INFORMATION typedef ptr RTL_PROCESS_MODULE_INFORMATION

; For LdrQueryProcessModuleInformation().
;
RTL_PROCESS_MODULES struct
NumberOfModules	ULONG ?
Modules			RTL_PROCESS_MODULE_INFORMATION 1 DUP (<>)
RTL_PROCESS_MODULES ends
PRTL_PROCESS_MODULES typedef ptr RTL_PROCESS_MODULES

comment '
NTSTATUS
LdrQueryInLoadOrderModuleList(
	IN HANDLE ProcessHandle OPTIONAL,
	OUT PLIST_ENTRY *InLoadOrderModuleList,
	OUT PLIST_ENTRY *InInitializationOrderModuleList OPTIONAL
	);

NTSTATUS
LdrQueryNextListEntry(
	IN HANDLE ProcessHandle OPTIONAL,
	IN PLDR_DATA_TABLE_ENTRY TableEntry,
	OUT PLDR_DATA_TABLE_ENTRY *NextTableEntry,
	);

NTSTATUS
LdrQueryModuleInfoFromLdrEntry(
	IN HANDLE ProcessHandle OPTIONAL,
	IN PVOID Reserved1,
	OUT PRTL_PROCESS_MODULE_INFORMATION ModuleInfo,
	IN PLDR_DATA_TABLE_ENTRY TableEntry,
	IN PLIST_ENTRY InInitializationOrderModuleList	; Optional if ProcessHandle != NULL.
	);

PRTL_CRITICAL_SECTION	; LdrpLoaderLock
LdrQueryModuleInfoLocalLoaderLock(
	);

VOID
LdrQueryModuleInfoLocalLoaderUnlock
	IN PRTL_CRITICAL_SECTION LoaderLock
	);
'
.code
; +
; Получает ссылку на LdrpLockPrefixTable:LOCK_PREFIX_TABLE
; Находится в секции данных, возможна замена хэндлеров.
;
QueryLockPrefixTable proc C
	assume fs:nothing
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.DllBase[eax]
	mov ecx,IMAGE_DOS_HEADER.e_lfanew[eax]
	add eax,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG*sizeof(IMAGE_DATA_DIRECTORY) + eax + ecx]	; _load_config_used
	mov eax,IMAGE_LOAD_CONFIG_DIRECTORY.LockPrefixTable[eax]	; LdrpLockPrefixTable
	ret
QueryLockPrefixTable endp

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

$Msg		CHAR "DllBase: %p, DllSize: %p, LoadCount: %p, Name: %s", 13, 10, 0

Entry proc
Local ModuleInformation:RTL_PROCESS_MODULE_INFORMATION
Local InLoadOrderModuleList:PVOID
	lea edi,ModuleInformation
	xor eax,eax
	cld
	mov ecx,sizeof(RTL_PROCESS_MODULE_INFORMATION)/4
	rep stosd
	invoke QueryLockPrefixTable
	.if !Eax
	int 3
	.endif
	lea edi,InLoadOrderModuleList
	mov ebx,eax
	Call LOCK_PREFIX_TABLE.pLdrQueryModuleInfoLocalLoaderLock[ebx]
	mov esi,eax
	push NULL
	push edi
	push NtCurrentProcess
	Call LOCK_PREFIX_TABLE.pLdrQueryInLoadOrderModuleList[ebx]
	BREAKERR
	push edi
	push InLoadOrderModuleList
	push NtCurrentProcess
	Call LOCK_PREFIX_TABLE.pLdrQueryNextListEntry[ebx]	; .exe
	BREAKERR
	push edi
	push InLoadOrderModuleList
	push NtCurrentProcess
	Call LOCK_PREFIX_TABLE.pLdrQueryNextListEntry[ebx]	; ntdll.dll
	BREAKERR
	push edi
	push InLoadOrderModuleList
	push NtCurrentProcess
	Call LOCK_PREFIX_TABLE.pLdrQueryNextListEntry[ebx]	; kernel32.dll
	BREAKERR
	push eax
	lea ecx,ModuleInformation
	push InLoadOrderModuleList
	push ecx
	push eax
	push NtCurrentProcess
	Call LOCK_PREFIX_TABLE.pLdrQueryModuleInfoFromLdrEntry[ebx]
	BREAKERR
	push esi
	Call LOCK_PREFIX_TABLE.pLdrQueryModuleInfoLocalLoaderUnlock[ebx]
	lea ecx,ModuleInformation.FullPathName
	movzx edx,ModuleInformation.LoadCount
	invoke DbgPrint, addr $Msg, ModuleInformation.ImageBase, ModuleInformation.ImageSize, Edx, Ecx
	ret
Entry endp
end Entry