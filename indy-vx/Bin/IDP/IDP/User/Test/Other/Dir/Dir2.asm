; Директория конфигурации ntdll.dll
;
; \IDP\Public\User\Test\Other\Dir\Dir2.asm
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

.data
OldPrefixTable	LOCK_PREFIX_TABLE <>

.code
CRLF	equ 13, 10, 0

$LdrQueryInLoadOrderModuleList		CHAR "LdrQueryInLoadOrderModuleList( *InLoadOrderModuleList:%p, *InInitializationOrderModuleList:%p )", CRLF
$LdrQueryNextListEntry				CHAR "LdrQueryNextListEntry( TableEntry:%p, *NextTableEntry:%p )", CRLF
$LdrQueryModuleInfoFromLdrEntry		CHAR "LdrQueryModuleInfoFromLdrEntry( ModuleInformation:%p, TableEntry:%p, InInitializationOrderModuleList:%p )", CRLF
$LdrQueryModuleInfoLocalLoaderLock		CHAR "LdrQueryModuleInfoLocalLoaderLock()", CRLF
$LdrQueryModuleInfoLocalLoaderUnlock	CHAR "LdrQueryModuleInfoLocalLoaderUnlock( LoaderLock:%p )", CRLF

; Калбэки для LdrQueryProcessModuleInformation().
;
LdrQueryInLoadOrderModuleList:
	pushad
	mov ebx,esp
	invoke DbgPrint, addr $LdrQueryInLoadOrderModuleList, dword ptr [ebx + 4*8 + 4*2], dword ptr [ebx + 4*8 + 4*3]
	popad
	jmp OldPrefixTable.pLdrQueryInLoadOrderModuleList

LdrQueryNextListEntry:
	pushad
	mov ebx,esp
	invoke DbgPrint, addr $LdrQueryNextListEntry, dword ptr [ebx + 4*8 + 4*2], dword ptr [ebx + 4*8 + 4*3]
	popad
	jmp OldPrefixTable.pLdrQueryNextListEntry

LdrQueryModuleInfoFromLdrEntry:
	pushad
	mov ebx,esp
	invoke DbgPrint, addr $LdrQueryModuleInfoFromLdrEntry, dword ptr [ebx + 4*8 + 4*3], dword ptr [ebx + 4*8 + 4*4], dword ptr [ebx + 4*8 + 4*5]
	popad
	jmp OldPrefixTable.pLdrQueryModuleInfoFromLdrEntry

LdrQueryModuleInfoLocalLoaderLock:
	pushad
	invoke DbgPrint, addr $LdrQueryModuleInfoLocalLoaderLock
	popad
	jmp OldPrefixTable.pLdrQueryModuleInfoLocalLoaderLock

LdrQueryModuleInfoLocalLoaderUnlock:
	pushad
	mov ebx,esp
	invoke DbgPrint, addr $LdrQueryModuleInfoLocalLoaderUnlock, dword ptr [ebx + 4*8 + 4]
	popad
	jmp OldPrefixTable.pLdrQueryModuleInfoLocalLoaderUnlock

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

Entry proc
Local ModuleInformation:PVOID
Local ModuleInformationLength:ULONG
	invoke QueryLockPrefixTable
	.if !Eax
	int 3
	.endif
	mov esi,eax
	mov ebx,eax
	mov ModuleInformation,0
	mov ModuleInformationLength,32*sizeof(RTL_PROCESS_MODULE_INFORMATION) + 4
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr ModuleInformation, 0, addr ModuleInformationLength, MEM_COMMIT, PAGE_READWRITE
	BREAKERR
	lea edi,OldPrefixTable
	mov ecx,sizeof(LOCK_PREFIX_TABLE)/4
	cld
	rep movsd
	assume ebx:PLOCK_PREFIX_TABLE
	mov [ebx].pLdrQueryInLoadOrderModuleList,offset LdrQueryInLoadOrderModuleList
	mov [ebx].pLdrQueryNextListEntry,offset LdrQueryNextListEntry
	mov [ebx].pLdrQueryModuleInfoFromLdrEntry,offset LdrQueryModuleInfoFromLdrEntry
	mov [ebx].pLdrQueryModuleInfoLocalLoaderLock,offset LdrQueryModuleInfoLocalLoaderLock
	mov [ebx].pLdrQueryModuleInfoLocalLoaderUnlock,offset LdrQueryModuleInfoLocalLoaderUnlock
	invoke LdrQueryProcessModuleInformation, ModuleInformation, ModuleInformationLength, NULL
	BREAKERR
	ret
Entry endp
end Entry