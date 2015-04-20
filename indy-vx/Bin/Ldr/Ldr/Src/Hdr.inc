ObjectHandleFlagInformation	equ 4

FUNCTION_TABLE struct
; NT
pZwSetInformationObject			PVOID ?
pZwUnmapViewOfSection			PVOID ?
pZwQuerySystemInformation		PVOID ?
pZwOpenSection					PVOID ?
pZwCreateSection				PVOID ?
pZwMapViewOfSection				PVOID ?
pZwClose						PVOID ?
pZwQueryObject					PVOID ?
pZwAllocateVirtualMemory			PVOID ?
pZwFreeVirtualMemory			PVOID ?
;pZwProtectVirtualMemory			PVOID ?
; RTL
;pRtlInitializeCriticalSection	PVOID ?
;pRtlDeleteCriticalSection		PVOID ?	; * Ќе используем внешние кс, достаточно LdrpLoaderLock.
;pRtlEnterCriticalSection		PVOID ?
;pRtlLeaveCriticalSection		PVOID ?
pRtlAddVectoredExceptionHandler	PVOID ?
pRtlRemoveVectoredExceptionHandler	PVOID ?
pRtlCreateUnicodeStringFromAsciiz	PVOID ?
pRtlFreeUnicodeString			PVOID ?
pRtlCompareUnicodeString			PVOID ?
; LDR
pLdrLoadDll					PVOID ?
; KI
;pKiUserExceptionDispatcher		PVOID ?	; * ќпределим динамически генерацией трассировочного останова в диспетчере.
FUNCTION_TABLE ends

ENVIRONMENT struct
Fn			FUNCTION_TABLE <>
CalloutList	PLIST_ENTRY ?
DllName		UNICODE_STRING <>
Directory		UNICODE_STRING <>
StackData		DWORD ?
SectionHandle	HANDLE ?
DesiredBase	PVOID ?	; IMAGE_NT_HEADERS.OptionalHeader.ImageBase
ViewBase		PVOID ?
Buffer		PVOID ?
BugIp		PVOID ?
Recursion		BOOLEAN ?
Status		ULONG ?	; LDR_STATUS_*
ENVIRONMENT ends
PENVIRONMENT typedef ptr ENVIRONMENT

LDR_STATUS_PROCESSING		equ 0
LDR_STATUS_SECTION_OPENED	equ 1
LDR_STATUS_SECTION_MAPPED	equ 2
LDR_STATUS_SECTION_CHECKED	equ 3
LDR_STATUS_SECTION_CLOSED	equ 4

TfBreaker	equ 0
TfTracer	equ 8
TfSignal	equ 7
TfHalt	equ 6

; +
;
$PUSH_FN_TABLE macro
; CRC32
;	push 023A2D386H
	push 0183679F2H
	push 0699A6209H
	push 043681CE6H
	push 0F45CAC9DH
	push 0FED80136H
	push 0BAAB0208H
;	push 09FF81F51H
;	push 058FF5064H
;	push 06023E15CH
;	push 08D76F9A4H
;	push 0D2654135H
	push 0F97A25D4H
	push 0D820A574H
	push 05A91FB11H
	push 0180C0D23H
	push 0D287EE26H
	push 02C919477H
	push 073BDFD70H
	push 0F775FBC7H
	push 09D35F923H
	push 051AA9C9BH
endm

$GET_ENVIRONMENT macro Reg32
	mov Reg32,fs:[TEB.Tib.StackBase]
	mov Reg32,dword ptr [Reg32 - 4]
endm