	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

	include \masm32\include\ws2_32.inc
	includelib \masm32\lib\ws2_32.lib
	
	include \masm32\include\urlmon.inc
	includelib \masm32\lib\urlmon.lib

;	DBGBUILD	equ TRUE

.code
	include Img.asm
	include GCBE\Bin\Gcbe.inc

	include Hdr.inc
	include Tls.asm
	include Wsp.asm
	include Hmgr.asm
	include Body.asm
	include Trap.asm

%NTERR macro
	.if Eax
		Int 3
	.endif
endm

.code
$File db "c:\1.html", 0
$Link db "http://www.google.ru/",0

HsForceFlags    equ 10H    ; HEAP.ForceFlags

; def Heap.h
HsSignature	equ 8H	; HEAP_SEGMENT.Signature

HEAP_SIGNATURE			equ 0EEFFEEFFH
INVALID_HEAP_SIGNATURE	equ 0ECBFDAC0H

HEAP_FLAG_PAGE_ALLOCS			equ 01000000H
HEAP_SKIP_VALIDATION_CHECKS		equ 10000000H
HEAP_VALIDATE_ALL_ENABLED		equ 20000000H
HEAP_VALIDATE_PARAMETERS_ENABLED	equ 40000000H

xHmgrInvalidateHeapsCallback:
	%GET_CURRENT_GRAPH_ENTRY
HmgrInvalidateHeapsCallback proc HeapHandle:HANDLE, NewSign:ULONG 
	mov eax,NewSign
	mov ecx,HeapHandle
	lock xchg dword ptr [ecx + HsSignature],eax
	and dword ptr [ecx + HsForceFlags],NOT(HEAP_FLAG_PAGE_ALLOCS or HEAP_SKIP_VALIDATION_CHECKS)
	or dword ptr [ecx + HsForceFlags],(HEAP_VALIDATE_ALL_ENABLED or HEAP_VALIDATE_PARAMETERS_ENABLED)
	xor eax,eax
	ret
HmgrInvalidateHeapsCallback endp

PROCESS_HANDLE_TRACING_ENABLE struct
Flags		ULONG ?
PROCESS_HANDLE_TRACING_ENABLE ends

PROCESS_HANDLE_TRACING_ENABLE_EX struct
Flags		ULONG ?
TotalSlots	ULONG ?
PROCESS_HANDLE_TRACING_ENABLE_EX ends

PROCESS_HANDLE_TRACING_MAX_STACKS	equ 16

HANDLE_TRACE_DB_OPEN	equ 1
HANDLE_TRACE_DB_CLOSE	equ 2
HANDLE_TRACE_DB_BADREF	equ 3

PROCESS_HANDLE_TRACING_ENTRY struct
Handle		HANDLE ?
ClientId		CLIENT_ID <>
_Type		ULONG ?	; HANDLE_TRACE_DB_*
Stacks		PVOID PROCESS_HANDLE_TRACING_MAX_STACKS DUP (<>)
PROCESS_HANDLE_TRACING_ENTRY ends

PROCESS_HANDLE_TRACING_QUERY struct
Handle		HANDLE ?
TotalTraces	ULONG ?
HandleTrace	PROCESS_HANDLE_TRACING_ENTRY 1 DUP (<>)
PROCESS_HANDLE_TRACING_QUERY ends

ProcessHandleTracing	equ 32

Public DBG_LOG_ENABLE_TRACING

HtEnableHandleTracing proc Api:PAPIS
Local Tracing:PROCESS_HANDLE_TRACING_ENABLE
	mov eax,Api
	lea ecx,Tracing
	mov Tracing.Flags,NULL
	push sizeof(PROCESS_HANDLE_TRACING_ENABLE)
	push ecx
	push ProcessHandleTracing
	push NtCurrentProcess
DBG_LOG_ENABLE_TRACING::
	Call APIS.pZwSetInformationProcess[eax]
	ret
HtEnableHandleTracing endp

	Public xBodyEntry
xBodyEntry:
	%GET_CURRENT_GRAPH_ENTRY
BodyEntry proc uses ebx esi edi
Local Api:APIS
Local EnvBase:PVOID, EnvSize:PVOID
	invoke InitializeApis, addr Api
	test eax,eax
	jnz Exit
; Инициализация среды и TLS-буферов.
	mov EnvBase,eax
	mov EnvSize,4 * X86_PAGE_SIZE
	lea ecx,EnvSize
	lea edx,EnvBase
	push PAGE_READWRITE
	push MEM_COMMIT
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	Call Api.pZwAllocateVirtualMemory
	test eax,eax
	mov edi,EnvBase
	jnz Exit
	%SET_ENV_PTR Edi
	lea esi,Api
	mov ecx,sizeof(APIS)/4
	cld
	mov ebx,EnvBase
	rep movsd
	assume ebx:PENVIRONMENT
	invoke BodyInitialize, Ebx, addr [ebx].BodySnapshot
	test eax,eax
	jnz Exit
	invoke WspInitialize, Ebx, addr [ebx].WspSnapshot
	test eax,eax
	jnz Exit
	invoke HmgrInitialize, Ebx, addr [ebx].HmgrSnapshot
	test eax,eax
	jnz Exit
	%GET_GRAPH_ENTRY xXcptDispatch
	push eax
	push TRUE
	Call Api.pRtlAddVectoredExceptionHandler
	.if !Eax
	   mov eax,STATUS_UNSUCCESSFUL
	   jmp Exit
	.endif
	
	mov eax,fs:[TEB.Peb]
	push INVALID_HEAP_SIGNATURE
	or PEB.BeingDebugged[eax],1
	%GET_GRAPH_ENTRY xHmgrInvalidateHeapsCallback
	push eax
	Call Api.pRtlEnumProcessHeaps
	test eax,eax
	jnz Exit

	invoke HtEnableHandleTracing, Ebx
Exit:
	ret
BodyEntry endp

IcpStub:
	int 3
	
Ip proc
Local Wsa:WSADATA
Local wLength:ULONG
	invoke BodyEntry
	%NTERR
	invoke WSAStartup, 0202H, addr Wsa
	invoke socket, 0, 3, 1
	invoke ZwClose, Eax

	ifdef DBGBUILD
	   %HALT
	endif
	
	invoke ExitProcess, STATUS_SUCCESS
	ret
Ip endp
end Ip