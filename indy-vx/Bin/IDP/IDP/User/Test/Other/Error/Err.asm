; Получение адреса переменной g_dwLastErrorToBreakOn.
; Position Independent Code. Only for test!
;
; \IDP\Public\User\Test\Other\Error\Err.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
	include vars.inc

.code	; ERW

	include imgsup.asm

ENTRIES_LIST struct
_RtlAddVectoredExceptionHandler	PVOID ?
_RtlRemoveVectoredExceptionHandler	PVOID ?
_LdrEnumerateLoadedModules		PVOID ?
ENTRIES_LIST ends
PENTRIES_LIST typedef ptr ENTRIES_LIST

Gl_BugBreak				PVOID ?
Gl_pRtlComputeCrc32			PVOID ?
Gl_pg_dwLastErrorToBreakOn	PVOID ?
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; VEH
;
iExceptionDispatcher proc uses ebx esi ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov ecx,ExceptionPointers
	Call dt_
dt_:
	mov edx,EXCEPTION_POINTERS.ExceptionRecord[ecx]
	assume edx:PEXCEPTION_RECORD
	mov esi,EXCEPTION_POINTERS.ContextRecord[ecx]
	assume esi:PCONTEXT
	pop ebx
	cmp [edx].ExceptionFlags,NULL
	mov ecx,[esi].regEip
	jnz chain_
	cmp [edx].ExceptionCode,STATUS_SINGLE_STEP
	lea eax,[ebx + (offset StopTrace - offset dt_)]
	jne is_break_
	cmp eax,ecx
	je stop_
	mov eax,dword ptr [ebx + (offset Gl_BugBreak - offset dt_)]
	test eax,eax
	jz not_bug_
	.if Eax == 1
	mov dword ptr [ebx + (offset Gl_BugBreak - offset dt_)],ecx
	jmp stop_
	.endif
	cmp eax,ecx
	je stop_
not_bug_:
	cmp byte ptr [ecx],0A1H
	je load_
	cmp fs:[TEB.LastErrorValue],ERROR_INVALID_HANDLE
	jne step_
stop_:
	and [esi].regEFlags,NOT(EFLAGS_TF)
	jmp cont_
is_break_:
	cmp [edx].ExceptionCode,STATUS_BREAKPOINT
	jne chain_
	cmp [edx].ExceptionAddress,ecx
	lea eax,[ebx + (offset Breaker - offset dt_)]
	jne chain_
	cmp eax,ecx
	jne chain_
	inc [esi].regEip
	jmp step_
load_:
	mov ecx,dword ptr [ecx + 1]
	mov dword ptr [ebx + (Gl_pg_dwLastErrorToBreakOn - offset dt_)],ecx
step_:
	or [esi].regEFlags,EFLAGS_TF
cont_:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp exit_
chain_:
	xor eax,eax
exit_:
	ret
iExceptionDispatcher endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
;
LdrEnumerationCallback proc uses ebx DataTableEntry:PLDR_DATA_TABLE_ENTRY, KernelBase:PVOID, StopEnumeration:PVOID
	mov ebx,DataTableEntry
	assume ebx:PLDR_DATA_TABLE_ENTRY
	xor ecx,ecx
	movzx edx,[ebx].BaseDllName._Length
	push edx
	push [ebx].BaseDllName.Buffer
	push ecx
	$CALL Gl_pRtlComputeCrc32
	mov ecx,StopEnumeration
	cmp eax,2ECA438CH
	mov edx,KernelBase
	.if Zero?
	push [ebx].DllBase
	mov byte ptr [ecx],1
	pop dword ptr [edx]
	.endif
	ret
LdrEnumerationCallback endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
;
iQueryReference proc uses ebx PartialCrc:DWORD, pg_dwLastErrorToBreakOn:PVOID
Local pRtlComputeCrc32:PVOID
Local KernelImageBase:PVOID
Local pGetProcessId:PVOID
	ENTER_SEH
	lea ecx,pRtlComputeCrc32
	xor eax,eax
	push ecx
	push eax
	push eax
	$PUSH_STRING "RtlComputeCrc32"
	push eax
	Call NtImageQueryEntryFromCrc32
	test eax,eax
	mov ecx,pRtlComputeCrc32
	jnz exit_
	Call @f
Gl_EntriesList::
	ENTRIES_LIST < 0BAAB0208H, \	; RtlAddVectoredExceptionHandler
				0FED80136H, \	; RtlRemoveVectoredExceptionHandler
			  	0FC07EBC7H  >	; LdrEnumerateLoadedModules
	DD 0
@@:
	mov ebx,dword ptr [esp]
	push PartialCrc
	push pRtlComputeCrc32
	push NULL
	mov dword ptr [ebx + (offset Gl_pRtlComputeCrc32 - offset Gl_EntriesList)],ecx
	Call EncodeEntriesListFromCrc32
	test eax,eax
	jnz exit_
	lea ecx,KernelImageBase
	lea edx,[ebx + (offset LdrEnumerationCallback - offset Gl_EntriesList)]
	push ecx
	push edx
	push eax
	Call ENTRIES_LIST._LdrEnumerateLoadedModules[ebx]
	test eax,eax
	jnz exit_
	cmp KernelImageBase,eax
	lea ecx,pGetProcessId
	je error_
	invoke NtImageQueryEntryFromCrc32, KernelImageBase, 9B3D61A0H, pRtlComputeCrc32, PartialCrc, Ecx	; Crc32(GetProcessId)
	test eax,eax
	lea ecx,[ebx + offset (iExceptionDispatcher - offset Gl_EntriesList)]
	jnz exit_
	push ecx
	push 1
	Call dword ptr ENTRIES_LIST._RtlAddVectoredExceptionHandler[ebx]
	test eax,eax
	jz error_
	push EFLAGS_TF
	mov dword ptr [ebx + (offset Gl_BugBreak - offset Gl_EntriesList)], 1
	popfd
Breaker::
	int 3	; x1, (cli, hlt etc.)
	push eax
	Call pGetProcessId
StopTrace::
	lea ecx,[ebx + offset (iExceptionDispatcher - offset Gl_EntriesList)]
	jnz exit_
	push ecx
	Call dword ptr ENTRIES_LIST._RtlRemoveVectoredExceptionHandler[ebx]
	mov ecx,dword ptr [ebx + (offset Gl_pg_dwLastErrorToBreakOn - offset Gl_EntriesList)]
	mov edx,pg_dwLastErrorToBreakOn
	test ecx,ecx
	mov dword ptr [edx],ecx
	jz error_
	xor eax,eax
exit_:
	LEAVE_SEH
	ret
error_:
	mov eax,STATUS_UNSUCCESSFUL
	jmp exit_
iQueryReference endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
BREAKERR macro
	.if Eax
	int 3
	.endif
endm

$Result	CHAR "ref. g_dwLastErrorToBreakOn: %p", 13, 10, 0

STACK_FRAME struct
rEbp		PVOID ?	; Next frame, PSTACK_FRAME
rEip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

$Trace	CHAR "Backtrace frame:", 13, 10, 0
$Frame	CHAR " [%p]: Ebp = %p, Eip = %p", 13, 10, 0

; Тестовый VEH для вывода бактрейса, не пикод.
;
VectoredExceptionHandler proc uses ebx esi ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov eax,ExceptionPointers
	mov edx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume edx:PEXCEPTION_RECORD
	mov esi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume esi:PCONTEXT
	cmp [edx].ExceptionFlags,NULL
	jne chain_
	cmp [edx].ExceptionCode,STATUS_BREAKPOINT
	jne chain_
	mov ebx,[esi].regEbp
	assume ebx:PSTACK_FRAME
	invoke DbgPrint, addr $Trace
next_:
	cmp [ebx].rEip,0
	je stop_
	invoke DbgPrint, addr $Frame, Ebx, [Ebx].rEbp, [Ebx].rEip
	mov ebx,[ebx].rEbp
	jmp next_
stop_:
	inc [esi].regEip
cont_:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp exit_
chain_:
	xor eax,eax
exit_:
	ret
VectoredExceptionHandler endp

Entry proc
Local Reference:PVOID
	invoke iQueryReference, 0, addr Reference
	BREAKERR
	invoke DbgPrint, addr $Result
	mov ecx,Reference
	mov dword ptr [ecx],ERROR_INVALID_HANDLE
	invoke RtlAddVectoredExceptionHandler, 1, addr VectoredExceptionHandler
	.if !Eax
	int 3
	.endif
	invoke GetThreadPriority, 0
	ret
Entry endp
end Entry