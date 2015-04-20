; \IDP\Public\User\Test\Other\TrCalls\Tc.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

_imp__LdrLoadDll proto :dword, :dword, :dword, :dword

EFLAGS_MASK	equ 202H

THREAD_CALL_PROCESSING_FLAG	equ dword ptr (PAGE_SIZE - 4)
THREAD_CALL_PROCESSING_EIP	equ dword ptr (PAGE_SIZE - 2*4)

.code
include ..\..\..\Bin\Graph\Dasm\Op.asm

Breaker proc C
	int 3
Breaker endp

$Call	CHAR "Call at %p", 13, 10, 0
$Skip	CHAR "Skip the procedure at %p", 13, 10, 0

ExceptionDispatcher proc uses esi edi ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov eax,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jne chain_
	cmp [esi].ExceptionCode,STATUS_SINGLE_STEP
	je @f
	cmp [esi].ExceptionCode,STATUS_BREAKPOINT
	jne chain_
	cmp [esi].ExceptionAddress,offset Breaker
	jne chain_
	mov eax,fs:[THREAD_CALL_PROCESSING_EIP]
	or [edi].regEFlags,EFLAGS_TF
	mov [edi].regEip,eax
	jmp cont_
@@:
	cmp fs:[THREAD_CALL_PROCESSING_FLAG],FALSE
	je @f
	lea ecx,Breaker
	mov eax,[edi].regEsp
	xchg dword ptr [eax],ecx
	mov fs:[THREAD_CALL_PROCESSING_EIP],ecx
	mov fs:[THREAD_CALL_PROCESSING_FLAG],FALSE
	invoke DbgPrint, addr $Skip, [esi].ExceptionAddress
	jmp cont_tf_	
@@:
	invoke QueryOpcodeTypeEx, [esi].ExceptionAddress
	cmp al,OP_TYPE_RET	; & far return..
	je cont_tf_
	or [edi].regEFlags,EFLAGS_TF
	cmp al,OP_TYPE_CALL	; & far call..
	jne cont_
	invoke DbgPrint, addr $Call, [esi].ExceptionAddress
	mov fs:[THREAD_CALL_PROCESSING_FLAG],TRUE
	jmp cont_
cont_tf_:
	and [edi].regEFlags,NOT(EFLAGS_TF)
cont_:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	ret
chain_:
	xor eax,eax
	ret
ExceptionDispatcher endp

$DllName	CHAR "psapi.dll",0

Entry proc
Local DllName:UNICODE_STRING
Local DllHandle:HANDLE
	invoke RtlAddVectoredExceptionHandler, 1, addr ExceptionDispatcher
	.if !Eax
	int 3
	.endif
	invoke RtlCreateUnicodeStringFromAsciiz, addr DllName, addr $DllName
	lea ecx,DllHandle
	lea edx,DllName
	xor eax,eax
	push ecx
	push edx
	push eax
	push eax
	push EFLAGS_TF or EFLAGS_MASK
	popfd
	Call dword ptr [_imp__LdrLoadDll]
	ret
Entry endp
end Entry