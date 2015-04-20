; \IDP\Public\User\Test\t3.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

.data
Space	dd 123456H
		dd 0ABCDEH
		
Reference	dd offset Space

.code
	include ..\Engine\mi\idp.inc
	
ExceptionDispatcher proc ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov eax,ExceptionPointers
	mov ecx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume ecx:PEXCEPTION_RECORD
	mov edx,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edx:PCONTEXT
	cmp [ecx].ExceptionFlags,NULL
	jnz chain_
	cmp [ecx].ExceptionCode,IDP_BREAKPOINT
	je cont_
	cmp [ecx].ExceptionCode,IDP_SINGLE_STEP
	je cont_
;	...
chain_:
	xor eax,eax
	ret
cont_:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	ret
ExceptionDispatcher endp

Entry proc
Local Buffer[8]:BYTE
	assume fs:nothing
	mov eax,IDP_INITIALIZE_ENGINE
	Call IDP
	BREAKERR
	
	push offset ExceptionDispatcher
	push 0
	mov eax,IDP_ADD_VEH
	Call IDP
	.if !Eax
	int 3
	.endif
	
	push 4
	push offset Reference
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	nop
	
	mov esi,dword ptr [Reference]
	lea edi,Buffer
	mov ecx,4
	push ds
	pop fs
	DB PREFIX_FS
	movsd
	int 3
	ret
Entry endp
end Entry