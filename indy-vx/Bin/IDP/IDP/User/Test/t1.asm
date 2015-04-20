; \IDP\Public\User\Test\t1.asm
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
align_	byte 3 dup (?)
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
	
	push 2*4	; Размер области памяти.
	push offset Reference	; Ссылка на область.
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	nop
	
	mov eax,dword ptr [Reference]
;	mov ecx,dword ptr [eax - 1]	; AV
	mov ecx,dword ptr [eax]
	mov ecx,dword ptr [eax + 1]
	mov ecx,dword ptr [eax + 2]
	mov ecx,dword ptr [eax + 3]
;	...
	mov ecx,dword ptr [eax + 7]
;	mov ecx,dword ptr [eax + 8]	; AV
	int 3
	ret
Entry endp
end Entry