; Захват __security_check_cookie().
;
; \IDP\Public\User\Test\t6.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

_imp__RtlUnhandledExceptionFilter2 proto :dword, :dword
_imp__RtlIntegerToChar proto :dword, :dword, :dword, :dword
	
BREAKERR macro
	.if Eax
	int 3
	.endif
endm

.code
	include ..\Engine\mi\idp.inc

ExceptionDispatcher proc uses esi edi ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov eax,ExceptionPointers
	mov ecx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume ecx:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [ecx].ExceptionFlags,NULL
	jnz chain_
	cmp [ecx].ExceptionCode,IDP_BREAKPOINT
	je cont_
	cmp [ecx].ExceptionCode,IDP_SINGLE_STEP
	jne chain_
	mov eax,dword ptr [_imp__RtlUnhandledExceptionFilter2]
	cmp [edi].regEip,eax
	jb cont_
	add eax,40H
	cmp [edi].regEip,eax
	jnb cont_
	mov eax,[edi].regEbp
	mov eax,dword ptr [eax + 2*4]
	mov esi,dword ptr [eax + 4]	; PCONTEXT
	mov ecx,sizeof(CONTEXT)/4
	cld
	rep movsd
	mov CONTEXT.ContextFlags[edi - sizeof(CONTEXT)],CONTEXT_ALL
cont_:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	ret
chain_:
	xor eax,eax
	ret
ExceptionDispatcher endp

$Msg	CHAR "Test..", 13, 10, 0

comment '
RtlIntegerToChar:
	push 3C
	push 7C91A7F8
	call_SEH_prolog
	mov eax,dword ptr ds:[__security_cookie]
	'
Entry proc
	assume fs:nothing	
	mov eax,dword ptr [_imp__RtlIntegerToChar]
	cmp byte ptr [eax + 0CH],0A1H
	.if !Zero?
	int 3
	.endif
	mov eax,dword ptr [eax + 0DH]	; __security_cookie
	mov dword ptr ds:[eax],-1	

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
	
	mov ecx,fs:[TEB.Peb]
	mov eax,IDP_ADD_REFERENCE
	lea ecx,PEB.ProcessParameters[ecx]
	push sizeof(RTL_USER_PROCESS_PARAMETERS)
	push ecx
	Call IDP
	BREAKERR
	
	invoke DbgPrint, addr $Msg	; Break!

	ret
Entry endp
end Entry