; Захват PEB.ProcessParameters.
;
; \IDP\Public\User\Test\t2.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

	includelib \masm32\lib\masm32.lib

udw2str proto :ULONG, :PVOID
StdOut proto :PSTR
			
BREAKERR macro
	.if Eax
	int 3
	.endif
endm

.data
BreakCount	ULONG ?
Buffer		CHAR 12 DUP (?)

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
	jnz Chain
	cmp [ecx].ExceptionCode,IDP_BREAKPOINT
	jne @f
	inc BreakCount
	jmp Continue
@@:
	cmp [ecx].ExceptionCode,IDP_SINGLE_STEP
	jne Chain
Continue:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	ret
Chain:
	xor eax,eax
	ret
ExceptionDispatcher endp

$MsgCall	CHAR "Breaks: ",0

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

	mov ecx,fs:[TEB.Peb]
	mov eax,IDP_ADD_REFERENCE
	lea ecx,PEB.ProcessParameters[ecx]
	push sizeof(RTL_USER_PROCESS_PARAMETERS)
	push ecx
	Call IDP
	BREAKERR
	
; AllocConsole -> SetUpConsoleInfo -> GetStartupInfoW ..
	invoke AllocConsole
	invoke StdOut, addr $MsgCall
	invoke udw2str, BreakCount, addr Buffer
	invoke StdOut, addr Buffer
	invoke Sleep, INFINITE
	ret
Entry endp
end Entry