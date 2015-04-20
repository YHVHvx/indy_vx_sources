; \IDP\Public\User\Test\t4.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
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
$DllName	CHAR "psapi.dll",0

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

	mov ebx,fs:[TEB.Peb]
	mov ebx,PEB.Ldr[ebx]
	mov ebx,PEB_LDR_DATA.InLoadOrderModuleList.Flink[ebx]
	mov ebx,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[ebx]
	invoke wcslen, LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer[ebx]
	lea eax,[eax*2 + 2]
	lea ebx,LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer[ebx]
	push eax
	push ebx
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	
	invoke LoadLibrary, addr $DllName
	.if !Eax
	int 3
	.endif
	invoke AllocConsole
	invoke StdOut, addr $MsgCall
	invoke udw2str, BreakCount, addr Buffer
	invoke StdOut, addr Buffer
	invoke Sleep, INFINITE
	ret
Entry endp
end Entry