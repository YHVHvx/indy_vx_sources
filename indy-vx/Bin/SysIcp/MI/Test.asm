	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib

.code
	include SysIcp.inc
	
lpsz	db "..",0

$Message	CHAR "LOG #%p: %p", 13, 10, 0

SyscallCount	ULONG ?

ServiceDispatcher proc C
	pushad
	LOAD_DEFAULT_DS
	invoke DbgPrint, addr $Message, SyscallCount,  Eax
	inc SyscallCount
	LOAD_REDUCED_DS
	popad
	ret
ServiceDispatcher endp

Entry proc
	invoke MessageBeep, 0
	push offset ServiceDispatcher
	Call MIE
	.if Eax
	int 3
	.endif
	invoke MessageBox, 0, addr lpsz, addr lpsz, MB_OK
	ret
Entry endp
end Entry
