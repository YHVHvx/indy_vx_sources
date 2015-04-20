	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

.code
	include Dump.inc

$DbgOut	CHAR "Value: %p", 13, 10, 0
$DllName	CHAR "User32.dll",0
$MsgBox	CHAR "MessageBoxA",0

BREAKNTERR macro
	.if Eax
	int 3
	.endif
endm

BREAKWINERR macro
	.if !Eax
	int 3
	.endif
endm

Entry proc
	Call LoggerInitialize
	invoke LoadLibrary, addr $DllName
	BREAKWINERR
	invoke GetProcAddress, Eax, addr $MsgBox
	BREAKWINERR
	push MB_OK
	push offset $MsgBox
	push offset $MsgBox
	push 0
	Call Eax
	ret
Entry endp
end Entry