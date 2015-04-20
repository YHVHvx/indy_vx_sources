	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \MASM32\LIB\ntdll.lib
	
	include \masm32\include\user32.inc
	includelib \MASM32\LIB\user32.lib
.code
DllEntry proc hmodule:DWORD, reason:DWORD, unused:DWORD
	.if reason == DLL_PROCESS_ATTACH
	xor eax,eax
	inc eax
	.endif
	ret
DllEntry Endp

$Str		CHAR "..",0

Initialize proc
	invoke MessageBox, 0, addr $Str, addr $Str, MB_OK
	ret
Initialize endp
end DllEntry