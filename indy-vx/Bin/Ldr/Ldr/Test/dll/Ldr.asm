	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
.data
	include Map.inc
.code
	include Ldr.inc
	
$DllName	CHAR "ldr321.dll",0

Entry proc
Local ImageBase:PVOID
	lea eax,ImageBase
	push eax
	push 0
	push offset $DllName
	push offset gMap
	xor eax,eax	; Service ID.
	Call LDR
	int 3
	ret
Entry endp
end Entry