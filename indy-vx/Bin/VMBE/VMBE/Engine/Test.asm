	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
.code
	include VM.inc
	
_imp__RtlComputeCrc32 proto PartialCrc:ULONG, Buffer:PVOID, _Length:ULONG

$Str	CHAR "avcrap!", 0

MAGIC	equ 194

TestIp proc
	push sizeof $Str
	push offset $Str
	push 0
	mov eax,esp
	push 3
	push eax
	push dword ptr [_imp__RtlComputeCrc32]
	Call VMBYPASS
	add esp,3*4
	xor eax,0A05DB9D3H
	.if Zero?
		.if (Edx == MAGIC) && (Ecx > 10H)
			Int 3	; !VM
		.endif
	.endif
	ret
TestIp endp
end TestIp