	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	
.code
SIGNATURE_LENGTH	equ 44H

Ip proc

; LdrpFixSectionProtection:
; 	...
; 	6A FF		push -1
; 	E8 XXXXXXXX	call ntdll.ZwProtectVirtualMemory
; 	[LINE]
; 	68 XXXXXXXX	; ASCII "Set 0x%X protection for %p section for %d bytes, old protection 0x%X",LF
; 	[LINE]
; 	E8 XXXXXXXX	call ntdll.DbgPrintEx

Local BaseOfCode:PVOID, SizeOfCode:ULONG
	assume fs:nothing
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov ebx,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	mov ecx,ebx
	add ecx,IMAGE_DOS_HEADER.e_lfanew[ecx]
	assume ecx:PIMAGE_NT_HEADERS
	mov esi,[ecx].OptionalHeader.BaseOfCode
	mov edi,[ecx].OptionalHeader.SizeOfCode
	lea esi,[esi + ebx - 4]
	cld
	mov SizeOfCode,edi
	mov BaseOfCode,esi
	sub edi,SIGNATURE_LENGTH
Step:
	mov ecx,SIGNATURE_LENGTH/4
	xor eax,eax
@@:
	xor eax,dword ptr [esi + ecx*4]
	xor eax,ecx
	rol eax,cl
	loop @b
	cmp eax,60EC54DCH	; Hash
	je Found
	inc esi
	dec edi
	jnz Step
	int 3
Found:
	mov ecx,SizeOfCode	
	lea eax,[esi + 4]
	mov edx,BaseOfCode
	sub ecx,24H
Scan:
	cmp dword ptr [ecx + edx + 24H],eax
	je @f
	loop Scan
	int 3
@@:
	lea esi,[ecx + edx + 23H]
	cmp byte ptr [esi],68H
	jne Scan
	sub esi,20H
	mov ecx,20H
@@:
	cmp word ptr [esi + ecx],0FF6AH
	je Vale
	loop @b
	int 3
Vale:
	cmp byte ptr [esi + ecx + 2],0E8H
	jne @b
	lea eax,[esi + ecx + 7]
	add eax,dword ptr [eax - 4]	; *ZwProtectVirtualMemory
	
	; push service arg's.
	; Call Eax
	
	.if byte ptr [eax] != 0B8H
	   int 3
	.endif
	
	mov eax,dword ptr [eax + 1]	; ID
	
	.if Eax > 1000H
	   int 3
	.endif
	
	; push service arg's.
	; mov edx,esp
	; Int 2EH
	; add esp,5*4
	
Ip endp
end Ip