	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
.code GPECODE
	include ..\Bin\Gpe.inc

GCBE_PARSE_NL_UNLIMITED	equ -1

%NTERR macro
	.if Eax
	Int 3
	.endif
endm

.data
pRoutine		PVOID offset GPE	; Адрес разбираемой процедуры.
NestingLevel	ULONG GCBE_PARSE_NL_UNLIMITED	; Уровень вложенности. Для одной процедуры 1.

.code
$Msg	CHAR "0x%X", 13, 10, 0

	assume fs:nothing
Ep proc
Local GpBase:PVOID, GpLimit:PVOID, GpSize:ULONG
Local OldProtect:ULONG
	mov GpBase,NULL
	mov GpSize,1000H * X86_PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr GpBase, 0, addr GpSize, MEM_COMMIT, PAGE_READWRITE
	mov ebx,GpBase
	%NTERR
	add GpBase,0FFFH * X86_PAGE_SIZE
	mov GpSize,X86_PAGE_SIZE
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr GpBase, addr GpSize, PAGE_NOACCESS, addr OldProtect
	%NTERR
	mov GpLimit,ebx
	mov GpBase,ebx
	lea ecx,GpLimit
	push eax
	push eax
	push eax
	push eax
	push eax
	push NestingLevel
	push GCBE_PARSE_DISCLOSURE
	push ecx
	push pRoutine
	%GPCALL GP_PARSE
	%NTERR

	xor ebx,ebx
	mov esi,GpBase
@@:
	test dword ptr [esi + EhEntryType],TYPE_MASK
	.if Zero?		; Line
	add ebx,dword ptr [esi + EhSize]
	.else
	push dword ptr [esi + EhAddress]
	%GPCALL GP_LDE
	add ebx,eax
	.endif
	add esi,ENTRY_HEADER_SIZE
	cmp GpLimit,esi
	ja @b
	
	invoke DbgPrint, addr $Msg, Ebx
	ret
Ep endp
end Ep