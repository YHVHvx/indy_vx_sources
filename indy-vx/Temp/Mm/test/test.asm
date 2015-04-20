; \IDP\Public\User\Bin\Graph\Mm\Test\Test.asm
;
	.686
	.model flat, stdcall 
	option casemap :none 
	include \masm32\include\ntdll.inc

BREAKNZ macro
	.if Eax
	Int 3
	.endif
endm

.code
	include ..\Dump.inc

Entry proc
Local Buffer:PVOID, BufferHandle:HANDLE
	mov eax,MM_INITIALIZE
	Call MmEntry
	BREAKNZ
	lea ecx,BufferHandle
	lea edx,Buffer
	push ecx
	push edx
	push NULL
	push PAGE_SIZE*32
	mov eax,MM_ALLOCATE
	Call MmEntry
	BREAKNZ
	mov eax,Buffer
	mov ecx,32
@@:
	mov edx,dword ptr [eax]
	add eax,PAGE_SIZE
	loop @b
	push BufferHandle
	mov eax,MM_FREE
	Call MmEntry
	BREAKNZ
	mov eax,MM_UNINITIALIZE
	Call MmEntry
	BREAKNZ
	ret
Entry endp
end Entry
