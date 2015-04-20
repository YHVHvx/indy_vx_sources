	.686p
	.xmm
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.data
Iters	ULONG ?

.code
	include VirXasm32b.asm
	include LDE.asm

%NTERR macro
	.if Eax
	   Int 3
	.endif
endm

Entry proc
Local RegionBase:PVOID, RegionSize:ULONG
Local Buffer[16]:BYTE
Local Seed:ULONG
	cld
	mov RegionBase,NULL
	mov RegionSize,PAGE_SIZE*2
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr RegionBase, 0, addr RegionSize, MEM_RESERVE, PAGE_NOACCESS
	%NTERR
	mov RegionSize,PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr RegionBase, 0, addr RegionSize, MEM_COMMIT, PAGE_READWRITE
	%NTERR
	add RegionBase,X86_PAGE_SIZE - MAX_INSTRUCTION_LENGTH
	lea esi,Buffer
	mov Seed,2
Next:
	lea edi,Buffer
	lea ebx,[esi + MAX_INSTRUCTION_LENGTH]
	.repeat
		invoke RtlRandom, addr Seed
		mov eax,Seed
		stosd
	.until Edi >= Ebx
	inc Iters
	invoke LDE, RegionBase, Esi
	mov ebx,eax
	Call VirXasm32
	.if !al || (al > MAX_INSTRUCTION_LENGTH) || (bl != al)
		int 3
	.endif
	jmp Next
	ret
ENDCODE::
Entry endp
end Entry