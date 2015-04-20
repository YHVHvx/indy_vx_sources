	.686p
	.xmm
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.code
STARTCODE:
	mov esp,Dr7
	
	sidt [esp + eax + 100H]
	sgdt [esi + edi - 1]
	
	xchg esp,ebx
	xchg eax,esp
	
	bswap esp
	BYTE ESCAPE_0F, OP_SYSENTER
	
	lss esp,[eax]
	cmovz esp,eax
	movsx esp,al
	bts esp,ecx
	cmpxchg [eax],esp
	
	btc esp,10
	xchg eax,esp
	xchg esp,eax
	
	BYTE 8FH, 11000100B
	add esp,eax
	add eax,esp
	
	leave	; OP_LEAVE
	int 10h	; OP_INTN
	retn 4	; OP_RETN
	pop esp	; OP_POPESP

	add esp,esp
	
	bts esp,0
	
	enter 10, 10
	
	pop ss	; OP_POPSS
	ret		; OP_RET
	iretd	; OP_IRET
	retf		; OP_RETF
	
	lar esp,ecx
	movsx esp,al
	
	add esp,123
	xor esp,eax
	lea esp,[eax + ecx + 123]
	lds esp,[eax]

	BYTE 81H, 11000100B	; add esp,imm32
	BYTE 8FH, 11000100B	; pop esp
	
	pop esp
	popad
	push 123H
	
	popfd
	Call $

	mov Dr7,ecx
	nop

	include VirXasm32b.asm
	include LDE.asm

%NTERR macro
	.if Eax
	   Int 3
	.endif
endm

.data
LastIp	PVOID ?
IpCount	ULONG ?

.code
Entry proc
Local RegionBase:PVOID, RegionSize:ULONG
	mov RegionBase,NULL
	mov RegionSize,PAGE_SIZE*2
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr RegionBase, 0, addr RegionSize, MEM_RESERVE, PAGE_NOACCESS
	%NTERR
	mov RegionSize,PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr RegionBase, 0, addr RegionSize, MEM_COMMIT, PAGE_READWRITE
	%NTERR
	add RegionBase,X86_PAGE_SIZE - MAX_INSTRUCTION_LENGTH
	mov ebx,offset STARTCODE
	mov esi,ebx
	.repeat
		inc IpCount
		mov LastIp,ebx
		invoke LDE, RegionBase, Ebx
		add ebx,eax
		Call VirXasm32
		.if !al || (al > MAX_INSTRUCTION_LENGTH)
			int 3
		.endif
		add esi,eax
		.if Ebx != Esi
			Int 3
		.endif
	.until Esi == offset ENDCODE
	jmp $
	ret
ENDCODE::
Entry endp
end Entry