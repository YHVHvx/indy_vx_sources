; +
;
; Стаб для аллокации памяти.
;
EvAlloc proc uses ebx MaxSize:ULONG, CommitSize:ULONG, Protect:ULONG
Local Buffer:PVOID
	%GETENVPTR
	jz Exit
	mov ebx,eax
	%CPLCF0
	jc Kmode
	xor eax,eax
	assume ebx:PUENV
	cmp MaxSize,eax
	mov Buffer,eax
	lea ecx,CommitSize
	lea edx,Buffer
	push Protect
	jne GuardU
	push MEM_COMMIT
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	%APICALL [ebx].pZwAllocateVirtualMemory, 6
	.if !Eax
		mov eax,Buffer
	.else
Error:
		xor eax,eax
	.endif
Exit:
	test eax,eax
	ret
GuardU:
	lea ecx,MaxSize
	push MEM_RESERVE
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	%APICALL [ebx].pZwAllocateVirtualMemory, 6
	test eax,eax
	lea ecx,CommitSize
	lea edx,Buffer
	jnz Error
	push Protect
	push MEM_COMMIT
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	%APICALL [ebx].pZwAllocateVirtualMemory, 6
	test eax,eax
	mov eax,Buffer
	jz Exit
Free:
	lea eax,MaxSize
	lea ecx,Buffer
	mov MaxSize,NULL
	push MEM_RELEASE
	push eax
	push ecx
	push NtCurrentProcess
	%APICALL [ebx].pZwFreeVirtualMemory, 4
	jmp Error
Kmode:
	assume ebx:PKENV
	%OUT "WARNING: EvAlloc(KM GUARD NOT SUPPORTED)" 
;	cmp MaxSize,NULL
;	jne GuardK
	push MaxSize
	push NonPagedPool
	Call [ebx].pExAllocatePool
	jmp Exit
GuardK:
EvAlloc endp

; +
; Освобождение памяти.
;
EvFree proc Base:PVOID
	%GETENVPTR
	jz Exit
	%CPLCF0
	jc Kmode
	push NULL	; Size
	lea edx,Base
	mov ecx,esp
	push MEM_RELEASE
	push ecx
	push edx
	push NtCurrentProcess
	%APICALL UENV.pZwFreeVirtualMemory[eax], 4
Exit:
	ret
Kmode:
	push Base
	Call KENV.pExFreePool[eax]
	jmp Exit
EvFree endp	
	
; +
; Проверка нахождения двух адресов в одной проекции.
;
; o UM
;
EvAreTheSame proc uses ebx Env:PUENV, Ip1:PVOID, Ip2:PVOID
	mov ebx,Env
	.if !Ebx
		%GETENVPTR
		.if Zero?
			mov eax,STATUS_UNSUCCESSFUL
			jmp Exit
		.endif
		mov ebx,eax
	.endif
	assume ebx:PUENV
	%SPINLOCK [ebx].LpZwAreMappedFilesTheSame, Init, Error
ApiCall:
	push Ip2
	push Ip1
	%APICALL [ebx].pZwAreMappedFilesTheSame, 2	; ZwAreMappedFilesTheSame(Ip1, Ip2)
Exit:
	ret
Init:
	push EOL
	push 7CA4251FH	; HASH("ZwAreMappedFilesTheSame")
	invoke LdrEncodeEntriesList, NULL, Esp
	test eax,eax
	pop [ebx].pZwAreMappedFilesTheSame
	pop edx
	.if Zero?
		%UNLOCK [ebx].LpZwAreMappedFilesTheSame,LOCK_INIT
		jmp ApiCall
	.endif
	%UNLOCK [ebx].LpZwAreMappedFilesTheSame,LOCK_FAIL
	jmp Exit
Error:
	mov eax,STATUS_INTERNAL_ERROR
	jmp Exit
EvAreTheSame endp

EvQueryMemory proc uses ebx Env:PUENV, Ip:PVOID, MmInfo:PMEMORY_BASIC_INFORMATION
	mov ebx,Env
	.if !Ebx
		%GETENVPTR
		.if Zero?
			mov eax,STATUS_UNSUCCESSFUL
			jmp Exit
		.endif
		mov ebx,eax
	.endif
	assume ebx:PUENV
	%SPINLOCK [ebx].LpZwQueryVirtualMemory, Init, Error
ApiCall:
	push NULL
	push sizeof(MEMORY_BASIC_INFORMATION)
	push MmInfo
	push MemoryBasicInformation
	push Ip
	push NtCurrentProcess
	%APICALL [ebx].pZwQueryVirtualMemory, 6	; ZwQueryVirtualMemory()
Exit:
	ret
Init:
	push EOL
	push 0EA7DF819H	; HASH("ZwQueryVirtualMemory")
	invoke LdrEncodeEntriesList, NULL, Esp
	test eax,eax
	pop [ebx].pZwQueryVirtualMemory
	pop edx
	.if Zero?
		%UNLOCK [ebx].LpZwQueryVirtualMemory,LOCK_INIT
		jmp ApiCall
	.endif
	%UNLOCK [ebx].LpZwQueryVirtualMemory,LOCK_FAIL
	jmp Exit
Error:
	mov eax,STATUS_INTERNAL_ERROR
	jmp Exit
EvQueryMemory endp

; +
;
EvQuerySysGate proc uses ebx Env:PUENV
	mov ebx,Env
	.if !Ebx
		%GETENVPTR
		.if Zero?
			mov eax,STATUS_UNSUCCESSFUL
			jmp Exit
		.endif
		mov ebx,eax
	.endif
	assume ebx:PUENV
	%SPINLOCK [ebx].LockGate, Init, Error
	mov eax,[ebx].SysGate
	mov ecx,[ebx].FastGate
Exit:
	ret
Init:
	Call GtInitU
	test eax,ecx
	.if !Zero?
		%UNLOCK [ebx].LockGate,LOCK_INIT
		jmp Exit
	.endif
	%UNLOCK [ebx].LockGate,LOCK_FAIL
	jmp Exit
Error:
	xor eax,eax
	xor ecx,ecx
	jmp Exit
EvQuerySysGate endp