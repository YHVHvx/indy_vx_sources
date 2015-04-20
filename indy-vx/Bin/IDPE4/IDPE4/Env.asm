
; +
; Инициализация среды.
;	
EvGetPtr proc C
	push ebx
	push ecx
	push edx
	mov ebx,dword ptr fs:[TePeb]
	%PLOCK dword ptr [Ebx + ENV_OFFSET], Init, Error	; Ожидаем окончание инициализации среды в спинлоке.
Exit:
	pop edx
	pop ecx
	pop ebx
	test eax,eax
	ret
Init:
	push EOL
	push 0DA44E712H	; HASH("ZwFreeVirtualMemory")
	push 039542311H	; HASH("ZwProtectVirtualMemory")
	push 024741E13H	; HASH("ZwAllocateVirtualMemory")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG "EvGetPtr.LdrEncodeEntriesList(): 0x%X", Eax
	test eax,eax
	.if !Zero?
		add esp,4*4
		jmp Error
	.endif
	push sizeof(UENV)	; Size
	mov ecx,esp
	push 0	; Base
	mov edx,esp
	push PAGE_READWRITE
	push MEM_COMMIT
	push ecx
	push 0
	push edx
	push NtCurrentProcess
	Call dword ptr [Esp + 8*4]	; ZwAllocateVirtualMemory()
	%DBG "EvGetPtr.ZwAllocateVirtualMemory: 0x%X", Eax
	.if !Eax
		pop eax	; PUENV
		assume eax:PUENV
		pop ecx	; Size
		pop [eax].pZwAllocateVirtualMemory
		pop [eax].pZwProtectVirtualMemory
		pop [eax].pZwFreeVirtualMemory
		pop edx	; EOL
	.else
		add esp,6*4
Error:
		xor eax,eax
	.endif
Unlock:
	mov dword ptr [ebx + ENV_OFFSET],eax
	jmp Exit
EvGetPtr endp

; +
;
EvQueryMemory proc uses ebx Env:PUENV, Ip:PVOID, MmInfo:PMEMORY_BASIC_INFORMATION
	mov ebx,Env
	assume ebx:PUENV
	%PLOCK [ebx].LpZwQueryVirtualMemory, Init, Error
ApiCall:
	push NULL
	push sizeof(MEMORY_BASIC_INFORMATION)
	push MmInfo
	push MemoryBasicInformation
	push Ip
	push NtCurrentProcess
	%APICALL Eax, 6	; ZwQueryVirtualMemory()
Exit:
	ret
Init:
	push EOL
	push 0EA7DF819H	; HASH("ZwQueryVirtualMemory")
	invoke LdrEncodeEntriesList, NULL, Esp
	test eax,eax
	pop eax
	pop edx
	.if Zero?
		%PUNLOCK [ebx].LpZwQueryVirtualMemory,eax
		jmp ApiCall
	.endif
	%PUNLOCK [ebx].LpZwQueryVirtualMemory, LOCK_FAIL
	jmp Exit
Error:
	mov eax,STATUS_INTERNAL_ERROR
	jmp Exit
EvQueryMemory endp