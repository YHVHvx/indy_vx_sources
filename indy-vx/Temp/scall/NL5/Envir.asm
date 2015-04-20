%GETENVPTR macro
	Call GtEnvPtr
endm

ifdef OPT_ENABLE_DBG_LOG
	$GtEnvPtr_LdrEncodeEntriesList	CHAR "GtEnvPtr_LdrEncodeEntriesList(): 0x%X", CRLF
	$GtEnvPtr_ZwAllocateVirtualMemory	CHAR "GtEnvPtr_ZwAllocateVirtualMemory: 0x%X", CRLF
endif

; +
; Инициализация среды.
;	
GtEnvPtr proc C
	push ecx
	push edx
	%CPLCF0	; CF, ~ZF
; В U-mode среда хранится в PEB, для ядра во всех PCR.
	mov ecx,1
	.if Carry?
		mov edx,dword ptr fs:[PcSelfPcr]
	.else
		mov edx,dword ptr fs:[TePeb]
	.endif
; Инициализация выполняется однократно, только на одном камне одним тредом. В ядре возможна 
; реинициализация, так как ссылка на среду размещается в текущем PCR. Для атомарного доступа 
; необходимо использовать IPI, либо глобальную переменную. KM код должен выполнить синхронизацию.
	%LOCKREAD dword ptr [edx + ENV_OFFSET], Init	; Ожидаем окончание инициализации среды в спинлоке.
Quit:
	pop edx
	pop ecx
	test eax,eax
	ret
Init:
	push ebx	; NT
	push esi	; PENV
	push edi
	%CPLCF0
	mov esi,edx
	jc Kmode
Umode:
	push EOL
	push 0DA44E712H	; HASH("ZwFreeVirtualMemory")
	push 039542311H	; HASH("ZwProtectVirtualMemory")
	push 024741E13H	; HASH("ZwAllocateVirtualMemory")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG $GtEnvPtr_LdrEncodeEntriesList, Eax
	test eax,eax
	pop ebx	; @ZwAllocateVirtualMemory
	.if !Zero?
		add esp,3*4
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
	Call Ebx
	%DBG $GtEnvPtr_ZwAllocateVirtualMemory, Eax
	test eax,eax
	pop eax	; PUENV
	pop edx	; Size
	pop ecx	; @ZwProtectVirtualMemory
	pop edx	; @ZwFreeVirtualMemory
	lea esp,[esp + 4]	; EOL
	jnz Error
	assume eax:PUENV
	mov [eax].pZwProtectVirtualMemory,ecx
	mov [eax].pZwFreeVirtualMemory,edx
	mov [eax].pZwAllocateVirtualMemory,ebx
	jmp Unlock
ErrorK:
	add esp,2*4
Error:
	xor eax,eax
Unlock:
	mov dword ptr [esi + ENV_OFFSET],eax
Exit:
	pop edi
	pop esi
	pop ebx
	jmp Quit
Kmode:
	invoke LdrGetNtImageBaseK
	test eax,eax
	mov ebx,eax
	jz Error
	push EOL
	push 07BDF6C55H	; HASH("ExFreePool")
	push 0F56E599BH	; HASH("ExAllocatePool")
	invoke LdrEncodeEntriesList, Ebx, Esp
	test eax,eax
	pop edi	; @ExAllocatePool()
	jnz ErrorK
	push eax
	invoke LdrQueryKiAbiosGdt, Ebx, Esp
	test eax,eax
	pop esi	; @KiAbiosGdt
	jnz ErrorK
	push sizeof(KENV)	; Size
	push NonPagedPool
	Call Edi
	test eax,eax
	jz ErrorK
	assume eax:PKENV
	mov [eax].NtBase,ebx
	pop [eax].pExFreePool
	mov [eax].pExAllocatePool,edi
	mov ebx,eax
	invoke LdrLoadVariableInPcrs, Esi, 0, Eax, ENV_OFFSET
	test eax,eax
	jnz Error	; Память не освобождаем, ошибка маловероятна.
	mov eax,ebx
	jmp Exit
GtEnvPtr endp