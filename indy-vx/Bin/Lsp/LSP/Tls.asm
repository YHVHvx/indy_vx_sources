; Менеджер TLS.
;
; (c) Indy, 2011
;
.code

TLS_ENTRY struct
Teb	PTEB ?
Tid	HANDLE ?	; Thread Id
Tls	TLS <>
TLS_ENTRY ends
PTLS_ENTRY typedef ptr TLS_ENTRY

TLS_MAX_ENTRIES	equ 8C0H

; +
; Удаление описателей для завершённых потоков.
;	
TlsCleaningCycle proc uses ebx esi edi Apis:PAPIS
Local Free:PTLS_ENTRY, MemoryInformation:MEMORY_BASIC_INFORMATION
	mov ebx,Apis
	mov eax,TLS_MAX_ENTRIES
	test ebx,ebx
	cld
	mov Free,NULL
	.if Zero?
		%GET_ENV_PTR Ebx
	.endif
	lea esi,[ebx + sizeof(ENVIRONMENT)]
	assume esi:PTLS_ENTRY
	assume ebx:PENVIRONMENT
	.repeat
	   cmp [esi].Teb,NULL
	   mov edi,esi
	   .if Zero?
	      lea eax,[esi + TLS_ENTRY.Tls]
	      jmp Exit
	   .endif
	   lea eax,MemoryInformation
	   push NULL
	   push sizeof(MEMORY_BASIC_INFORMATION)
	   push eax
	   push MemoryBasicInformation
	   push [esi].Teb
	   push NtCurrentProcess
	   Call [ebx].Apis.pZwQueryVirtualMemory
	   test eax,eax
	   jnz Clear
	   cmp MemoryInformation.State,MEM_COMMIT
	   jne Clear
	   cmp MemoryInformation.Protect,PAGE_READWRITE
	   mov eax,[esi].Teb
	   jne Clear
	   cmp MemoryInformation._Type,MEM_PRIVATE
	   mov edx,[esi].Tid
	   jne Clear
	   .if (dword ptr TEB.Tib.Self[Eax] != Eax) || (dword ptr TEB.Cid.UniqueThread[Eax] != Edx)
	Clear:
	      .if Free == NULL
	         mov Free,edi
	      .endif
	      mov ecx,sizeof(TLS_ENTRY)/4
	      xor eax,eax
	      rep stosd
	   .endif
	   add esi,sizeof(TLS_ENTRY)
	   dec eax
	.until Zero?
Load:
	mov eax,Free
	.if Eax
	   add eax,TLS_ENTRY.Tls
	.endif
Exit:
	ret
TlsCleaningCycle endp

; +
; Поиск TLS в массиве.
;
TlsGet proc uses ebx Apis:PAPIS
	mov ebx,Apis
	mov ecx,fs:[TEB.Tib.Self]
	test ebx,ebx
	mov edx,fs:[TEB.Cid.UniqueThread]
	.if Zero?
		%GET_ENV_PTR Ebx
	.endif
	add ebx,sizeof(ENVIRONMENT)
	assume ebx:PTLS_ENTRY
	mov eax,TLS_MAX_ENTRIES
	.repeat
	   cmp [ebx].Teb,NULL
	   je Alloc
	   cmp [ebx].Teb,ecx
	   je IsTid
   Scan:
	   add ebx,sizeof(TLS_ENTRY)
	   dec eax
	.until Zero?
	; Лимит описателей исчерпан. Выполняем цикл очистки.
	invoke TlsCleaningCycle, Apis	; Вернёт свободный блок.
	jmp Exit
IsTid:
	cmp [ebx].Tid,edx
	jne Scan
	jmp Load
; Вход не найден, создаём его.
Alloc:
	mov [ebx].Teb,ecx
	mov [ebx].Tid,edx
Load:
	lea eax,[ebx].Tls
Exit:
	ret
TlsGet endp