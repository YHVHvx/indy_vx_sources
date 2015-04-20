; Менеджер TLS.
;
; (c) Indy, 2012
;
; o Синхронное изменение списка(RWL).
;
; +
; Удаление описателей для завершённых потоков.
;	
TlsCleaningCycle proc uses ebx esi edi Env:PUENV
Local Free:PTLS_ENTRY, MmInfo:MEMORY_BASIC_INFORMATION
	mov ebx,Env
	mov eax,TLS_MAX_ENTRIES
	test ebx,ebx
	cld
	mov Free,NULL
	.if Zero?
		%GETENVPTR
		mov ebx,eax
	.endif
	assume ebx:PUENV
	lea esi,[ebx].Tls
	assume esi:PTLS_ENTRY
	.repeat
		cmp [esi].Teb,NULL
		mov edi,esi
		.if Zero?
			mov eax,esi
			jmp Exit
		.endif
		invoke EvQueryMemory, Ebx, [Esi].Teb, addr MmInfo
		test eax,eax
		jnz Clear
		cmp MmInfo.State,MEM_COMMIT
		jne Clear
		cmp MmInfo.Protect,PAGE_READWRITE
		mov eax,[esi].Teb
		jne Clear
		cmp MmInfo._Type,MEM_PRIVATE
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
Exit:
	ret
TlsCleaningCycle endp

; +
; Поиск TLS в массиве и аллокация.
;
TlsAdd proc uses ebx esi edi ecx edx Env:PUENV
	mov ebx,Env
	mov edx,fs:[TEB.Cid.UniqueThread]
	.if !Ebx
		%GETENVPTR
		mov ebx,eax
	.endif
	assume ebx:PUENV
	%WLOCK [ebx].TlsLock
	mov ecx,fs:[TEB.Tib.Self]
	lea esi,[ebx].Tls
	assume esi:PTLS_ENTRY
	mov eax,TLS_MAX_ENTRIES
	.repeat
	   cmp [esi].Teb,NULL
	   je Alloc
	   cmp [esi].Teb,ecx
	   je IsTid
   Scan:
	   add esi,sizeof(TLS_ENTRY)
	   dec eax
	.until Zero?
	; Лимит описателей исчерпан. Выполняем цикл очистки.
	invoke TlsCleaningCycle, Ebx	; Вернёт свободный блок.
	jmp Exit
IsTid:
	cmp [esi].Tid,edx
	jne Scan
	jmp Load
; Вход не найден, создаём его.
Alloc:
	mov [esi].Teb,ecx
	mov [esi].Tid,edx
Load:
	lea eax,[ebx].Tls
Exit:
	%WUNLOCK [ebx].TlsLock
	test eax,eax
	ret
TlsAdd endp

; +
; Поиск TLS в массиве.
;
TlsGet proc uses ebx esi ecx edx Env:PUENV
	mov ebx,Env
	mov edx,fs:[TEB.Cid.UniqueThread]
	.if !Ebx
		%GETENVPTR
		mov ebx,eax
	.endif
	assume ebx:PUENV
	%RLOCK [ebx].TlsLock
	mov ecx,fs:[TEB.Tib.Self]
	lea esi,[ebx].Tls
	assume esi:PTLS_ENTRY
	mov eax,TLS_MAX_ENTRIES
	.repeat
	   cmp [esi].Teb,NULL
	   je Error
	   cmp [esi].Teb,ecx
	   je IsTid
   Scan:
	   add esi,sizeof(TLS_ENTRY)
	   dec eax
	.until Zero?
Error:
	xor eax,eax
Exit:
	%RUNLOCK [ebx].TlsLock
	test eax,eax
	ret
IsTid:
	cmp [esi].Tid,edx
	jne Scan
Load:
	lea eax,[ebx].Tls
	jmp Exit
TlsGet endp