; o IDPE 4.1
;
; o MI, UM
;
; (с) Indy, 2012
;
; +
; 
; G - гранулярность.
;
CreateDescriptor proc Base:PVOID, Limit:ULONG, G:BOOLEAN
	mov eax,Base
	mov edx,Limit
	mov ecx,eax
	and edx,0F0000H	; Lim. 19:16
	shr eax,16		; Base 23:16
	and ecx,0FF000000H	; Base 31:24
	and eax,0FFH
	;                           111S001A              GDXU
	lea edx,[eax + edx + 100H * 11110010B + 100000H * 0100B]	; Type 001B - DATA, R/W.
	mov eax,Limit
	or edx,ecx
	cmp G,FALSE
	mov ecx,Base
	.if !Zero?	; 4K
		bts edx,23	; G
	.endif
	and eax,0FFFFH
	shl ecx,16
	lea ecx,[ecx + eax]
; Edx:Ecx
	ret
CreateDescriptor endp

; +
;
IdpQueryDescriptor proc uses ebx LdtEntry:PDESCRIPTOR_TABLE_ENTRY
	%GETENVPTR
	jz Error
	mov ebx,eax
	assume ebx:PUENV
	%PLOCK [ebx].LpZwQueryInformationThread, Init, Error
Gate:
	push NULL
	push sizeof(DESCRIPTOR_TABLE_ENTRY)
	push LdtEntry
	push ThreadDescriptorTableEntry
	push NtCurrentThread
	%APICALL Eax, 5
Exit:
	ret
Init:
	push EOL
	push 23A0F19FH	; HASH("ZwQueryInformationThread")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG "IdpQuerySelector.LdrEncodeEntriesList(ZwQueryInformationThread): 0x%X", Eax
	test eax,eax
	pop eax
	pop ecx
	.if Zero?
		%PUNLOCK [ebx].LpZwQueryInformationThread, eax
		jmp Gate
	.endif
	%PUNLOCK [ebx].LpZwQueryInformationThread, LOCK_FAIL
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
IdpQueryDescriptor endp

; +
;
IdpIsFreeDescriptor proc Selector:DWORD
Local LdtEntry:DESCRIPTOR_TABLE_ENTRY
	mov eax,Selector
	lea ecx,LdtEntry
	mov LdtEntry.Selector,eax
	invoke IdpQueryDescriptor, Ecx
	.if !Eax
		cmp LdtEntry.Descriptor,eax	; Base:Limit
		je Free
;		bt LdtEntry.Descriptor[4],15	; P
;		jnc Free
		mov eax,STATUS_WAS_LOCKED
	.elseif (Eax == STATUS_NO_LDT) || (Eax == STATUS_ACCESS_VIOLATION)
Free:
		xor eax,eax
	.endif
Exit:
	ret
IdpIsFreeDescriptor endp

comment '
	Ip = [Ref]
	Align = X86_PAGE_SIZE	; 2^12
; SegList{} - массив описателей сегментов.
; SegCount - число описателей в массиве.
Scan:
	Base = Ip & (X86_PAGE_SIZE - 1)	; Выделяем выравнивание.
	if !Base
		Base + Align
	fi
	For J = 1 To SegCount
	; Ищем свободное окно.
		if ((Base >= SegList{J}.Base) & (Base < SegList{J}.Limit)) | ((Base <= SegList{J}.Base) & (SegList{J}.Base < Limit))
		; Регионы пересекаются.
			Base + Align
			Limit = Base + SegSize
			if Limit >= 10000H
				Align shr 1
				Base = Ip & (X86_PAGE_SIZE - 1)
				if !Align
					#FAIL
				fi
				> Scan
			fi
		fi
	Next
	SegCount + 1
	J + 1
	SegList{J}.Base = Base
	SegList{J}.Limit = Limit
	SegList{J}.Ip = Ip
	SegList{J}.Ref = Ref
	'
; +
; 
IdpAddReference proc uses ebx esi edi Reference:PVOID, SpaceSize:ULONG
Local Map:ULONG, LockValue:ULONG
	%GETENVPTR
	mov ebx,eax
	mov edi,Reference
	.if Zero?
		mov eax,STATUS_UNSUCCESSFUL
		jmp Quit
	.endif
	assume ebx:PUENV
	%WLOCK [ebx].IdpLock
	%DBG "IdpAddReference.LOCK"
	mov edi,dword ptr [edi]
	mov Map,PAGE_SIZE	; Align
	cmp edi,10000H
	jna Error
	cmp [ebx].Handle,NULL
	jne Scan
	push EOL
	push 0C5713067H	; HASH("KiUserExceptionDispatcher")
	push 0815C378DH	; HASH("RtlAddVectoredExceptionHandler")
	push 0395537A4H	; HASH("RtlRemoveVectoredExceptionHandler")
	push 0019FD26EH	; HASH("DbgBreakPoint")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG "IdpAddReference.LdrEncodeEntriesList(): 0x%X", Eax
	test eax,eax
	pop [ebx].pDbgBreakPoint
	pop [ebx].pRtlRemoveVectoredExceptionHandler
	pop [ebx].pRtlAddVectoredExceptionHandler
	pop [ebx].pKiUserExceptionDispatcher
	pop ecx	; EOL
	jnz Exit
	%GET_GRAPH_ENTRY xVEH
	push eax
	push TRUE
	Call [ebx].pRtlAddVectoredExceptionHandler
	test eax,eax
	mov [ebx].Handle,eax
	jz Error
	mov [ebx].BugEvent,XCPT_BREAK
	Call [Ebx].pDbgBreakPoint	
Scan:
	mov edx,edi
	and edx,(PAGE_SIZE - 1)	; Base
	.if Zero?
		add edx,Map
	.endif
	mov ecx,[ebx].SegCount
	mov eax,edx
	cmp ecx,IDP_MAX_ENTRIES
	lea esi,[ebx].SegList
	jnb Error
	add eax,SpaceSize	; Limit
	assume esi:PSEGMENT_ENTRY
	test ecx,ecx
	.if Zero?
		mov [ebx].LastSelector,RPL_MASK or SEL_TABLE_MASK
		jmp Found
	.endif
Next:
	cmp [esi].Base,edx
	jbe @f
	cmp [esi].Base,eax
	jnb Free
Cross:
	add edx,Map
	mov eax,edx
	add eax,SpaceSize	; Limit
	.if Eax >= 10000H
		shr Map,1
		jnz Scan
		mov eax,STATUS_INSUFFICIENT_RESOURCES
		jmp Exit
	@@:
		cmp [esi].Limit,edx
		ja Cross
	.endif
Free:
	add esi,sizeof(SEGMENT_ENTRY)
	dec ecx
	jnz Next
Found:
	mov ecx,Reference
	push edx
	mov [esi].Address,edi
	inc [ebx].SegCount
	mov [esi].Base,edx
	add SpaceSize,edx
	mov [esi].Limit,eax
	dec SpaceSize
	not edx
	mov [esi].Reference,ecx
	lea edx,[edx + edi + 1]
	mov [esi].SegBase,edx
	invoke CreateDescriptor, Edx, SpaceSize, 0	; Edx:Ecx
	push NULL
	mov edi,[ebx].LastSelector
	push NULL
	push NULL
	push edx
	push ecx
	push eax
	.repeat
		add edi,(1 shl 3)
		cmp edi,2000H shl 3
		jnb ErrSel
		invoke IdpIsFreeDescriptor, Edi
		test eax,eax
		jz @f
	.until Eax != STATUS_WAS_LOCKED
	add esp,7*4
	jmp Exit	
@@:
	mov dword ptr [esp],edi
	%PLOCK [Ebx].LpZwSetLdtEntries, InitLdt, ErrSel
Ldt:
	%APICALL Eax, 6
	%DBG "IdpAddReference.ZwSetLdtEntries(SEL: 0x%X): 0x%X", Eax, Edi
	test eax,eax
	mov ecx,Reference
	.if Zero?
		mov [ebx].LastSelector,edi
		mov [esi].Selector,edi
		pop dword ptr [ecx]
	.else
		dec [ebx].SegCount
	.endif
Exit:
	%WUNLOCK [ebx].IdpLock
	%DBG "IdpAddReference.UNLOCK", Eax
Quit:
	%DBG "IdpAddReference ): 0x%X", Eax
	ret
InitLdt:
	push EOL
	push 0AB2E5566H	; HASH("ZwSetLdtEntries")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG "IdpAddReference.LdrEncodeEntriesList(ZwSetLdtEntries): 0x%X", Eax
	test eax,eax
	pop eax
	pop ecx
	.if Zero?
		%PUNLOCK [ebx].LpZwSetLdtEntries,eax
		jmp Ldt
	.endif
	%PUNLOCK [ebx].LpZwSetLdtEntries, LOCK_FAIL
ErrSel:
	add esp,7*4
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
IdpAddReference endp

; +
;
IdpGetReference proc uses ebx esi edi Reference:PVOID, SegEntry:PSEGMENT_ENTRY
	%GETENVPTR
	mov ebx,eax
	mov esi,STATUS_UNSUCCESSFUL
	jz Exit
	assume ebx:PUENV
	mov esi,STATUS_NOT_FOUND
	%RLOCK [ebx].IdpLock
	.if [Ebx].Handle
		lea edi,[ebx].SegList
		mov ecx,[ebx].SegCount
		mov edx,Reference
		test ecx,ecx
		jz Unlock
		assume edi:PSEGMENT_ENTRY
		.repeat
			.if [Edi].Reference == Edx
				mov edx,SegEntry
				xor esi,esi
				mov dword ptr [edx],edi
				jmp Unlock
			.endif
			add edi,sizeof(SEGMENT_ENTRY)
			dec ecx
		.until Zero?
	.endif
Unlock:
	%RUNLOCK [ebx].IdpLock
Exit:
	mov eax,esi
	ret
IdpGetReference endp

; +
;
IdpAddVEH proc First:BOOLEAN, Handler:PVOID
	%GETENVPTR
	assume eax:PUENV
	push eax
	%RLOCK [eax].IdpLock
	.if ![Eax].Handle
		push EOL
		push 0815C378DH	; HASH("RtlAddVectoredExceptionHandler")
		invoke LdrEncodeEntriesList, NULL, Esp
		pop ecx
		test eax,eax
		pop edx
		.if Zero?
			push Handler
			push First
			Call Ecx
		.else
			xor eax,eax
		.endif
	.else
		push Handler
		push First
		Call [Eax].pRtlAddVectoredExceptionHandler
	.endif
	pop ecx
	%RUNLOCK UENV.IdpLock[ecx]
	ret
IdpAddVEH endp

; +
;
IdpRemoveVEH proc Handle:HANDLE
	%GETENVPTR
	assume eax:PUENV
	push eax
	%RLOCK [eax].IdpLock
	.if ![Eax].Handle
		push EOL
		push 0395537A4H	; HASH("RtlRemoveVectoredExceptionHandler")
		invoke LdrEncodeEntriesList, NULL, Esp
		pop ecx
		test eax,eax
		pop edx
		.if Zero?
			push Handle
			Call Ecx
		.else
			xor eax,eax
		.endif
	.else
		push Handle
		Call [Eax].pRtlRemoveVectoredExceptionHandler
	.endif
	pop ecx
	%RUNLOCK UENV.IdpLock[ecx]
	ret
IdpRemoveVEH endp