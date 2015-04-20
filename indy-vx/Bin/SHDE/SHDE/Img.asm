PUBLIC LdrImageNtHeader
PUBLIC LdrImageQueryEntryFromHash
PUBLIC LdrQueryServicesList
PUBLIC LdrEncodeEntriesList
PUBLIC LdrMapViewOfImage

; +
;Проверяет валидность заголовка модуля.
;
LdrImageNtHeader proc ImageBase:PVOID, ImageHeader:PIMAGE_NT_HEADERS
	mov edx,ImageBase
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	assume edx:PIMAGE_DOS_HEADER
	cmp [edx].e_magic,'ZM'
	jne @f
	add edx,[edx].e_lfanew
	assume edx:PIMAGE_NT_HEADERS
	cmp [edx].Signature,'EP'
	jne @f
	cmp [edx].FileHeader.SizeOfOptionalHeader,sizeof(IMAGE_OPTIONAL_HEADER32)
	jne @f
	cmp [edx].FileHeader.Machine,IMAGE_FILE_MACHINE_I386	
	jne @f
	test [edx].FileHeader.Characteristics,IMAGE_FILE_32BIT_MACHINE
	je @f
	mov ecx,ImageHeader
	xor eax,eax
	mov dword ptr [ecx],edx
@@:
	ret
LdrImageNtHeader endp

xLdrCalculateHash:
	%GET_CURRENT_GRAPH_ENTRY
LdrCalculateHash proc uses ebx esi PartialHash:ULONG, StrName:PSTR, NameLength:ULONG
	xor eax,eax
	mov ecx,NameLength
	mov esi,StrName
	mov ebx,PartialHash
	cld
@@:
	lodsb
	xor ebx,eax
	xor ebx,ecx
	rol ebx,cl
	loop @b
	mov eax,ebx
	ret
LdrCalculateHash endp

; +
;
CompareAsciizString proc uses ebx String1:PSTR, String2:PSTR
    mov ecx,String1
    mov edx,String2
    xor ebx,ebx
@@:
    mov al,byte ptr [ecx + ebx]
    cmp byte ptr [edx + ebx],al
    jne @f
    inc ebx
    test al,al
    jne @b
@@:
    ret
CompareAsciizString endp

; +
; Поиск функции по имени/хэшу в экспорте.
;
LdrImageQueryEntryFromHash proc uses ebx esi edi ImageBase:PVOID, HashOrFunctionName:DWORD, pComputeHashRoutine:PVOID, PartialHash:ULONG, Function:PVOID
Local ExportDirectory:PIMAGE_EXPORT_DIRECTORY
Local ImageHeader:PIMAGE_NT_HEADERS
Local NumberOfNames:ULONG
	%SEHPROLOG
	mov ebx,ImageBase
	.if !Ebx
		invoke LdrGetNtBase
		mov ebx,eax
	.endif
	invoke LdrImageNtHeader, Ebx, addr ImageHeader
	test eax,eax
	mov edx,ImageHeader
	jnz Exit
	assume edx:PIMAGE_NT_HEADERS
	mov eax,[edx].OptionalHeader.DataDirectory.VirtualAddress
	test eax,eax
	jz ErrImage
	add eax,ebx
	assume eax:PIMAGE_EXPORT_DIRECTORY	
	mov ExportDirectory,eax
	mov esi,[eax].AddressOfNames
	test esi,esi
	jz ErrTable
	mov eax,[eax].NumberOfNames
	test eax,eax
	jz ErrTable
	mov NumberOfNames,eax
	add esi,ebx
	xor edi,edi
Next:
	cld
	mov eax,dword ptr [esi]
	add eax,ebx
	.if pComputeHashRoutine != NULL
		push edi
		mov edi,eax
		mov ecx,MAX_PATH
		mov edx,edi
		xor eax,eax
		repne scasb
		not ecx
		pop edi
		add ecx,MAX_PATH
		push ecx
		push edx
		push PartialHash
		Call pComputeHashRoutine
		cmp HashOrFunctionName,eax
	.else
		invoke CompareAsciizString, HashOrFunctionName, Eax
	.endif
	jnz @f
	mov ecx,ExportDirectory
	assume ecx:PIMAGE_EXPORT_DIRECTORY
	mov eax,[ecx].AddressOfNameOrdinals
	add eax,ebx
	movzx edi,word ptr [2*edi + eax]
	.if Edi
		.if Edi >= [Ecx]._Base
			sub edi,[ecx]._Base
		.endif
		inc edi
	.endif
	mov esi,[ecx].AddressOfFunctions
	add esi,ebx
	mov ecx,dword ptr [4*edi + esi]
	test ecx,ecx
	mov edx,Function
	jz ErrImage
	add ecx,ebx
	xor eax,eax
	mov dword ptr [edx],ecx
	jmp Exit
@@:
	add esi,4
	inc edi
	dec NumberOfNames
	jnz Next
	mov eax,STATUS_PROCEDURE_NOT_FOUND
	%SEHEPILOG
	ret
ErrImage:
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	jmp Exit
ErrTable:
	mov eax,STATUS_BAD_FUNCTION_TABLE
	jmp Exit
LdrImageQueryEntryFromHash endp

SYSTUB struct
OpMovEax		BYTE ?	; OP_LOAD_ID
ServiceId		ULONG ?
OpMovEdx		BYTE ?	; OP_LOAD_GATE
Gate			PVOID ?
OpCall		WORD ?
OpRet		BYTE ?
Args			WORD ?
SYSTUB ends
PSYSTUB typedef ptr SYSTUB

SYSTUB8 struct
OpMovEax		BYTE ?	; OP_LOAD_ID
ServiceId		ULONG ?
OpCall		WORD ?
Gate			PVOID ?
OpRet		BYTE ?
Args			WORD ?
SYSTUB8 ends
PSYSTUB8 typedef ptr SYSTUB8

OP_RET		equ 0C3H
OP_RETN		equ 0C2H
OP_LOAD_ID	equ 0B8H
OP_LOAD_GATE	equ 0BAH
OP_CALL_GATE	equ 0E8H

; +
; Получение списка сервисов.
;
; Формат описателя: [Name][0].4[Addr].2[Id].2[Args].4[Hash]
;
LdrQueryServicesList proc uses ebx esi edi NtBase:PVOID, NtView:PVOID, pList:PPVOID
Local ExportDirectory:PIMAGE_EXPORT_DIRECTORY
Local ImageHeader:PIMAGE_NT_HEADERS
Local NumberOfNames:ULONG
Local List:PVOID
	%SEHPROLOG
	mov ebx,NtBase
	.if !Ebx
		invoke LdrGetNtBase
		mov ebx,eax
	.endif
	invoke LdrImageNtHeader, Ebx, addr ImageHeader
	test eax,eax
	mov edx,ImageHeader
	jnz Exit
	mov eax,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress[edx]
	mov ecx,pList
	test eax,eax
	mov ecx,dword ptr [ecx]
	jz ErrImage	
	add eax,ebx
	assume eax:PIMAGE_EXPORT_DIRECTORY
	mov ExportDirectory,eax
	mov esi,[eax].AddressOfNames
	mov List,ecx
	test esi,esi
	mov eax,[eax].NumberOfNames
	jz ErrTable
	test eax,eax
	jz ErrTable
	add esi,ebx
	mov NumberOfNames,eax
	xor edi,edi
Next:	
	cld
	mov eax,dword ptr [esi]
	push edi
	add eax,ebx
	push esi
	mov edi,eax
	mov ecx,MAX_PATH
	mov esi,edi
	xor eax,eax
	repne scasb
	not ecx
	add ecx,MAX_PATH
	
	cmp ecx,3
	jb Skip
	cmp word ptr [esi],"wZ"	; Zw*
	mov edx,ExportDirectory
	jne Skip
	
	assume edx:PIMAGE_EXPORT_DIRECTORY
	mov edi,dword ptr [esp + 4]
	mov eax,[edx].AddressOfNameOrdinals
	add eax,ebx
	movzx eax,word ptr [2*edi + eax]
	.if Eax
		.if Eax >= [Edx]._Base
			sub eax,[edx]._Base
  		.endif
		inc eax
	.endif
	mov edx,[edx].AddressOfFunctions
	add edx,ebx
	mov eax,dword ptr [4*eax + edx]
	test eax,eax
	jz ErrImage
	add eax,ebx

	assume eax:PSYSTUB
	cmp [eax].OpMovEax,OP_LOAD_ID
	jne Skip
	xor edx,edx
	cmp [eax].OpMovEdx,OP_LOAD_GATE
	jne IsStub8
	cmp [eax].OpRet,OP_RET
	je SrvId
	cmp [eax].OpRet,OP_RETN
	jne Skip
SrvArg:
	movzx edx,[eax].Args
SrvId:
	cmp [eax].ServiceId,300H
	mov edi,List
	jnb Skip
	push ecx
	push esi
	inc ecx
	rep movsb
	sub eax,ebx
	add eax,NtView
	stosd
	mov eax,[eax].ServiceId
	mov word ptr [edi + 2],dx
	mov word ptr [edi],ax
	push 0
	add edi,4
	Call LdrCalculateHash
	stosd
	mov List,edi
Skip:
	pop esi
	pop edi
	add esi,4
	inc edi
	dec NumberOfNames
	jnz Next
	mov ecx,pList
	mov edx,List
	xor eax,eax
	mov dword ptr [ecx],edx
	%SEHEPILOG
	ret
ErrImage:
	pop esi
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	pop edi
	jmp Exit
ErrTable:
	mov eax,STATUS_BAD_FUNCTION_TABLE
	jmp Exit
IsStub8:
	assume eax:PSYSTUB8
	cmp [eax].OpCall,OP_CALL_GATE
	jne Skip
	cmp [eax].OpRet,OP_RET
	je SrvId
	cmp [eax].OpRet,OP_RETN
	je SrvArg
	jmp Skip
LdrQueryServicesList endp

; +
; Находит список функций по их хэшам.
;
LdrEncodeEntriesList proc uses ebx esi edi ImageBase:PVOID, PartialHash:ULONG, EntriesList:PVOID
	%SEHPROLOG
	%GET_GRAPH_ENTRY xLdrCalculateHash
	mov esi,EntriesList
	mov ebx,eax
	mov edi,esi
	lodsd
	.repeat
		invoke LdrImageQueryEntryFromHash, ImageBase, Eax, Ebx, PartialHash, Edi
		test eax,eax
		jnz Exit
		lodsd
		add edi,4
	.until !Eax
	%SEHEPILOG
	ret
LdrEncodeEntriesList endp

; +
; Проецируем копию образа.
;
LdrMapViewOfImage proc uses ebx Apis:PAPIS, ImageBase:PVOID, ViewBase:PPVOID
Local FileU[MAX_PATH*2 + sizeof(UNICODE_STRING)]:CHAR
Local ObjAttr:OBJECT_ATTRIBUTES
Local File:HANDLE, Section:HANDLE
Local IoStatus:IO_STATUS_BLOCK
Local ViewSize:ULONG
	mov ecx,ImageBase
	lea eax,FileU
	mov ebx,Apis
	assume ebx:PAPIS
	.if !Ecx
		mov ecx,fs:[TEB.Peb]
		mov ecx,PEB.LoaderLock[ecx]
	.endif
	push NULL
	push sizeof UNICODE_STRING + 2*sizeof MAX_PATH
	push eax
	push MemoryMappedFilenameInformation
	push ecx
	push NtCurrentProcess
	Call [ebx].pZwQueryVirtualMemory
	test eax,eax
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	mov ObjAttr.uAttributes,OBJ_CASE_INSENSITIVE
	lea ecx,FileU
	jnz Exit	; STATUS_INVALID_ADDRESS/STATUS_INVALID_IMAGE_NOT_MZ/STATUS_FILE_INVALID etc.
	mov ObjAttr.hRootDirectory,eax
	mov ObjAttr.pObjectName,ecx
	lea edx,IoStatus
	push FILE_NON_DIRECTORY_FILE or FILE_SYNCHRONOUS_IO_NONALERT
	mov ObjAttr.pSecurityDescriptor,eax
	lea ecx,ObjAttr
	push FILE_SHARE_READ or FILE_SHARE_DELETE
	mov ObjAttr.pSecurityQualityOfService,eax
	push edx
	lea eax,File
	push ecx
	push SYNCHRONIZE or FILE_EXECUTE or FILE_READ_ACCESS
	push eax
	Call [ebx].pZwOpenFile 
	test eax,eax
	lea ecx,Section
	jl Exit
	push File
	push SEC_IMAGE
	push PAGE_EXECUTE_READ
	push NULL
	push NULL
	push SECTION_MAP_READ or SECTION_MAP_EXECUTE or SECTION_MAP_WRITE or SECTION_QUERY
	push ecx
	Call [ebx].pZwCreateSection
	test eax,eax
	lea ecx,ViewSize
	.if Zero?
		mov ViewSize,eax
		push PAGE_EXECUTE_READ
		push eax
		push ViewShare
		push ecx
		push eax
		push eax
		push eax
		push ViewBase
		push NtCurrentProcess
		push Section
		Call [ebx].pZwMapViewOfSection
		push eax	; STATUS_SUCCESS/STATUS_IMAGE_NOT_AT_BASE
		push Section
		Call [ebx].pZwClose
		pop eax
	.endif
	push eax
	push File
	Call [ebx].pZwClose
	pop eax
Exit:
	ret
LdrMapViewOfImage endp

; +
; Получение базовых NTAPI.
;
LdrInitializeApis proc uses edi NtBase:PVOID, Apis:PAPIS
	mov edi,Apis
	cld
%PREGENHASH 0545B554FH, \
	05CC20C59H, \
	008C1BF69H, \
	03BF9E770H, \
	0C5713067H, \
	0815C378DH, \
	0395537A4H, \
	024741E13H, \
	039542311H, \
	0DA44E712H, \
	0EA7DF819H, \
	07085AB5AH, \
	034DF9700H, \
	034357463H, \
	0DE02B845H
	xor eax,eax
	stosd	; EOL
	invoke LdrEncodeEntriesList, NtBase, Eax, Apis
	ret
LdrInitializeApis endp