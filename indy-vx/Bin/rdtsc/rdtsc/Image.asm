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

xLdrCalculateHash:
	%GET_CURRENT_GRAPH_ENTRY
LdrCalculateHash proc uses ebx esi PartialHash:ULONG, StrName:PCHAR, NameLength:ULONG
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
; Поиск функции по имени/хэшу в экспорте.
;
LdrImageQueryEntryFromHash proc uses ebx esi edi ImageBase:PVOID, HashOrFunctionName:DWORD, pComputeHashRoutine:PVOID, PartialHash:ULONG, Function:PVOID
Local ExportDirectory:PIMAGE_EXPORT_DIRECTORY
Local ImageHeader:PIMAGE_NT_HEADERS
Local NumberOfNames:ULONG
	%SEHPROLOG
	mov ebx,ImageBase
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
	cld
Next:	
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
	movzx edi,word ptr [2*edi+eax]
	.if edi
	  .if edi >= [ecx]._Base
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