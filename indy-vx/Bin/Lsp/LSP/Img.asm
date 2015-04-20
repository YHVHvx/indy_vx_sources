%GET_CURRENT_GRAPH_ENTRY macro
	Call GetGraphReference
endm

%GET_GRAPH_ENTRY macro PGET_CURRENT_GRAPH_ENTRY
	Call PGET_CURRENT_GRAPH_ENTRY
endm

%GET_GRAPH_REFERENCE macro
GetGraphReference::
	pop eax
	ret
endm

	%GET_GRAPH_REFERENCE

	assume fs:nothing
SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	jmp ecx
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 2*4]
	pop ebp
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	%GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov ecx,dword ptr [esp + 3*4]	; Ctx.
	mov edx,dword ptr [esp]	; ~ nt!ExecuteHandler2().
	mov ebx,CONTEXT.regEbx[ecx]
	mov esi,CONTEXT.regEsi[ecx]
	mov edi,CONTEXT.regEdi[ecx]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov ecx,EXCEPTION_RECORD.ExceptionAddress[eax]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp
	
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

; +
; Поиск функции по имени/хэшу в экспорте.
;
LdrImageQueryEntryFromHash proc uses ebx esi edi ImageBase:PVOID, HashOrFunctionName:DWORD, pComputeHashRoutine:PVOID, PartialHash:ULONG, Function:PVOID
Local ExportDirectory:PIMAGE_EXPORT_DIRECTORY
Local ImageHeader:PIMAGE_NT_HEADERS
Local NumberOfNames:ULONG
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov eax,fs:[TEB.Peb]
	mov ebx,ImageBase
	mov eax,PEB.Ldr[eax]
	test ebx,ebx
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	.if Zero?
	   mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	   mov ebx,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
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
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
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
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	%GET_GRAPH_ENTRY xLdrCalculateHash
	mov esi,EntriesList
	mov ebx,eax
	mov edi,esi
	lodsd
@@:
	invoke LdrImageQueryEntryFromHash, ImageBase, Eax, Ebx, PartialHash, Edi
	test eax,eax
	jnz Exit
	lodsd
	add edi,4
	test eax,eax
	jnz @b
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
LdrEncodeEntriesList endp

	include Hash.asm