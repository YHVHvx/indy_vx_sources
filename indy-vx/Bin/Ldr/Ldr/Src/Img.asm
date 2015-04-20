GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm

SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	assume fs:nothing
	push dword ptr fs:[TEB.Tib.ExceptionList]
	mov dword ptr fs:[TEB.Tib.ExceptionList],esp
	jmp ecx
SEH_Prolog endp

; o Не восстанавливаются Ebx, Esi и Edi.
;
SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[TEB.Tib.ExceptionList]
	lea esp,[esp + 3*4]
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

_$_GetCallbackReference::
	pop eax
	ret

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
LdrImageQueryEntryFromCrc32 proc uses ebx esi edi ImageBase:PVOID, Crc32OrFunctionName:DWORD, pRtlComputeCrc32:PVOID, PartialCrc:ULONG, Function:PVOID
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
	.if pRtlComputeCrc32 != NULL
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
	push PartialCrc
	Call pRtlComputeCrc32
	cmp Crc32OrFunctionName,eax
	.else
	invoke CompareAsciizString, Crc32OrFunctionName, Eax
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
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
ErrImage:
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	jmp Exit
ErrTable:
	mov eax,STATUS_BAD_FUNCTION_TABLE
	jmp Exit
LdrImageQueryEntryFromCrc32 endp

; +
; Находит список функций по их хэшам.
;
LdrEncodeEntriesList proc uses ebx esi edi ImageBase:PVOID, PartialCrc:ULONG, EntriesList:PVOID
Local pRtlComputeCrc32:PVOID
Local $RtlComputeCrc32[16]:CHAR
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	lea ecx,pRtlComputeCrc32
	xor eax,eax
	push ecx
	lea edx,$RtlComputeCrc32
	push eax
	push eax
	push edx
	push eax
	sub eax,0BC938BAEH
	mov dword ptr [$RtlComputeCrc32],eax
	add eax,03203F91DH
	mov dword ptr [$RtlComputeCrc32 + 4],eax
	xor eax,0733081BH
	mov dword ptr [$RtlComputeCrc32 + 2*4],eax
	xor eax,72715617H
	mov dword ptr [$RtlComputeCrc32 + 3*4],eax
	Call LdrImageQueryEntryFromCrc32
	test eax,eax
	mov esi,EntriesList
	jnz Exit
	mov edi,esi
	lodsd
@@:
	invoke LdrImageQueryEntryFromCrc32, ImageBase, Eax, pRtlComputeCrc32, PartialCrc, Edi
	test eax,eax
	jnz Exit
	lodsd
	add edi,4
	test eax,eax
	jnz @b
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
LdrEncodeEntriesList endp

; +
; Конвертирует образ файла в образ файловой секции, выравнивая размер файловых секций в памяти.
;
LdrConvertFileToImage proc uses ebx esi edi Environment:PENVIRONMENT, ImageBase:PVOID, MapAddress:PVOID
Local SystemInformation:SYSTEM_BASIC_INFORMATION
Local ImageHeader:PIMAGE_NT_HEADERS
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov edi,MapAddress
	mov esi,ImageBase
	lea eax,SystemInformation
	push NULL
	mov ecx,Environment
	push sizeof(SYSTEM_BASIC_INFORMATION)
	push eax
	push SystemBasicInformation
	Call ENVIRONMENT.Fn.pZwQuerySystemInformation[ecx]
	test eax,eax
	jnz Exit
	invoke LdrImageNtHeader, ImageBase, addr ImageHeader
	test eax,eax
	mov ebx,ImageHeader
	jnz Exit
	assume ebx:PIMAGE_NT_HEADERS
	mov edx,[ebx].OptionalHeader.SectionAlignment
	cmp SystemInformation.PhysicalPageSize,edx
	mov eax,STATUS_MAPPED_ALIGNMENT
	jnz Exit
	mov ecx,[ebx].OptionalHeader.SizeOfHeaders	; Align
	cld
	rep movsb
	lea edi,[ebx + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_SECTION_HEADER)]
	assume edi:PIMAGE_SECTION_HEADER
	movzx ebx,IMAGE_NT_HEADERS.FileHeader.NumberOfSections[ebx]
@@:
	add edi,sizeof(IMAGE_SECTION_HEADER)
	mov ecx,[edi].VirtualSize
	mov eax,edi
	mov esi,[edi].PointerToRawData
	mov edi,[edi].VirtualAddress
	add esi,ImageBase
	add edi,MapAddress
	rep movsb
	mov edi,eax
	dec ebx
	jnz @b
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret		
LdrConvertFileToImage endp

; +
; Создаёт секцию из образа модуля.
;
LdrCreateImageSection proc uses ebx esi edi Environment:PENVIRONMENT, SectionHandle:PHANDLE, DirectoryHandle:HANDLE, ImageBase:PVOID, SectionName:PSTR
Local ObjAttr:OBJECT_ATTRIBUTES
Local LocalSectionHandle:HANDLE
Local LocalSectionSize:LARGE_INTEGER, ViewSize:ULONG
Local MapAddress:PVOID, SectionOffset:LARGE_INTEGER
Local ImageHeader:PIMAGE_NT_HEADERS
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov ebx,Environment
	assume ebx:PENVIRONMENT
	invoke LdrImageNtHeader, ImageBase, addr ImageHeader
	test eax,eax
	mov edx,ImageHeader
	jnz Exit
	assume edx:PIMAGE_NT_HEADERS
	mov edx,[edx].OptionalHeader.SizeOfImage
	mov ecx,DirectoryHandle
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	mov dword ptr [LocalSectionSize+4],eax
	mov dword ptr [LocalSectionSize],edx
	mov ViewSize,edx
	cmp SectionName,eax
	mov ObjAttr.hRootDirectory,ecx
	mov ObjAttr.uAttributes,eax
	mov ObjAttr.pSecurityDescriptor,eax
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.pObjectName,eax
	lea ecx,LocalSectionSize
	lea edx,ObjAttr
	push eax
	push SEC_COMMIT
	push PAGE_EXECUTE_READWRITE
	lea eax,LocalSectionHandle
	push ecx
	push edx
	push SECTION_ALL_ACCESS
	push eax
	Call [ebx].Fn.pZwCreateSection
	test eax,eax
	jnz Exit
	mov MapAddress,eax
	mov dword ptr [SectionOffset],eax
	mov dword ptr [SectionOffset + 4],eax
	push PAGE_READWRITE
	push NULL
	push ViewShare
	lea eax,ViewSize
	push eax
	lea eax,SectionOffset
	push eax
	push 0
	push 0
	lea eax,MapAddress
	push eax
	push NtCurrentProcess
	push LocalSectionHandle
	Call [ebx].Fn.pZwMapViewOfSection	
	test eax,eax
	jnz Close
	invoke LdrConvertFileToImage, Ebx, ImageBase, MapAddress
	push eax
	push MapAddress
	push NtCurrentProcess
	Call [ebx].Fn.pZwUnmapViewOfSection
	pop eax
	mov edx,LocalSectionHandle
	test eax,eax
	mov ecx,SectionHandle
	jnz Close
	mov dword ptr [ecx],edx
	jmp Exit
Close:
	push eax
	push LocalSectionHandle
	Call [ebx].Fn.pZwClose
	pop eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
LdrCreateImageSection endp

SIZEOF_KNOWNDLLS_DIRECTORY_NAME	equ 10	; "\KnownDlls"

; +
;
LdrIsKnownDllDirectory proc uses ebx esi edi Environment:PENVIRONMENT, DirectoryHandle:HANDLE
Local ObjectNameBuffer[MAX_PATH*4]:WCHAR
Local ObjectName:UNICODE_STRING
Local ReturnLength:ULONG
	lea esi,ObjectNameBuffer
	lea eax,ReturnLength
	lea ecx,ObjectName
	mov ebx,Environment
	assume ebx:PENVIRONMENT
	mov ObjectName.MaximumLength,MAX_PATH*2
	mov ObjectName._Length,MAX_PATH*2
	mov ObjectName.Buffer,esi
	push eax
	push MAX_PATH*4 + sizeof(UNICODE_STRING)
	push ecx
	push ObjectNameInformation
	push DirectoryHandle
	Call [ebx].Fn.pZwQueryObject
	test eax,eax
	jnz Exit
	cmp ReturnLength,2*SIZEOF_KNOWNDLLS_DIRECTORY_NAME + sizeof(UNICODE_STRING) + 2
	mov eax,STATUS_OBJECT_NAME_NOT_FOUND
	jne Exit
	cmp ObjectName._Length,2*SIZEOF_KNOWNDLLS_DIRECTORY_NAME
	jne Exit
	mov edi,[ebx].Directory.Buffer
	mov ecx,SIZEOF_KNOWNDLLS_DIRECTORY_NAME
	repe cmpsw	; or RtlCompareUnicodeString().
	jne Exit
	xor eax,eax
Exit:
	ret
LdrIsKnownDllDirectory endp