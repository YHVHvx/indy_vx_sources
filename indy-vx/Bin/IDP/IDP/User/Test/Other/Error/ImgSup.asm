ENTER_SEH macro
Local Delta1, Delta2
	push ebp
	Call Delta1
Delta1:
	add dword ptr [esp],(ExceptionExit_ - Delta1)
	Call Delta2
Delta2:
	add dword ptr [esp],(MainExceptionHandler - Delta2)
	assume fs:nothing
	push dword ptr fs:[TEB.Tib.ExceptionList]
	mov dword ptr fs:[TEB.Tib.ExceptionList],esp
endm

LEAVE_SEH macro
;	clc
ExceptionExit_:
	pop dword ptr fs:[TEB.Tib.ExceptionList]
	lea esp,[esp + 4*3]
endm

MainExceptionHandler proc C
	mov esp,dword ptr [esp + 8]	; (esp) -> ExceptionList
	mov eax,STATUS_UNSUCCESSFUL
	mov ebp,dword ptr [esp + 4*3]
;	stc
	jmp dword ptr [esp + 4*2]
MainExceptionHandler endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
;Проверяет валидность заголовка модуля.
;
LdrImageNtHeader proc ImageBase:PVOID, ImageHeader:PIMAGE_NT_HEADERS
	ENTER_SEH
	mov edx,ImageBase
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	assume edx:PIMAGE_DOS_HEADER
	cmp [edx].e_magic,'ZM'
	jne exit_
	add edx,[edx].e_lfanew
	assume edx:PIMAGE_NT_HEADERS
	cmp [edx].Signature,'EP'
	jne exit_
	cmp [edx].FileHeader.SizeOfOptionalHeader, SizeOf IMAGE_OPTIONAL_HEADER32
	jne exit_
	cmp [edx].FileHeader.Machine,IMAGE_FILE_MACHINE_I386	
	jne exit_
	test [edx].FileHeader.Characteristics,IMAGE_FILE_32BIT_MACHINE
	je exit_
	mov ecx,ImageHeader
	xor eax,eax
	mov dword ptr [ecx],edx
	LEAVE_SEH
exit_:
	ret
LdrImageNtHeader endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Поиск функции по имени/хэшу в экспорте.
; 
NtImageQueryEntryFromCrc32 proc uses ebx esi edi ImageBase:PVOID, Crc32OrFunctionName:DWORD, pRtlComputeCrc32:PVOID, PartialCrc:ULONG, Function:PVOID
Local ExportDirectory:PIMAGE_EXPORT_DIRECTORY, ImageHeader:PIMAGE_NT_HEADERS
Local NumberOfNames:ULONG
	ENTER_SEH
	mov ebx,ImageBase
	mov eax,fs:[TEB.Peb]
	test ebx,ebx
	mov eax,PEB.Ldr[eax]
	jnz @f
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov ebx,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
@@:
	invoke LdrImageNtHeader, Ebx, addr ImageHeader
	test eax,eax
	mov edx,ImageHeader
	jnz err_image_
	assume edx:PIMAGE_NT_HEADERS
	mov eax,[edx].OptionalHeader.DataDirectory.VirtualAddress
	test eax,eax
	jz err_image_	
	add eax,ebx
	assume eax:PIMAGE_EXPORT_DIRECTORY	
	mov ExportDirectory,eax
	mov esi,[eax].AddressOfNames	
	test esi,esi
	jz err_table_	
	mov eax,[eax].NumberOfNames
	test eax,eax
	jz err_table_
	mov NumberOfNames,eax
	add esi,ebx
	xor edi,edi
	cld
loop_:	
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
	.if Zero?
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
	jz err_image_
	add ecx,ebx
	xor eax,eax
	mov dword ptr [edx],ecx
	.else
	add esi,4
	inc edi
	dec NumberOfNames
	jnz loop_
	mov eax,STATUS_PROCEDURE_NOT_FOUND
	.endif
exit_:
	LEAVE_SEH
	ret
err_image_:
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	jmp exit_
err_table_:
	mov eax,STATUS_BAD_FUNCTION_TABLE
	jmp exit_
NtImageQueryEntryFromCrc32 endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Находит список функций по их хэшам.
;
EncodeEntriesListFromCrc32 proc uses ebx ImageBase:PVOID, pRtlComputeCrc32:PVOID, PartialCrc:ULONG, Crc32List:PVOID
	ENTER_SEH
	mov ebx,Crc32List
@@:
	push ebx
	push PartialCrc
	push pRtlComputeCrc32
	push dword ptr [ebx]
	push ImageBase
	Call NtImageQueryEntryFromCrc32
	test eax,eax
	lea ebx,[ebx + 4]
	jnz exit_
	cmp dword ptr [ebx],eax
	jne @b
exit_:
	LEAVE_SEH
	ret
EncodeEntriesListFromCrc32 endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~