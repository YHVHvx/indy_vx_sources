; \IDP\Public\User\Bin\Graph\Mm\Img.asm
;
GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm

.code
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
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
	jz err_image_
	add ecx,ebx
	xor eax,eax
	mov dword ptr [edx],ecx
	jmp exit_
@@:
	add esi,4
	inc edi
	dec NumberOfNames
	jnz loop_
	mov eax,STATUS_PROCEDURE_NOT_FOUND
	jmp exit_
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
exit_:
	Call SEH_Epilog
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
NtEncodeEntriesList proc uses esi edi ImageBase:PVOID, PartialCrc:ULONG, Crc32List:PSTR, EntriesList:PVOID
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
	Call NtImageQueryEntryFromCrc32
	test eax,eax
	mov esi,Crc32List
	jnz exit_
	mov edi,EntriesList
	lodsd
@@:
	invoke NtImageQueryEntryFromCrc32, ImageBase, Eax, pRtlComputeCrc32, PartialCrc, Edi
	test eax,eax
	jnz exit_
	lodsd
	add edi,4
	test eax,eax
	jnz @b
	xor eax,eax
	jmp exit_
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
exit_:
	Call SEH_Epilog
	ret
NtEncodeEntriesList endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
comment '
NtQueryServicesList proc EntriesList:PVOID, ServicesList:PULONG, ServiceNumber:ULONG
	mov ecx,ServiceNumber
	mov esi,EntriesList
	mov edi,ServicesList
@@:
	lodsd
	cmp byte ptr [eax],0B8H	; mov eax,#
	jne err_
	mov eax,dword ptr [eax + 1]
	cmp eax,1000H
	jnb err_
save_:
	stosd
	loop @b
	ret
err_:
	xor eax,eax
	jmp save_
NtQueryServicesList endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'