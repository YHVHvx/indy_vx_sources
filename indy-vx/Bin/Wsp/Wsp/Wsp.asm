	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	
.code
	include VirXasm32b.asm
	
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
; Поиск _SockProcTable.
;
WspQuerySockProcTable proc uses ebx esi edi WsDllHandle:PHANDLE, SockProcTable:PVOID
Local Entries[4]:PVOID
Local $WsName[12]:CHAR
Local WsName:UNICODE_STRING
Local WsHandle:PVOID
Local pRtlComputeCrc32:PVOID	; /WSPStartup()
Local $Buffer[16]:CHAR
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	lea ecx,pRtlComputeCrc32
	xor eax,eax
	push ecx
	lea ebx,$Buffer
	push eax
	push eax
	push ebx
	push eax
	sub eax,0BC938BAEH
	mov dword ptr [$Buffer],eax
	mov Entries[0],0F45CAC9DH	; CRC32("RtlCreateUnicodeStringFromAsciiz")
	add eax,03203F91DH
	mov Entries[4],043681CE6H	; CRC32("RtlFreeUnicodeString")
	mov dword ptr [$Buffer + 4],eax
	mov Entries[2*4],0183679F2H	; CRC32("LdrLoadDll")
	xor eax,0733081BH
	mov Entries[3*4],0FED4B3C2H	; CRC32("LdrUnloadDll")
	mov dword ptr [$Buffer + 2*4],eax
	xor eax,72715617H
	mov dword ptr [$Buffer + 3*4],eax
	Call LdrImageQueryEntryFromCrc32
	test eax,eax
	lea esi,Entries
	jnz Exit
	mov edi,4
@@:
	invoke LdrImageQueryEntryFromCrc32, NULL, dword ptr [Esi], pRtlComputeCrc32, 0, Esi
	test eax,eax
	jnz Exit
	add esi,4
	dec edi
	jnz @b
	lea ecx,WsName
	mov dword ptr [$Buffer],"swsm"
	push ebx
	mov dword ptr [$Buffer + 4],".kco"
	push ecx
	mov dword ptr [$Buffer + 2*4],"lld"
	Call Entries[0]	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea ecx,WsHandle
	lea edx,WsName
	.if Zero?
	mov eax,STATUS_INVALID_PARAMETER
	jmp Exit
	.endif
	push ecx
	push edx
	push NULL
	push NULL
	Call Entries[2*4]	; LdrLoadDll()
	lea ecx,WsName
	push eax
	push ecx
	Call Entries[4]	; RtlFreeUnicodeString()
	pop eax
	test eax,eax
	jnz Exit
	invoke LdrImageQueryEntryFromCrc32, WsHandle, 10E4CD26H, pRtlComputeCrc32, NULL, addr pRtlComputeCrc32	; CRC32("WSPStartup")
	test eax,eax
	mov esi,pRtlComputeCrc32	; @WSPStartup()
	jnz Unload
	lea edi,[esi + 200H]
Ip:
	Call VirXasm32
	cmp al,3
	jne @f
	cmp byte ptr [esi],0C2H
	jne Step
	mov eax,STATUS_NOT_FOUND
Unload:
	push eax
	push WsHandle
	Call Entries[3*4]	; LdrUnloadDll()
	pop eax
	jmp Exit
@@:
	cmp al,5
	jne Step
	cmp byte ptr [esi],0BEH	; mov esi,offset _SockProcTable
	jne Step
	cmp word ptr [esi + 5],0A5F3H	; rep movsd
	jne Step
	mov ecx,dword ptr [esi + 1]
	mov edx,SockProcTable
	mov ebx,WsDllHandle
	mov esi,WsHandle
	xor eax,eax
	mov dword ptr [edx],ecx
	mov dword ptr [ebx],esi
	jmp Exit	; * Не выгружаем, счётчик ссылок увеличен на 1.
Step:
	add esi,eax
	cmp esi,edi
	jb Ip
	jmp Unload
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
WspQuerySockProcTable endp

Entry proc
Local WsHandle:HANDLE
Local SockProcTable:PVOID
	invoke WspQuerySockProcTable, addr WsHandle, addr SockProcTable
	ret
Entry endp
end Entry