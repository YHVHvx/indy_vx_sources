; Безопасный поиск базы модуля.
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
.code

MM_SHARED_USER_DATA_VA	equ 7FFE0000H

IpToFileHeader proc uses ebx esi edi Ip:PVOID
	mov esi,Ip
	xor ebx,ebx
	and esi,NOT(PAGE_SIZE*16 - 1)
@@:
	mov edx,MM_SHARED_USER_DATA_VA + X86_PAGE_SIZE - sizeof(HANDLE)	; 0x7FFE0FFC
	mov eax,ebx
	Int 2eh	; KiSystemServiceCopyArguments -> #AV
	cmp al,8
	je Scan	; NtAlertThread
	inc ebx
	bt ebx,10
	jnc @b
	xor eax,eax
	ret
Scan:
	mov edx,esi
	Call Is4R
	jnz IsMz
Next:
	sub esi,PAGE_SIZE*16
	ja Scan
	xor eax,eax
	ret
IsMz:
	mov edi,esi	; Base
	assume esi:PIMAGE_DOS_HEADER
	cmp [esi].e_magic,'ZM'
	jne Next
	add edi,[esi].e_lfanew
	mov edx,edi
	Call Is4R
	jz Next
	lea edx,[edi + sizeof(IMAGE_NT_HEADERS) - 4]
	Call Is4R
	jz Next
	assume edi:PIMAGE_NT_HEADERS
	cmp [edi].Signature,'EP'
	jne Scan
	cmp [edi].FileHeader.SizeOfOptionalHeader,sizeof(IMAGE_OPTIONAL_HEADER32)
	jne Next
	cmp [edi].FileHeader.Machine,IMAGE_FILE_MACHINE_I386	
	jne Next
	test [edi].FileHeader.Characteristics,IMAGE_FILE_32BIT_MACHINE
	jz Next
	mov eax,edi
	ret
Is4R:
; Edx: ptr, Ebx: ID
	mov eax,ebx
	Int 2eh
	cmp al,5
	retn	; ZF: no access.
IpToFileHeader endp

$Msg	CHAR "PE: 0x%p", 13, 10, 0	
	
Ip:
	assume fs:nothing
	mov eax,fs:[TEB.Peb]
	invoke IpToFileHeader, PEB.LoaderLock[eax]
	invoke DbgPrint, addr $Msg, Eax
	ret
end Ip