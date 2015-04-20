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

	assume fs:nothing
%GET_NT_BASE_U macro Reg32
	mov Reg32,fs:[TEB.Peb]
	mov Reg32,PEB.Ldr[Reg32]
	mov Reg32,PEB_LDR_DATA.InLoadOrderModuleList.Flink[Reg32]
	mov Reg32,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[Reg32]
	mov Reg32,LDR_DATA_TABLE_ENTRY.DllBase[Reg32]	; ntdll.dll
endm

LdrGetNtImageBaseU proc C
	%GET_NT_BASE_U Eax
	ret
LdrGetNtImageBaseU endp


; +
; Получает базу ядра(nt).
; o PASSIVE_LEVEL|APC_LEVEL, IF = 1.
; o Fs:KGDT_R3_TEB|KGDT_R0_PCR
;
LdrGetNtImageBaseK proc uses ebx esi edi
Local IDTR[8]:BYTE
Local ImageHeader:PIMAGE_NT_HEADERS
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	sidt qword ptr [IDTR]
	xor esi,esi
	mov eax,dword ptr [IDTR + 2]	; IDT Base
	movzx ebx,word ptr [eax + 2AH*8 + 6]	; KiGetTickCount, Hi
	shl ebx,16
	mov bx,word ptr [eax + 2AH*8]	; Lo
	and ebx,NOT(X86_PAGE_SIZE - 1)
@@:
	invoke LdrImageNtHeader, Ebx, addr ImageHeader
	test eax,eax
	jz @f
	sub ebx,X86_PAGE_SIZE
	jmp @b
@@:
	mov esi,ebx
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	mov eax,esi
	ret
LdrGetNtImageBaseK endp
	
; +
; Поиск функции по имени/хэшу в экспорте.
;
LdrImageQueryEntryFromHash proc uses ebx esi edi ImageBase:PVOID, HashOrFunctionName:DWORD, pComputeHashRoutine:PVOID, PartialHash:ULONG, Function:PVOID
Local ExportDirectory:PIMAGE_EXPORT_DIRECTORY
Local ImageHeader:PIMAGE_NT_HEADERS
Local NumberOfNames:ULONG
	%SEHPROLOG
	mov eax,Function
	mov ebx,ImageBase
	mov dword ptr [eax],NULL
	.if !Ebx
		%CPLCF0
		.if Carry?
			invoke LdrGetNtImageBaseK
			mov ebx,eax
		.else
			invoke LdrGetNtImageBaseU
			mov ebx,eax
		.endif
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
LdrEncodeEntriesList proc uses ebx esi edi ImageBase:PVOID, EntriesList:PVOID
	%SEHPROLOG
	%GET_GRAPH_ENTRY xLdrCalculateHash
	mov esi,EntriesList
	mov ebx,eax
	mov edi,esi
	lodsd
	.repeat
		invoke LdrImageQueryEntryFromHash, ImageBase, Eax, Ebx, 0, Edi	; !PartialCrc
		test eax,eax
		jnz Exit
		lodsd
		add edi,4
	.until !Eax
	%SEHEPILOG
	ret
LdrEncodeEntriesList endp

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

SIB_SCALE_MASK		equ 11000000B
SIB_INDEX_MASK		equ 00111000B
SIB_BASE_MASK		equ 00000111B

; +
; Поиск переменной KiAbiosGdt.
;
; Переменная nt!KiAbiosGdt - массив баз GDT всех процессоров.
; Переменная hal!HalpProcessroPCR -о массив баз PCR всех процессоров.
; Механизм: nt!KiAbiosGdt[KeNumberProcessors] -> GDT -> PCR.
; hal!HalpProcessroPCR не используем.
; Можно доставить IPI, но потребуется поиск KeIpiGenericCall(), 
; которая в младших версиях не экспортируется.
; 
; o Включается LDE.
; 
LdrQueryKiAbiosGdt proc uses ebx esi edi NtImageBase:PVOID, pKiAbiosGdt:PVOID
Local ImageHeader:PIMAGE_NT_HEADERS
Local Fn[2*4]:PVOID
	%SEHPROLOG
	invoke LdrImageNtHeader, NtImageBase, addr ImageHeader
	test eax,eax
	mov Fn[0],0D259263FH	; HASH("KeI386AllocateGdtSelectors")
	mov Fn[4],eax
	jnz Exit
	invoke LdrEncodeEntriesList, NtImageBase, addr Fn
	test eax,eax
	mov esi,Fn[0]	; KeI386AllocateGdtSelectors
	mov edi,pKiAbiosGdt
	jnz Exit
	lea ebx,[esi + 74H]
Step:
	movzx eax,word ptr [esi]
; 2B15 XXXXXXXX	sub edx,dword ptr ds:[_KiAbiosGdt]
	cmp al,2BH	; 2B /r sub r32,r/m32
	jne Next
	mov al,ah	; ModR/M
	test ah,MODRM_MOD_MASK
	jnz Next
	and al,MODRM_RM_MASK
	shr ah,3
	cmp al,101B
	jne Next
	cmp ah,2	; Eax, Ecx, Edx.
	ja Next
	mov ecx,dword ptr [esi + 2]	; _KiAbiosGdt
	xor eax,eax
	mov dword ptr [edi],ecx
	jmp Exit	
Next:
	Call VirXasm32
	add esi,eax
	cmp ebx,esi
	ja Step
	mov eax,STATUS_NOT_FOUND
	%SEHEPILOG
	ret
LdrQueryKiAbiosGdt endp

; +
; Загрузка переменной в KPCR всех процессоров.
; o Disp < X86_PAGE_SIZE
; o Адресация переменной посредством FS:[Disp].
;
LdrLoadVariableInPcrs proc uses ebx esi edi pKiAbiosGdt:PVOID, NumberProcessors:ULONG, Variable:PVOID, Disp:ULONG
	%SEHPROLOG
	mov edi,pKiAbiosGdt
	cmp NumberProcessors,32
	mov eax,1
	ja Error
	cmp NumberProcessors,0
	jne @f
	cpuid
	shr ebx,16
	mov byte ptr [NumberProcessors],bl	
@@:
	mov esi,dword ptr [edi]	; PKGDT
	xor eax,eax
	xor ecx,ecx
	xor edx,edx
	xor ebx,ebx
	lock cmpxchg8b qword ptr [esi + KGDT_R0_PCR]	; -> Edx:Eax
	mov ecx,edx
	btr edx,8	; A
	mov ebx,Variable
	cmp dh,10010010B	; P:1, DPL:0, S:1, Type:001(DATA, RW)
	jne Error
	cmp ax,1	; Limit
	mov ecx,edx
	jne Error
	shr ecx,8
	and ch,11001111B
	mov al,dl	; Base: 23%16
	cmp ch,11000000B	; G:1, ; D:1
	jne Error
	and edx,0FF000000H	; Base: 31%24
	ror eax,16
	mov ecx,Disp
	or eax,edx	; PKPCR
	mov dword ptr [eax + ecx],ebx
	add edi,4
	dec NumberProcessors
	jnz @b
	xor eax,eax
	jmp Exit
Error:
	mov eax,STATUS_UNSUCCESSFUL
	%SEHEPILOG
	ret
LdrLoadVariableInPcrs endp

; +
;
LdrLoadDllEx proc DllName:PSTR, DllCharacteristics:PULONG, DllHandle:PVOID
Local Entries[4]:PVOID
Local DllNameU:UNICODE_STRING
	xor ecx,ecx
	mov Entries[0],059B88A67H	; CRC32("RtlCreateUnicodeStringFromAsciiz")
	mov Entries[4],0DB164279H	; CRC32("RtlFreeUnicodeString")
	mov Entries[2*4],09E1E35CEH	; CRC32("LdrLoadDll")
	mov Entries[3*4],ecx
	invoke LdrEncodeEntriesList, NULL, addr Entries
	test eax,eax
	lea ecx,DllNameU
	jnz Exit
	push DllName
	push ecx
	Call Entries[0]	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea ecx,DllNameU
	.if Zero?
		mov eax,STATUS_INVALID_PARAMETER
	.else
		push DllHandle
		push ecx
		push DllCharacteristics
		push NULL
		Call Entries[2*4]	; LdrLoadDll()
		lea ecx,DllNameU
		push eax
		push ecx
		Call Entries[4]	; RtlFreeUnicodeString()
		pop eax
	.endif
Exit:
	ret
LdrLoadDllEx endp

; +
; Загрузка User32.dll
;
LdrLoadUser32 proc DllHandle:PVOID
Local DllName[12]:CHAR
	mov dword ptr [DllName],"resU"
	mov dword ptr [DllName + 4],"d.23"
	mov dword ptr [DllName + 2*4],"ll"
	invoke LdrLoadDllEx, addr DllName, NULL, DllHandle
	ret
LdrLoadUser32 endp