	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

.code
	include VirXasm32b.asm

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

; o Не восстанавливаются Ebx, Esi и Edi.
;
SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 3*4]
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	%GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov edx,dword ptr [esp]	; ~ nt!ExecuteHandler2().
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov ecx,EXCEPTION_RECORD.ExceptionAddress[eax]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

	%GET_GRAPH_REFERENCE
	
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
; Получает базу ядра(nt).
; o PASSIVE_LEVEL|APC_LEVEL, IF = 1.
; o Fs:KGDT_R3_TEB|KGDT_R0_PCR
;
LdrGetNtImageBase proc uses ebx esi edi NtImageBase:PVOID
Local IDTR[8]:BYTE
Local ImageHeader:PIMAGE_NT_HEADERS
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	sidt qword ptr [IDTR]
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
	mov ecx,NtImageBase
	mov dword ptr [ecx],ebx
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
LdrGetNtImageBase endp

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
	mov ebx,ImageBase
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	test ebx,ebx
	.if Zero?
	invoke LdrGetNtImageBase, addr ImageBase
	test eax,eax
	mov ebx,ImageBase
	jnz Exit
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
Local pRtlComputeCrc32:PVOID
Local $RtlComputeCrc32[16]:CHAR
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

; o WRMSR
; o KiLoadFastSyscallMachineSpecificRegisters
; o KiFastCallEntry
; o KPRCB.DpcStack

comment '
_KiLoadFastSyscallMachineSpecificRegisters:
$		6A 00			push 0
$+2		6A 08			push 8	; KGDT_R0_CODE
$+4		68 74010000		push 174	; IA32_SYSENTER_CS
$+9		E8 XXXXXXXX		call _WRMSR
$+E		6A 00			push 0
$+10		68 XXXXXXXX		push offset KiFastCallEntry	; Fixup..
$+15		68 76010000		push 176
$+1A		E8 XXXXXXXX		call _WRMSR
$+1F		6A 00			push 0
$+21		FFB6 XXXXXXXX		push dword ptr ds:[esi + DIS]	; KPRCB.DpcStack
$+27		68 75010000		push 175	; IA32_SYSENTER_ESP
$+2C		E8 XXXXXXXX		call _WRMSR

_WRMSR:
$		8B4C24 04			mov ecx,dword ptr ss:[esp + 4]
$+4		8B4424 08			mov eax,dword ptr ss:[esp + 8]
$+8		8B5424 0C			mov edx,dword ptr ss:[esp + C]
$+C		0F30				wrmsr
$+E		C2 0C00			ret 0C'

SIGN_LENGTH		equ 30H	; Align!

FIX_WRMSR_1	equ 09H
FIX_WRMSR_2	equ 1AH
FIX_WRMSR_3	equ 2CH
FIX_EIP		equ 10H
FIX_ESP		equ 22H

MSR_ENVIRONMENT struct
pWRMSR			PVOID ?
pKiLoadFastSyscallX	PVOID ?
pKiFastCallEntry	PVOID ?
PrcbDpcStack		ULONG ?	; Смещение в KPRCB.
MSR_ENVIRONMENT ends
PMSR_ENVIRONMENT typedef ptr MSR_ENVIRONMENT

xQueryMsrEnvironment proc uses ebx esi edi NtImageBase:PVOID, MsrEnv:PMSR_ENVIRONMENT
Local ImageHeader:PIMAGE_NT_HEADERS
Local SectionHeader:PIMAGE_SECTION_HEADER
Local Environment:MSR_ENVIRONMENT
Local Buffer[SIGN_LENGTH]:BYTE
	Call SEH_Epilog_Reference
	Call SEH_Prolog
; Mask.
	push 000000000H
	push 0E8000001H
	push 075680000H
	push 00000B6FFH
	push 0006A0000H
	push 00000E800H
	push 000017668H
	push 000000000H
	push 068006A00H
	push 0000000E8H
	push 000000174H
	push 068086A00H
	mov ebx,esp
	invoke LdrImageNtHeader, NtImageBase, addr ImageHeader
	test eax,eax
	mov edx,ImageHeader
	jnz Exit
	mov edi,IMAGE_SECTION_HEADER.VirtualAddress[edx + sizeof(IMAGE_NT_HEADERS)]	; .text
	mov ecx,IMAGE_SECTION_HEADER.VirtualSize[edx + sizeof(IMAGE_NT_HEADERS)]
	add edi,NtImageBase
	sub ecx,SIGN_LENGTH
	cld
@@:
	mov eax,6AH	;push #
	repne scasb
	mov esi,edi
	jne Error
	push ecx
	push esi
	mov ecx,(SIGN_LENGTH/4)
	lea edi,Buffer
	xor eax,eax
	rep movsd
	mov ecx,(SIGN_LENGTH/4)
	lea edi,Buffer
	mov esi,ebx
	mov dword ptr [Buffer + FIX_WRMSR_1],eax
	mov dword ptr [Buffer + FIX_WRMSR_2],eax
	mov dword ptr [Buffer + FIX_WRMSR_3],eax
	mov dword ptr [Buffer + FIX_EIP],eax
	mov dword ptr [Buffer + FIX_ESP],eax
	repe cmpsd
	pop edi
	pop ecx
	jne @b
	mov eax,dword ptr [edi + FIX_WRMSR_1]
	lea ecx,[eax + edi + FIX_WRMSR_1 + 5 - 1]	; _WRMSR
	sub eax,11H
	mov Environment.pWRMSR,ecx
	cmp dword ptr [edi + FIX_WRMSR_2],eax
	jne @b
	sub eax,12H
	mov edx,dword ptr [edi + FIX_ESP]
	cmp dword ptr [edi + FIX_WRMSR_3],eax
	jne @b
	mov Environment.PrcbDpcStack,edx
	cmp word ptr [ecx + 0CH],300FH	; wrmsr
	mov eax,dword ptr [edi + FIX_EIP]	; _KiFastCallEntry
	jne Error
	sub edi,5
	mov ecx,40H
@@:
	cmp dword ptr [edi],0FF8B9090H	; nop/nop/mov edi,edi
	je @f
Step:
	dec edi
	loop @b
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
@@:
	cmp dword ptr [edi - 3],90909090H
	jne Step
	add edi,2	; _KiLoadFastSyscallMachineSpecificRegisters
	lea esi,Environment
	mov Environment.pKiLoadFastSyscallX,edi
	mov Environment.pKiFastCallEntry,eax
	mov edi,MsrEnv
	xor eax,eax
	movsd
	movsd
	movsd
	movsd
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	add esp,SIGN_LENGTH
	Call SEH_Epilog
	ret
xQueryMsrEnvironment endp

; Ref. KiIpiGenericCall():
;   _KiAdjustInterruptTime@8
;   _KeSetIntervalProfile@8
;   _KiRestoreFastSyscallReturnState@0
;
xQueryMsrEnvironmentEx proc uses ebx esi edi NtImageBase:PVOID, pKiIpiGenericCall:PVOID, MsrEnv:PMSR_ENVIRONMENT
Local ImageHeader:PIMAGE_NT_HEADERS
Local SectionHeader:PIMAGE_SECTION_HEADER
Local Environment:MSR_ENVIRONMENT
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	invoke LdrImageNtHeader, NtImageBase, addr ImageHeader
	test eax,eax
	jnz Exit
	invoke xQueryMsrEnvironment, NtImageBase, addr Environment
	test eax,eax
	mov edx,ImageHeader
	jnz Exit
	mov edi,IMAGE_SECTION_HEADER.VirtualAddress[edx + sizeof(IMAGE_NT_HEADERS)]	; .text
	mov ecx,IMAGE_SECTION_HEADER.VirtualSize[edx + sizeof(IMAGE_NT_HEADERS)]
	add edi,NtImageBase
	cld
	mov ebx,ecx
	mov esi,edi
	mov edx,Environment.pKiLoadFastSyscallX
	add ebx,edi
Scan:
	mov eax,68H	; push offset _KiFastCallEntry
@@:
	repne scasb
	jne Error
	cmp dword ptr [edi],edx
	jne @b
	cmp byte ptr [edi + 4],0E8H
	jne @b
	cmp word ptr [edi - 3],006AH	; push 0
	jne @b
	mov eax,dword ptr [edi + 5]
	lea eax,[eax + edi + 4 + 5]	; _KiIpiGenericCall
	cmp esi,eax
	jae Scan
	cmp ebx,eax
	jna Scan
	cmp dword ptr [eax],8B55FF8BH	; mov edi,edi/push ebp..
	jne Scan
	mov ecx,pKiIpiGenericCall
	mov dword ptr [ecx],eax
	mov edi,MsrEnv
	lea esi,Environment
	movsd
	movsd
	movsd
	movsd
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
xQueryMsrEnvironmentEx endp

; +
;
xQueryKiIpiGenericCall proc uses esi NtImageBase:PVOID, pKiIpiGenericCall:PVOID
Local Fn[2]:PVOID
Local Env:MSR_ENVIRONMENT
	mov esi,NtImageBase
	mov Fn[0],0E84775CEH	; HASH("KeIpiGenericCall")
	test esi,esi
	mov Fn[4],NULL
	.if Zero?
	invoke LdrGetNtImageBase, addr NtImageBase
	test eax,eax
	mov esi,NtImageBase
	jnz Exit
	.endif
	invoke LdrEncodeEntriesList, Esi, 0, pKiIpiGenericCall
	.if Eax == STATUS_PROCEDURE_NOT_FOUND
	invoke xQueryMsrEnvironmentEx, Esi, pKiIpiGenericCall, addr Env
	.endif
Exit:
	ret
xQueryKiIpiGenericCall endp

IPI_DATA struct
DpcStack	PVOID 16 DUP (?)
IPI_DATA ends
PIPI_DATA typedef ptr IPI_DATA

IA32_SYSENTER_ESP	equ 175H

; +
; Получает DPC-стек каждого ядра.
; Вызывается последовательно на всех ядрах.
; o IPI_LEVEL
;
xIpiRoutine:
	%GET_CURRENT_GRAPH_ENTRY
xIpiRoutineInternal proc uses ebx esi edi IpiData:PIPI_DATA
;	xor eax,eax
;	mov esi,IpiData
;	inc eax
;	cpuid
;;	rol ebx,8
;	and ebx,1111B	; ID
	assume esi:PIPI_DATA
	mov ecx,IA32_SYSENTER_ESP
	mov edi,ebx
	rdmsr
	mov [esi].DpcStack[edi*4],eax
	xor eax,eax
	ret
xIpiRoutineInternal endp

xSendIpi proc
Local pKiIpiGenericCall:PVOID
Local IpiData:PIPI_DATA
	invoke xQueryKiIpiGenericCall, NULL, addr pKiIpiGenericCall
	test eax,eax
	lea ecx,IpiData
	jnz Exit
	%GET_GRAPH_ENTRY xIpiRoutine
	push ecx
	push eax
	Call pKiIpiGenericCall
Exit:
	ret
xSendIpi endp
