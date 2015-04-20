; \IDP\Public\User\Test\Other\Snaps\Lg.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
.code
	jmp LoggerInitialize
	
	include ShowSnaps.asm

DBG_PRINTEXCEPTION_C	equ 40010006H

ENTRIES_LIST struct
pAllocConsole	PVOID ?
pGetStdHandle	PVOID ?
pWriteFile	PVOID ?
pRtlAddVectoredExceptionHandler	PVOID ?
ENTRIES_LIST ends

PbEntriesList	equ (PAGE_SIZE - sizeof(ENTRIES_LIST))

	ASSUME FS:NOTHING

_$_VEH::
	GET_CURRENT_GRAPH_ENTRY
ExceptionDispatcher proc uses ebx esi ExceptionPointers:PEXCEPTION_POINTERS
Local WriteCount:ULONG
	mov ebx,ExceptionPointers
	xor eax,eax
	mov ebx,EXCEPTION_POINTERS.ExceptionRecord[ebx]
	assume ebx:PEXCEPTION_RECORD
	.if [Ebx].ExceptionCode == DBG_PRINTEXCEPTION_C
	mov esi,fs:[TEB.Peb]
	push STD_OUTPUT_HANDLE
	Call ENTRIES_LIST.pGetStdHandle[esi + PbEntriesList]
	test eax,eax
	lea ecx,WriteCount
	jz @f
	push NULL
	push ecx 
	push dword ptr [Ebx].ExceptionInformation
	push dword ptr [Ebx].ExceptionInformation + 4
	push eax
	Call ENTRIES_LIST.pWriteFile[esi + PbEntriesList]
@@:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	.elseif [Ebx].ExceptionCode == STATUS_BREAKPOINT
	mov ebx,ExceptionPointers
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	mov ebx,EXCEPTION_POINTERS.ContextRecord[ebx]
	inc CONTEXT.regEip[ebx]
	.endif
exit_:
	ret
ExceptionDispatcher endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LoggerInitialize proc uses edi
Local ShowSnaps:PVOID
	mov edi,fs:[TEB.Peb]
	xor eax,eax
	mov ecx,PEB.Ldr[edi]
	add edi,PbEntriesList
	mov ecx,PEB_LDR_DATA.InLoadOrderModuleList.Flink[ecx]
	cld
	push edi
	sub eax,795E278H
	push edi
	mov ecx,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[ecx]
	stosd	; 0F86A1D88H AllocConsole()
	mov ecx,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[ecx]
	xor eax,22B79463H
	stosd	; 0DADD89EBH GetStdHandle()
	add eax,0F20BCC27H
	stosd	; 0CCE95612H WriteFile()
	xor eax,eax
	stosd
	push eax
	push LDR_DATA_TABLE_ENTRY.DllBase[ecx]
	Call NtEncodeEntriesList
	test eax,eax
	lea ecx,[esp - 2*4]
	jnz exit_
	push eax
	push 0BAAB0208H	; RtlAddVectoredExceptionHandler()
	push ecx
	push ecx
	push eax
	push eax
	Call NtEncodeEntriesList
	pop dword ptr [edi - 4]
	test eax,eax
	pop ecx
	jnz exit_
	invoke QueryShowSnaps, addr ShowSnaps
	test eax,eax
	jnz exit_
	Call _$_VEH
	push eax
	push dword ptr 0
	Call ENTRIES_LIST.pRtlAddVectoredExceptionHandler[edi - sizeof(ENTRIES_LIST)]
	test eax,eax
	jz error_
	Call ENTRIES_LIST.pAllocConsole[edi - sizeof(ENTRIES_LIST)]
	test eax,eax
	mov ecx,ShowSnaps
	jz error_
	mov edx,fs:[TEB.Peb]
	mov byte ptr [ecx],1
	xor eax,eax
	mov PEB.BeingDebugged[edx],1
exit_:
	ret
error_:
	mov eax,STATUS_UNSUCCESSFUL
	jmp exit_
LoggerInitialize endp
end LoggerInitialize