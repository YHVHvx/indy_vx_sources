; Захват загрузчика.
;
; \IDP\Public\User\Test\Other\LdrIcp\LdrIcp.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
STACK_FRAME struct
rEbp		PVOID ?	; Next frame, PSTACK_FRAME
rEip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

.data
CalloutEntry	PVOID ?

.code
$Trace	CHAR "Backtrace frame:", 13, 10, 0
$Frame	CHAR " [%p]: Ebp = %p, Eip = %p", 13, 10, 0

	ASSUME FS:NOTHING
; Вызывается с причиной DLL_PROCESS_ATTACH.
;
DispatchCallout proc uses ebx DllHandle:PVOID, Reason:ULONG, Context:PVOID
	cmp Reason,DLL_PROCESS_ATTACH
	jne exit_
; Сбрасываем флаг LDRP_ENTRY_PROCESSED для последующих вызовов, взводится после возврата.
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	and byte ptr LDR_DATA_TABLE_ENTRY.Flags[eax + 1],NOT(LDR_ENTRY_PROCESSED)
	mov ebx,ebp
	assume ebx:PSTACK_FRAME
	invoke DbgPrint, addr $Trace
@@:
	cmp [ebx].rEip,0
	je exit_
	invoke DbgPrint, addr $Frame, Ebx, [Ebx].rEbp, [Ebx].rEip
	mov ebx,[ebx].rEbp
	jmp @b
exit_:
	mov eax,TRUE
	ret
DispatchCallout endp

$Beep	db "Beep",0

LDR_ENTRY_PROCESSED	equ (LDRP_ENTRY_PROCESSED shr 8)

Entry proc
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov ebx,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	lea ecx,DispatchCallout
	mov edx,LDR_DATA_TABLE_ENTRY.DllBase[ebx]	; ntdll.dll
	and byte ptr LDR_DATA_TABLE_ENTRY.Flags[ebx + 1],NOT(LDR_ENTRY_PROCESSED)
	xchg LDR_DATA_TABLE_ENTRY.EntryPoint[ebx],ecx	; kernel32.dll
	mov CalloutEntry,ecx
	invoke GetProcAddress, Edx, addr $Beep	; -> LdrpGetProcedureAddress() -> LdrpRunInitializeRoutines()
	.if !Eax
	int 3
	.endif
	mov ecx,dword ptr [CalloutEntry]
	xor eax,eax
	xchg LDR_DATA_TABLE_ENTRY.EntryPoint[ebx],ecx
	ret
Entry endp
end Entry