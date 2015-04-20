; Захват TEB.
; Регистр Fs восстанавливается при возврате из быстрых системных вызовов и при входе в диспетчер исключений.
; Для захвата возврата из сервисов используем хардварный останов на KiFastSystemCallRet().
; Устанавливать хардварный останов на диспетчер исключений нельзя, возникнет рекурсия до исчерпания стека.
; Перезагружаем региситр Fs в VEH.
;
; \IDP\Public\User\Test\Other\Teb\Teb.asm
;
	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
UsSystemCallReturn	equ 7FFE0304H

.data
pInitRoutine	PVOID ?

.code
; Instruction format:
; 0F B : 11 XXX XXX
;           \ / \ /
;            |   |__ RGP
;            |______ DR
; B=21:For read DR, 23 for write DR
.code
DrAccessDispatch proc uses esi edi ExceptionAddress:PVOID, Context:PCONTEXT
	mov esi,ExceptionAddress
	xor eax,eax
	cmp byte ptr [esi],0Fh
	jne exit_
	cmp byte ptr [esi + 1],21h
	mov edi,Context
	je correct_opcode_
	cmp byte ptr [esi + 1],23h
	jne exit_
correct_opcode_:
	assume edi:PCONTEXT
	movzx edx,byte ptr [esi + 2]
	bt dx,7
	jnc exit_
	bt dx,6
	jnc exit_
	mov ecx,edx
	shr ecx,3
	and edx,111b	; RGP
	and ecx,111b	; DR
	bt edx,1
	jnz ctx_correct_
	bt edx,2
	jnz exit_		; Dr4 or Dr5 -> next handler
ctx_correct_:
; Correct DR for context
	.if 	Ecx > 3
	sub ecx,2
	.endif
	lea ecx,[ecx * 4 + CONTEXT.regDr0]
; Correct RGP for context
	cmp edx,100b	; Esp
	mov eax,CONTEXT.regEsp
	je corrected_
	cmp edx,101b	; Ebp
	mov eax,CONTEXT.regEbp
	je corrected_
	cmp edx,110b	; Esi
	mov eax,CONTEXT.regEsi
	je corrected_
	cmp edx,111b	; Edi
	mov eax,CONTEXT.regEdi
	je corrected_
; Eax, Ecx, Edx, Ebx
	shl edx,2
	mov eax,CONTEXT.regEax
	sub eax,edx
corrected_:
	.if byte ptr [esi+1] == 21h	; Read DR
	xchg eax,ecx
	.endif
	mov edx,dword ptr [edi + eax]
	add [edi].regEip,3	; On next instruction
	mov dword ptr [edi + ecx],edx
	mov [edi].regDr6,NULL
	mov eax,EXCEPTION_CONTINUE_EXECUTION
exit_:
	ret
DrAccessDispatch endp

ExceptionDispatcher proc uses ebx ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov eax,ExceptionPointers
	mov ecx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume ecx:PEXCEPTION_RECORD
	mov edx,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edx:PCONTEXT
	cmp [ecx].ExceptionFlags,NULL
	mov ebx,[edx].regEip
	jnz chain_
	cmp [ecx].ExceptionCode,STATUS_PRIVILEGED_INSTRUCTION
	jne @f
	invoke DrAccessDispatch, Ebx, Edx
	jmp exit_
@@:
	cmp [ecx].ExceptionCode,STATUS_SINGLE_STEP
	jne is_av_
	test [edx].regDr6,HB_EVENT_BREAK_0
	jz step_
	or [edx].regEFlags,EFLAGS_TF
	mov [edx].regDr7,0
	jmp load_
is_av_:
	cmp [ecx].ExceptionCode,STATUS_ACCESS_VIOLATION
	jne chain_
	cmp byte ptr [ebx],PREFIX_FS
	jne chain_
	mov [edx].regSegFs,KGDT_R3_TEB or RPL_MASK
	or [edx].regEFlags,EFLAGS_TF
	jmp load_
step_:
	and [edx].regEFlags,NOT(EFLAGS_TF)
	mov [edx].regSegFs,0
	mov eax,dword ptr ds:[UsSystemCallReturn]
	mov ecx,HB_0_ON_LOCAL or HB_LOCALS_ENABLE or HB_0_TYPE_EXEC
	mov [edx].regDr0,eax
	mov [edx].regDr7,ecx
load_:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
exit_:
	ret
chain_:
	xor eax,eax
	jmp exit_
ExceptionDispatcher endp

StartupCallout proc C
	pushad	; Chain..
	mov eax,dword ptr ds:[UsSystemCallReturn]
	mov ecx,HB_0_ON_LOCAL or HB_LOCALS_ENABLE or HB_0_TYPE_EXEC
	mov Dr0,eax
	mov Dr7,ecx
	popad
	jmp pInitRoutine
StartupCallout endp

$Msg	CHAR "Test..",0

Entry proc
; Установка нотификатора на создание потоков.
	assume fs:nothing
	mov eax,fs:[TEB.Peb]
	lea ecx,StartupCallout
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList[eax]
	assume eax:PLDR_DATA_TABLE_ENTRY
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]	; ntdll.dll
; 	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]	; kernel32/kernelbase.dll
	lock xchg [eax].EntryPoint,ecx	; Следует захватить несколько описателей.
	push offset ExceptionDispatcher
	mov pInitRoutine,ecx
	push 1
	Call RtlAddVectoredExceptionHandler
	.if !Eax
	int 3
	.endif
	
	mov eax,dword ptr ds:[UsSystemCallReturn]	; Exec/RW
	mov ecx,HB_0_ON_LOCAL or HB_LOCALS_ENABLE or HB_0_TYPE_EXEC
	mov Dr0,eax	; Emulated!
	mov Dr7,ecx	; -

	invoke ZwYieldExecution	; Break!
	nop
	mov eax,fs:[TEB.Peb]	; Break!
	nop
	invoke DbgPrint, addr $Msg	; Break!
	ret
Entry endp
end Entry