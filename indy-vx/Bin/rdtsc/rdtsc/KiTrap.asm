PKTRAP_FRAME typedef PVOID
PKEXCEPTION_FRAME typedef PVOID

KPROCESSOR_MODE typedef ULONG

OP_UD2	equ 0B0FH
OP_RDTSC	equ 310FH

xKiDebugRoutineInternal:
	%GET_CURRENT_GRAPH_ENTRY
KiDebugRoutineInternal proc uses ebx esi edi TrapFrame:PKTRAP_FRAME, 
 ExceptionFrame:PKEXCEPTION_FRAME, 
 ExceptionRecord:PEXCEPTION_RECORD, 
 ContextRecord:PCONTEXT, 
 PreviousMode:KPROCESSOR_MODE, 
 SecondChance:BOOLEAN
 	
	cmp SecondChance,FALSE
	jne Chain
	
	cmp PreviousMode,KernelMode
	je Chain

	mov esi,ExceptionRecord
	assume esi:PEXCEPTION_RECORD

	mov ebx,ContextRecord
	assume ebx:PCONTEXT

	cmp [esi].ExceptionFlags,NULL
	jne Chain

	test [ebx].ContextFlags,CONTEXT_CONTROL
	jz Chain

	cmp [esi].ExceptionCode,STATUS_ILLEGAL_INSTRUCTION
	jne IsRdtsc

	cmp [ebx].regEax,XCPT_UD_MAGIC
	jne Chain
		
	mov [ebx].regEax,0	; !Eax
	mov [ebx].regEFlags,EFLAGS_MASK	; !EFlags
	
	cli
	mov eax,Cr4
	or eax,CR4_TSD
	mov Cr4,eax
	sti

Skip:
; * Возможно рекурсивное возникновение фолта, что требует обработки.
; * Так как код пермутирующий, обработка такого фолта требует анализ графа.

	mov esi,[esi].ExceptionAddress
	Call VirXasm32
	add [ebx].regEip,eax
	
Load:
	mov eax,TRUE
	jmp Exit
	
Chain:
	xor eax,eax
Exit:
	ret
IsRdtsc:
	cmp [esi].ExceptionCode,STATUS_PRIVILEGED_INSTRUCTION
	jne Chain
	
	cmp [ebx].regEax,XCPT_TSC_MAGIC
	je Chain
	
	rdtsc
	mov [ebx].regEax,eax
	mov [ebx].regEdx,edx
	
	jmp Skip
KiDebugRoutineInternal endp