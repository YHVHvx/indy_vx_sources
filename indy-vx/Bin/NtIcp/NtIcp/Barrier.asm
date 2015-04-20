
CALLOUT_BARRIER struct
RtlpCalloutEntryLock	PVOID ?
RtlpCalloutEntryList	PVOID ?
CalloutEntry			PVOID ?	; Heap..
BarrierEntry			PVOID ?
CALLOUT_BARRIER ends
PCALLOUT_BARRIER typedef ptr CALLOUT_BARRIER

STACK_FRAME struct
rEbp		PVOID ?	; Next frame, PSTACK_FRAME
rEip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

.data
gBarrier	CALLOUT_BARRIER <>
gEip		PVOID ?	; Доступ только при захваченной критической секции RtlpCalloutEntryLock.
gAdjust	BOOLEAN ?
gHandler	PVOID ?

.code
; +
; Вызывается для восстановления атрибутов страницы и списка при возврате из 
; процедур RtlAddVectoredExceptionHandler() и RtlRemoveVectoredExceptionHandler().
;
BarrierRestoreRoutine proc C
	pushad
	.if gAdjust
; Eax:PLIST_ENTRY
	mov ecx,LIST_ENTRY.Blink[eax]
	mov edx,gBarrier.BarrierEntry
	mov LIST_ENTRY.Flink[ecx],edx
	mov LIST_ENTRY.Blink[edx],ecx
	mov ebx,LIST_ENTRY.Flink[edx]
	mov LIST_ENTRY.Blink[eax],edx
	mov LIST_ENTRY.Flink[eax],ebx
	mov LIST_ENTRY.Blink[ebx],eax
	mov LIST_ENTRY.Flink[edx],eax
	.endif
	push gBarrier.BarrierEntry
	push PAGE_SIZE
	push 0	; Protect
	push esp
	push PAGE_READONLY
	lea ecx,[esp + 3*4]
	lea edx,[esp + 4*4]
	push ecx	; Size
	push edx	; Base
	push NtCurrentProcess
	Call ZwProtectVirtualMemory
	lea esp,[esp + 3*4]
	; В случае ошибки при следующем изменении списка исключение не возникнет.
	invoke RtlLeaveCriticalSection, gBarrier.RtlpCalloutEntryLock
	popad
	jmp gEip
BarrierRestoreRoutine endp
;
; +
; VEH
; Вызывается при попытке изменить описатель.
; Передать управление на следующий локальный обработчик.
;
ACCESS_TYPE_READ	equ 0
ACCESS_TYPE_WRITE	equ 1

	assume fs:nothing
BarrierAccessDispatch proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local BarrierEntry:PVOID, PageSize:ULONG, OldProtect:ULONG
	mov eax,ExceptionPointers
; /--------------------\
	lea ebx,gBarrier
; \--------------------/
	assume ebx:PCALLOUT_BARRIER
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jne Chain
	cmp [esi].ExceptionCode,STATUS_ACCESS_VIOLATION
	jne Chain
; [ExceptionInformation]:
; +0 R/W
; +4 Line address.
	mov ecx,[ebx].RtlpCalloutEntryLock
	cmp [esi].ExceptionInformation,ACCESS_TYPE_WRITE
	mov eax,[esi].ExceptionInformation + 4
	jne Chain
	mov edx,fs:[TEB.Cid.UniqueThread]
	sub eax,[ebx].BarrierEntry
	cmp RTL_CRITICAL_SECTION.OwningThread[ecx],edx
	jne Chain	
; LockCount		>= 1
; RecursionCount	>= 2
;	- Не проверяем.
	cmp [esi].NumberParameters,2
	mov ecx,[ebx].BarrierEntry
	jne Chain
	mov PageSize,PAGE_SIZE
	test eax,eax
	mov BarrierEntry,ecx
	.if Zero?
	mov gAdjust,FALSE
	.else
	sub eax,4
	jnz Chain
	mov gAdjust,TRUE
	.endif
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr BarrierEntry, addr PageSize, PAGE_READWRITE, addr OldProtect
	test eax,eax
	jnz Chain
	mov ecx,[edi].regEbp
	lea edx,BarrierRestoreRoutine
	xchg STACK_FRAME.rEip[ecx],edx
; /--------------------\
	mov gEip,edx
; \--------------------/
	invoke RtlEnterCriticalSection, [ebx].RtlpCalloutEntryLock	; или NtContinue.
	; Не проверяем статус.
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp Exit
Chain:
	leave
; /--------------------\
	jmp gHandler
; \--------------------/
Exit:
	ret
BarrierAccessDispatch endp

OP_HLT	equ 0F4H
;
; +
; VEH
; o Критическая секция RtlpCalloutEntryLock захвачена.
; o Ebx - содержит ссылку на RtlpCalloutEntryLock.
;
InitializeCalloutEntryListBarrierCallback proc uses esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local PageSize:ULONG, OldProtect:ULONG
Local Barrier:CALLOUT_BARRIER
	mov Barrier.RtlpCalloutEntryLock,ebx
	mov eax,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jne Chain
	cmp [esi].ExceptionCode,STATUS_PRIVILEGED_INSTRUCTION
	mov eax,[edi].regEip
	jne Chain
	cmp byte ptr [eax],OP_HLT
	jne Chain
	cmp [edi].regEdx,'RRAB'
	jne Chain
	invoke RtlRemoveVectoredExceptionHandler, [edi].regEax
	test eax,eax
	mov PageSize,PAGE_SIZE
	jz Error
	mov Barrier.BarrierEntry,0
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr Barrier.BarrierEntry, 0, addr PageSize, MEM_COMMIT, PAGE_READWRITE
	test eax,eax
	jnz Exit
	invoke RtlAddVectoredExceptionHandler, 1, addr BarrierAccessDispatch
	test eax,eax
	cld
	jz Free
	mov esi,eax
	mov edi,Barrier.BarrierEntry
	mov ecx,8
	mov Barrier.BarrierEntry,edi
	mov Barrier.CalloutEntry,eax
	rep movsd
	
	mov edx,LIST_ENTRY.Blink[eax]	; RtlpCalloutEntryList
	mov esi,Barrier.BarrierEntry
	mov Barrier.RtlpCalloutEntryList,edx
	mov edi,LIST_ENTRY.Flink[eax]
	mov LIST_ENTRY.Flink[edx],esi
	mov LIST_ENTRY.Blink[edi],esi
	
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr Barrier.BarrierEntry, addr PageSize, PAGE_READONLY, addr OldProtect
	test eax,eax
	jz Exit
	
	mov ecx,Barrier.CalloutEntry
	push eax
	mov esi,LIST_ENTRY.Flink[ecx]
	mov edi,LIST_ENTRY.Blink[ecx]
	mov LIST_ENTRY.Blink[esi],ecx
	mov LIST_ENTRY.Flink[edi],ecx
	invoke RtlRemoveVectoredExceptionHandler, Barrier.CalloutEntry
	pop eax		
Free:
	push eax
	invoke ZwFreeVirtualMemory, NtCurrentProcess, addr Barrier.BarrierEntry, addr PageSize, MEM_RELEASE
	pop eax
Exit:
	mov ecx,ExceptionPointers
	test eax,eax
	mov ecx,EXCEPTION_POINTERS.ContextRecord[ecx]
	lea esi,Barrier
	mov edi,CONTEXT.regEcx[ecx]	; PCALLOUT_BARRIER
	.if Zero?
	movsd
	movsd
	movsd
	movsd
	.endif
	mov CONTEXT.regEax[ecx],eax
	inc CONTEXT.regEip[ecx]
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Return:
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
Chain:
	xor eax,eax
	jmp Return
InitializeCalloutEntryListBarrierCallback endp

InitializeCalloutEntryListBarrier proc Barrier:PCALLOUT_BARRIER
Local CalloutEntry:PVOID
	invoke RtlAddVectoredExceptionHandler, 1, addr InitializeCalloutEntryListBarrierCallback
	mov ecx,Barrier
	mov CalloutEntry,eax
	mov edx,'RRAB'
; Eax - ссылка на описатель.
; Ecx - ссылка на CALLOUT_BARRIER.
; Edx - маркер 'RRAB'
	hlt
	.if Eax
	push eax
	invoke RtlRemoveVectoredExceptionHandler, CalloutEntry
	pop eax
	.endif
	ret
InitializeCalloutEntryListBarrier endp