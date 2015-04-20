
CALLOUT_BARRIER struct
RtlpCalloutEntryLock	PVOID ?
RtlpCalloutEntryList	PVOID ?
CalloutEntry			PVOID ?	; Heap..
BarrierEntry			PVOID ?
CALLOUT_BARRIER ends
PCALLOUT_BARRIER typedef ptr CALLOUT_BARRIER

BARRIER_ENVIRONMENT struct
Barrier	CALLOUT_BARRIER <>
rEip		PVOID ?	; Доступ только при захваченной критической секции RtlpCalloutEntryLock.
Adjust	BOOLEAN ?
Handler	PVOID ?
BugBreak	ULONG ?	; Адрес второй инструкции диспетчера исключений.
Breaker	BYTE 8 DUP (?)
BARRIER_ENVIRONMENT ends
PBARRIER_ENVIRONMENT typedef ptr BARRIER_ENVIRONMENT

NT_ENTRIES struct
; Вызываем сервисы через стабы.
pZwAllocateVirtualMemory			PVOID ?
pZwFreeVirtualMemory			PVOID ?
pZwProtectVirtualMemory			PVOID ?
pZwSetLdtEntries				PVOID ?
pRtlAddVectoredExceptionHandler	PVOID ?
pRtlRemoveVectoredExceptionHandler	PVOID ?
pRtlEnterCriticalSection			PVOID ?
pRtlLeaveCriticalSection			PVOID ?
NT_ENTRIES ends
PNT_ENTRIES typedef ptr NT_ENTRIES

ENGINE_ENVIRONMENT struct
EntriesList			NT_ENTRIES <>
BarrierEnvironment		BARRIER_ENVIRONMENT <>
ApfnInformation		APFN_INFORMATION <>
LocalServiceDispatcher	PVOID ?
;RemoteServiceDispatcher	PVOID ?	; Reserved.
Signature				DWORD ?
ENGINE_ENVIRONMENT ends
PENGINE_ENVIRONMENT typedef ptr ENGINE_ENVIRONMENT

STACK_FRAME struct
rEbp		PVOID ?	; Next frame, PSTACK_FRAME
rEip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

PUSHAD_FRAME struct
rEdi		DWORD ?
rEsi		DWORD ?
rEbp		DWORD ?
rEsp		DWORD ?
rEbx		DWORD ?
rEdx		DWORD ?
rEcx		DWORD ?
rEax		DWORD ?
PUSHAD_FRAME ends
PPUSHAD_FRAME typedef ptr PUSHAD_FRAME

PbEnvironment	equ (PAGE_SIZE - sizeof(PENGINE_ENVIRONMENT))

.code
; +
; Вызывается для восстановления атрибутов страницы и списка при возврате из 
; процедур RtlAddVectoredExceptionHandler() и RtlRemoveVectoredExceptionHandler().
;
	ASSUME FS:NOTHING
_$_BarrierRestoreRoutine:
	GET_CURRENT_GRAPH_ENTRY
BarrierRestoreRoutine proc C
	push 0	; rEip
	pushad
	mov eax,fs:[TEB.Peb]
	mov ebx,dword ptr [eax + PbEnvironment]
	assume ebx:PENGINE_ENVIRONMENT
	.if [ebx].BarrierEnvironment.Adjust
; Eax:PLIST_ENTRY
	mov ecx,LIST_ENTRY.Blink[eax]
	mov edx,[ebx].BarrierEnvironment.Barrier.BarrierEntry
	mov LIST_ENTRY.Flink[ecx],edx
	mov LIST_ENTRY.Blink[edx],ecx
	mov ebx,LIST_ENTRY.Flink[edx]
	mov LIST_ENTRY.Blink[eax],edx
	mov LIST_ENTRY.Flink[eax],ebx
	mov LIST_ENTRY.Blink[ebx],eax
	mov LIST_ENTRY.Flink[edx],eax
	.endif
	push [ebx].BarrierEnvironment.Barrier.BarrierEntry
	push PAGE_SIZE
	push 0	; Protect
	push esp
	push PAGE_READONLY
	lea ecx,[esp + 3*4]
	lea edx,[esp + 4*4]
	push ecx	; Size
	push edx	; Base
	push NtCurrentProcess
	Call [ebx].EntriesList.pZwProtectVirtualMemory
	lea esp,[esp + 3*4]
	mov esi,[ebx].BarrierEnvironment.rEip
	; В случае ошибки при следующем изменении списка исключение не возникнет.
	push [ebx].BarrierEnvironment.Barrier.RtlpCalloutEntryLock
	Call [ebx].EntriesList.pRtlLeaveCriticalSection
	mov dword ptr [esp + sizeof(PUSHAD_FRAME)],esi
	popad
	ret
BarrierRestoreRoutine endp
;
; +
; VEH
; Вызывается при попытке изменить описатель.
; Передать управление на следующий локальный обработчик.
;
ACCESS_TYPE_READ	equ 0
ACCESS_TYPE_WRITE	equ 1

_$_BarrierAccessDispatch:
	GET_CURRENT_GRAPH_ENTRY
BarrierAccessDispatch proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local BarrierEntry:PVOID, PageSize:ULONG, OldProtect:ULONG
	mov ebx,fs:[TEB.Peb]
	mov eax,ExceptionPointers
	mov ebx,dword ptr [ebx + PbEnvironment]
	assume ebx:PENGINE_ENVIRONMENT
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jne Chain
	cmp [esi].ExceptionCode,STATUS_ACCESS_VIOLATION
	jne IsTrap
; [ExceptionInformation]:
; +0 R/W
; +4 Line address.
	mov ecx,[ebx].BarrierEnvironment.Barrier.RtlpCalloutEntryLock
	cmp [esi].ExceptionInformation,ACCESS_TYPE_WRITE
	mov eax,[esi].ExceptionInformation + 4
	jne Chain
	mov edx,fs:[TEB.Cid.UniqueThread]
	sub eax,[ebx].BarrierEnvironment.Barrier.BarrierEntry
	cmp RTL_CRITICAL_SECTION.OwningThread[ecx],edx
	jne Chain	
; LockCount		>= 1
; RecursionCount	>= 2
;	- Не проверяем.
	cmp [esi].NumberParameters,2
	mov ecx,[ebx].BarrierEnvironment.Barrier.BarrierEntry
	jne Chain
	mov PageSize,PAGE_SIZE
	test eax,eax
	mov BarrierEntry,ecx
	.if Zero?
	mov [ebx].BarrierEnvironment.Adjust,FALSE
	.else
	sub eax,4
	jnz Chain
	mov [ebx].BarrierEnvironment.Adjust,TRUE
	.endif
	lea ecx,OldProtect
	lea edx,PageSize
	lea eax,BarrierEntry
	push ecx
	push PAGE_READWRITE
	push edx
	push eax
	push NtCurrentProcess
	Call [ebx].EntriesList.pZwProtectVirtualMemory
	test eax,eax
	mov ecx,[edi].regEbp
	jnz Chain
	GET_GRAPH_ENTRY_REFERENCE _$_BarrierRestoreRoutine
	xchg STACK_FRAME.rEip[ecx],eax
	push [ebx].BarrierEnvironment.Barrier.RtlpCalloutEntryLock
	mov [ebx].BarrierEnvironment.rEip,eax
	Call [ebx].EntriesList.pRtlEnterCriticalSection
	; Не проверяем статус.
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp Exit
Chain:
	mov eax,[ebx].BarrierEnvironment.Handler
	pop edi
	pop esi
	pop ebx
	leave
	Jmp Eax
Exit:
	ret
IsTrap:
	cmp [esi].ExceptionCode,STATUS_SINGLE_STEP
	mov ecx,[ebx].BarrierEnvironment.BugBreak
	jne Chain
	mov edx,[esi].ExceptionAddress
	jecxz Chain
	cmp ecx,edx
	jne Chain
	and [edi].regEFlags,NOT(EFLAGS_TF)
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp Exit
BarrierAccessDispatch endp

OP_HLT	equ 0F4H
;
; +
; VEH
; o Критическая секция RtlpCalloutEntryLock захвачена.
; o Ebx - содержит ссылку на RtlpCalloutEntryLock.
;
_$_InitializeCalloutEntryListBarrierCallback:
	GET_CURRENT_GRAPH_ENTRY
InitializeCalloutEntryListBarrierCallback proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local PageSize:ULONG, OldProtect:ULONG
Local Barrier:CALLOUT_BARRIER
	mov Barrier.RtlpCalloutEntryLock,ebx
	mov eax,ExceptionPointers
	mov ebx,fs:[TEB.Peb]
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	mov ebx,dword ptr [ebx + PbEnvironment]
	assume ebx:PENGINE_ENVIRONMENT
	cmp [esi].ExceptionFlags,NULL
	jne Chain
	cmp [esi].ExceptionCode,STATUS_PRIVILEGED_INSTRUCTION
	mov eax,[edi].regEip
	jne IsTrap
	cmp byte ptr [eax],OP_HLT
	jne Chain
	cmp [edi].regEdx,'RRAB'
	jne Chain
	push [edi].regEax
	Call [ebx].EntriesList.pRtlRemoveVectoredExceptionHandler
	test eax,eax
	mov PageSize,PAGE_SIZE
	jz Error
	mov Barrier.BarrierEntry,0
	push PAGE_READWRITE
	push MEM_COMMIT
	lea ecx,PageSize
	lea edx,Barrier.BarrierEntry
	push ecx
	push 0
	push edx
	push NtCurrentProcess
	Call [ebx].EntriesList.pZwAllocateVirtualMemory
	test eax,eax
	jnz Exit
	GET_GRAPH_ENTRY_REFERENCE _$_BarrierAccessDispatch
	push eax
	push 1
	Call [ebx].EntriesList.pRtlAddVectoredExceptionHandler 
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
	
	lea ecx,OldProtect
	lea edx,PageSize
	lea eax,Barrier.BarrierEntry
	push ecx
	push PAGE_READONLY
	push edx
	push eax
	push NtCurrentProcess
	Call [ebx].EntriesList.pZwProtectVirtualMemory
	test eax,eax
	jz Exit
	
	mov ecx,Barrier.CalloutEntry
	push eax
	mov esi,LIST_ENTRY.Flink[ecx]
	mov edi,LIST_ENTRY.Blink[ecx]
	mov LIST_ENTRY.Blink[esi],ecx
	mov LIST_ENTRY.Flink[edi],ecx
	
	push Barrier.CalloutEntry
	Call [ebx].EntriesList.pRtlRemoveVectoredExceptionHandler
	pop eax		
Free:
	push eax
	push MEM_RELEASE
	lea ecx,PageSize
	lea edx,Barrier.BarrierEntry
	push ecx
	push edx
	push NtCurrentProcess
	Call [ebx].EntriesList.pZwFreeVirtualMemory
	pop eax
Exit:
	mov ecx,ExceptionPointers
	test eax,eax
	mov ecx,EXCEPTION_POINTERS.ContextRecord[ecx]
	lea esi,Barrier
	lea edi,[ebx].BarrierEnvironment.Barrier
	.if Zero?
	movsd
	movsd
	movsd
	movsd
	.endif
	mov CONTEXT.regEax[ecx],eax
	inc CONTEXT.regEip[ecx]
Continue:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Return:
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
Chain:
	xor eax,eax
	jmp Return
IsTrap:
	cmp [esi].ExceptionCode,STATUS_SINGLE_STEP
	mov ecx,[ebx].BarrierEnvironment.BugBreak
	jne Chain
	mov edx,[esi].ExceptionAddress
	jecxz Chain
	cmp ecx,'GUBT'
	jne @f
	mov [ebx].BarrierEnvironment.BugBreak,eax	; Eip = ExceptioonAddress.
	and [edi].regEFlags,NOT(EFLAGS_TF)
	jmp Continue
@@:
	cmp ecx,edx
	jne Chain
	and [edi].regEFlags,NOT(EFLAGS_TF)
	jmp Continue
InitializeCalloutEntryListBarrierCallback endp

; +
; Инициализация.
; o NT_ENTRIES инициализирована!
; o Ссылка на ENGINE_ENVIRONMENT в PEB загружена!
;
InitializeCalloutEntryListBarrier proc uses ebx Handler:PVOID
Local CalloutEntry:PVOID
	mov ebx,fs:[TEB.Peb]
	GET_GRAPH_ENTRY_REFERENCE _$_InitializeCalloutEntryListBarrierCallback
	mov ecx,Handler
	mov ebx,dword ptr [ebx + PbEnvironment]
	assume ebx:PENGINE_ENVIRONMENT
	push eax
	mov [ebx].BarrierEnvironment.Handler,ecx
	push 1
	Call [ebx].EntriesList.pRtlAddVectoredExceptionHandler
	mov CalloutEntry,eax
	lea ecx,[ebx].BarrierEnvironment.Breaker
	mov dword ptr [ebx].BarrierEnvironment.Breaker,00010068H
	mov dword ptr [ebx].BarrierEnvironment.Breaker + 4,0C3F49D00H
	mov [ebx].BarrierEnvironment.BugBreak,'GUBT'
comment '
	push EFLAGS_TF
	popfd
	hlt
	ret
	'
	mov edx,'RRAB'
; Eax - ссылка на описатель.
; Edx - маркер 'RRAB'
	Call Ecx
	.if Eax
	push eax
	push CalloutEntry
	Call [ebx].EntriesList.pRtlRemoveVectoredExceptionHandler
	pop eax
	.endif
	ret
InitializeCalloutEntryListBarrier endp