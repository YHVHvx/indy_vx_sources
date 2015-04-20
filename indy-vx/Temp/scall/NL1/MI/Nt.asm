; o Захват сервисов.
; o Indy Clerk
; o Micode
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

.code
	jmp Initialize
	include Img.asm
	include Apfn.asm
	include Barrier.asm

DS_LIMIT		equ 7FFDFH	; ..0x7FFDFFFF

TABLE_MASK	equ 100B
RPL_MASK 		equ 011B

DS_SELECTOR	equ (8H or RPL_MASK or TABLE_MASK)

UsSystemCall		equ 7FFE0300H
UsSystemCallRet	equ 7FFE0304H

MAXIMUM_INSTRUCTION_LENGTH	equ 16

VALIDATE_SIGNATURE	equ 'ISYS'

LOAD_REDUCED_DS macro
	push DS_SELECTOR
	pop ds
endm

LOAD_DEFAULT_DS macro
	push KGDT_R3_DATA or RPL_MASK
	pop ds
endm

SYSCALL_CONTINUE macro
	jmp dword ptr cs:[UsSystemCall]	; Cs!
endm

.code
_$_LeaveStub:
	GET_CURRENT_GRAPH_ENTRY
LeaveStub proc C
	LOAD_REDUCED_DS
	ret
LeaveStub endp

EnterStub proc C
; [Esp]:	@Stub
;		@RefStub
;		p1
;		...
;		pN
	mov edx,fs:[TEB.Peb]
	mov edx,dword ptr [edx + PbEnvironment]
	mov edx,ENGINE_ENVIRONMENT.LocalServiceDispatcher[edx]
	.if Edx
	Call Edx
	.endif
	lea edx,[ecx*4 + 4]
	jecxz Stub
@@:
	push dword ptr [esp + edx]
	loop @B
Stub:
	push eax
	GET_GRAPH_ENTRY_REFERENCE _$_LeaveStub
	xchg dword ptr [esp],eax
	push dword ptr [esp + edx]	; @Stub
	push EFLAGS_TF
	LOAD_REDUCED_DS	; Уже загружен диспетчером..
	popfd
	jmp dword ptr cs:[UsSystemCall]
; [Esp]:	@Stub
;		@LeaveStub
;		p1
;		...
;		pN
;		@Stub
;		@RefStub
;		p1
;		...
;		pN
EnterStub endp

; +
; VEH
; o Трассировочный баг не закрываем, это должен сделать первый обработчик в цепочке!
; o Если необходимо вызвать системный функционал из диспетчера, при дальнейшем развё
;   ртывании цепочки обработчиков, то восстановить на время вызова Ds в дефолтное зн
;   ачение, использую связку LOAD_DEFAULT_DS/LOAD_REDUCED_DS!
;
_$_AccessDispatch:
	GET_CURRENT_GRAPH_ENTRY
AccessDispatch proc uses esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local BarrierEntry:PVOID, PageSize:ULONG, OldProtect:ULONG
	mov eax,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jne Chain
	cmp [esi].ExceptionCode,STATUS_ACCESS_VIOLATION
	je Access
	cmp [esi].ExceptionCode,STATUS_SINGLE_STEP
	jne Chain
	mov eax,dword ptr cs:[UsSystemCall]
	cmp [edi].regEip,eax
	je KiBreak
	jb StopTrace
	add eax,MAXIMUM_INSTRUCTION_LENGTH
	cmp [edi].regEip,eax
	jnb StopTrace
	or [edi].regEFlags,EFLAGS_TF
	jmp ReloadDs
KiBreak:
; Sysenter или Int 0x2e.
; При возврате из сервиса восстановим Ds. Восстановление происходит при трассировочном исключении
; (шлюз трассируется), для большей надёжноти заменим арес возврата(аналогично и с KiUserCallbackD
; ispatcher, Pfn). Последние два механизма не обязательны, ибо калбэки вызываются с взведённым TF.
; Вызов может быть рекурсивным. Необходимо сохранить адрес возврата в стаб(из KiFastSystemCall) в 
; стеке, установив адрес возврата на LeaveStub(). Для этого исполним EnterStub().
	mov eax,[edi].regEsp
	xor ecx,ecx
	cmp dword ptr [eax + 4],offset LeaveStub
	mov edx,dword ptr [eax]
	jne @f
	or [edi].regEFlags,EFLAGS_TF
	jmp ReloadDs
@@:
	cmp byte ptr [edx],0C3H	; Ret
	je GoStub
	cmp byte ptr [edx],0C2H	; Ret #
	jne StopTrace	; Число параметров не определено, не системный вызов.
	movzx ecx,word ptr [edx + 1]
GoStub:
; ooooooooooooooooooooooooooooooooooooooooooooooo
;	pushad
; Eip = @KiFastSystemCall/KiIntSystemCall
; Eax = Service ID
;	LOAD_DEFAULT_DS
; Можно вызвать обработчик. Тогда он получит удалённый контекст.
; Используем вызов обработчика в контексте потока, вызывающего сервис.
;	popad
; ooooooooooooooooooooooooooooooooooooooooooooooo
	shr ecx,2
	mov [edi].regEip,offset EnterStub
	mov [edi].regEcx,ecx
StopTrace:
	and [edi].regEFlags,NOT(EFLAGS_TF)
	jmp ReloadDs
Access:
; [ExceptionInformation]:
; +0 R/W
; +4 Line address.
	cmp [esi].ExceptionInformation,ACCESS_TYPE_READ
	je @f	; Чтение или исполнение сегмента.
; Запись в сегмент. (-1 если смещение больше чем лимит сегмента).
	cmp [esi + 4].ExceptionInformation,-1
	jne Chain	; Обращение в пределах сегмента, пропускаем исключение.
; Обращение за пределы сегмента. Проверяем сегмент данных.
	cmp [edi].regSegDs,DS_SELECTOR
	jne Chain	; Ds дефолтный(не DS_SELECTOR), обращение не к сегменту данных, пропускаем исключение.
	jmp Step	; Вероятно обращение к сегменту данных, восстанавливаем Ds в дефолтный и трассируем инструкцию.
@@:
	cmp [esi + 4].ExceptionInformation,-1
	jne IsCallout	; Обращение в пределах сегмента, возможно вызов InitRoutine().
	cmp [edi].regSegDs,DS_SELECTOR
	jne Chain	; Ds дефолтный, пропускаем исключение.
; Вероятно обращение к UsSharedData. Проверяем стаб.
IsBreak:
	cmp [edi].regEdx,UsSystemCall
	jne Step
	mov eax,[edi].regEip
	; ..IsValid
	cmp word ptr [eax],12FFH	; call dword ptr ds:[edx]
	jne Step	; Не стаб, восстанавливаем дефолтный Ds и трассируем инструкцию.
; Вызов из стаба(ZwXX()).
; При вызове калбэка будет сгенерировано исключение(APC и пр.), тогда перезагрузим Ds.
	;..
	jmp Step
IsCallout:
	cmp [edi].regEip,80000000H	; Исключение в пределах пользовательского ап(не Callout).
	jb Chain
; Возможно вызов InitRoutine(), проверяем.
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.EntryPoint[eax]
	cmp [esi].ExceptionAddress,eax
	jne Chain
	cmp [edi].regEip,eax
	jne Chain
; Вызов InitRoutine(). Корректируем адрес и возвращаемся.
	btr [edi].regEip,31
; Ds должен быть дефолтный, иначе возникнут рекурсивные вызовы!
	LOAD_DEFAULT_DS
ReloadDs:
	mov [edi].regSegDs,DS_SELECTOR
Continue:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	ret
Step:
	mov [edi].regSegDs,KGDT_R3_DATA or RPL_MASK
	or [edi].regEFlags,EFLAGS_TF
	jmp Continue
Chain:
	mov [edi].regSegDs,DS_SELECTOR
	LOAD_REDUCED_DS
	xor eax,eax
	jmp Exit
AccessDispatch endp

; +
;
_$_ApfnStub:
	GET_CURRENT_GRAPH_ENTRY
ApfnStub proc C
	LOAD_REDUCED_DS
	ret
ApfnStub endp

; +
; Захват InitRoutine модуля ntdll.dll
; (Можно заменить указатель на заглушку, загружающую Ds).
;
LDR_DILAPIDATE_DATABASE macro
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	assume eax:PLDR_DATA_TABLE_ENTRY
	mov eax,[eax].InLoadOrderModuleList.Flink
	bts LDR_DATA_TABLE_ENTRY.EntryPoint[eax],31	; +0x80000000
endm

Initialize proc uses esi edi ServiceDispatcher:PVOID
Local EntriesList:NT_ENTRIES
Local EnvironmentAddress:PVOID, EnvironmentSize:ULONG
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov ecx,fs:[TEB.Peb]
	xor eax,eax
	mov ecx,dword ptr [ecx + PbEnvironment]
	jecxz @f
	cmp ENGINE_ENVIRONMENT.Signature[ecx],VALIDATE_SIGNATURE
	je Reduce
@@:
	cld
	lea edi,EntriesList
	add eax,0D820A574H
	stosd
	xor eax,0215A80A0H
	stosd
	sub eax,02714E49FH
	stosd
	add eax,05731DE26H
	stosd
	xor eax,0933C1D53H
	stosd
	sub eax,0BBD300D2H
	stosd
	add eax,05A274F2EH
	stosd
	xor eax,0C7074F35H
	stosd
	lea ecx,EntriesList
	xor eax,eax
	mov EnvironmentSize,sizeof(ENGINE_ENVIRONMENT)
	stosd
	mov EnvironmentAddress,eax
	invoke NtEncodeEntriesList, Eax, Eax, Ecx
	test eax,eax
	lea ecx,EnvironmentSize
	lea edx,EnvironmentAddress
	jnz Exit
	push PAGE_READWRITE
	push MEM_COMMIT
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	Call EntriesList.pZwAllocateVirtualMemory
	test eax,eax
	jnz Exit
	push eax
	push eax
	push eax
	push 0C7F200H
	push 0FFDFH
	push DS_SELECTOR
	Call EntriesList.pZwSetLdtEntries
	test eax,eax
	mov edi,EnvironmentAddress	; ENGINE_ENVIRONMENT.EntriesList:NT_ENTRIES
	jnz Free
	cld
	mov edx,fs:[TEB.Peb]
	lea esi,EntriesList
	mov ecx,sizeof(NT_ENTRIES)/4
	mov dword ptr [edx + PbEnvironment],edi
	GET_GRAPH_ENTRY_REFERENCE _$_AccessDispatch
	rep movsd
	push eax
	Call InitializeCalloutEntryListBarrier
	test eax,eax
	mov ecx,EnvironmentAddress
	mov edx,ServiceDispatcher
	jnz Remove
	mov ENGINE_ENVIRONMENT.LocalServiceDispatcher[ecx],edx
	mov ENGINE_ENVIRONMENT.Signature[ecx],VALIDATE_SIGNATURE
	lea ecx,ENGINE_ENVIRONMENT.ApfnInformation[ecx]
	GET_GRAPH_ENTRY_REFERENCE _$_ApfnStub
	push ecx
	push eax
	push EntriesList.pZwAllocateVirtualMemory
	Call ApfnRedirect
	; Результат не проверяем, возможно подсистема не инициализирована.
	LDR_DILAPIDATE_DATABASE
Reduce:
	LOAD_REDUCED_DS
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
Remove:
	xor ecx,ecx
	push eax
	push ecx
	push ecx
	push ecx
	push ecx
	push ecx
	push DS_SELECTOR
	Call EntriesList.pZwSetLdtEntries
	pop eax
Free:
	push eax
	push MEM_RELEASE
	lea ecx,EnvironmentSize
	lea edx,EnvironmentAddress
	push ecx
	push edx
	push NtCurrentProcess
	Call EntriesList.pZwFreeVirtualMemory
	pop eax
	jmp Exit
Initialize endp
end Initialize