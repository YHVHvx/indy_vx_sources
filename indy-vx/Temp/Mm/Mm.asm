; o Менеджер расширяемых буферов.
; o MI, UM
;
; \IDP\Public\User\Bin\Graph\Mm\Mm.asm
;
;	.686
;	.model flat, stdcall 
;	option casemap :none 
;	include \masm32\include\ntdll.inc

PbManagerDatabase	equ (PAGE_SIZE - 3*4)	; Смещение указателя в PEB.

BUFFER_INFORMATION struct
ThreadId		HANDLE ?	; Опционально, если ноль то буфер глобальный(расширяется при обращении любого треда).
BaseAddress	PVOID ?
AllocationBase	PVOID ?
PageCount		ULONG ?
SystemCalls	ULONG ?
BUFFER_INFORMATION ends
PBUFFER_INFORMATION typedef ptr BUFFER_INFORMATION

NT_ENTRIES struct
pZwQuerySystemInformation		PVOID ?
pZwAllocateVirtualMemory			PVOID ?
pZwFreeVirtualMemory			PVOID ?
pRtlInitializeCriticalSection		PVOID ?
pRtlDeleteCriticalSection		PVOID ?
pRtlEnterCriticalSection			PVOID ?
pRtlLeaveCriticalSection			PVOID ?
pRtlAddVectoredExceptionHandler	PVOID ?
pRtlRemoveVectoredExceptionHandler	PVOID ?
NT_ENTRIES ends
PNT_ENTRIES typedef ptr NT_ENTRIES

MANAGER_DATABASE struct
BugBreak		ULONG ?	; Адрес второй инструкции диспетчера исключений.
Breaker		BYTE 8 DUP (?)	; Код для генерации останова.
EntriesList	NT_ENTRIES <>	; Список адресов апи.
CalloutList	PVOID ?	; Указатель возвращенный RtlAddVectoredExceptionHandler().
ManagerLock	RTL_CRITICAL_SECTION <>	; Критическая секция для захвата базы данных.
BufferCount	ULONG ?
;Buffer	BUFFER_INFORMATION 1 DUP (<>)
MANAGER_DATABASE ends
PMANAGER_DATABASE typedef ptr MANAGER_DATABASE

DATABASE_BUFFERS_LIMIT equ ((PAGE_SIZE - sizeof(MANAGER_DATABASE))/sizeof(BUFFER_INFORMATION))

.code
MmEntry::
	test eax,eax
	jz MmInitializeMemoryManagment
	dec eax
	jz MmUninitializeMemoryManagment
	dec eax
	jz MmAllocateBuffer
	dec eax
	jz MmFreeBuffer
	mov eax,STATUS_UNSUCCESSFUL
	retn

	include img.asm
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Менеджер памяти.
; Управляет списками описателей регионов, обрабатывает ис
; ключения и расширяет память. Для расширения памяти необ
; ходимо обработать исключение. Диспетчер исключений фикс
; ирован и находится в нтдлл. Изза этого нет смысла скрыв
; ать вызовы.
; Таблица описателей регионов описывает каждый из регионо
; в памяти, выделенных посредством AllocateBuffer(). Табл
; ица защищена критической секцией. Описатель таблицы хра
; нится в PEB.
;
_$_DispatchBufferOverflow:
	%GET_CURRENT_GRAPH_ENTRY
DispatchBufferOverflow proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local RegionSize:ULONG
	assume fs:nothing
	mov eax,ExceptionPointers
	mov ecx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume ecx:PEXCEPTION_RECORD
	mov edx,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edx:PCONTEXT
	cmp [ecx].ExceptionFlags,NULL
	mov ebx,fs:[TEB.Peb]
	jnz Chain
	xor eax,eax
	lock cmpxchg dword ptr [ebx + PbManagerDatabase],eax
	mov edi,[ecx].ExceptionAddress
	je Chain
	mov ebx,eax
	assume ebx:PMANAGER_DATABASE
	; Контекст всегда полный, не проверяем.
	; ExceptionAddress = Eip.
	cmp [ecx].ExceptionCode,STATUS_ACCESS_VIOLATION
	mov esi,[ebx].BugBreak
	je TPF
	cmp [ecx].ExceptionCode,STATUS_SINGLE_STEP
	je TDB
	cmp [ecx].ExceptionCode,STATUS_PRIVILEGED_INSTRUCTION
	lea eax,[ebx].Breaker + 6
	jne Chain
	cmp eax,edi
	jne Chain
	inc [edx].regEip
	jmp StopTrace	
TDB:
	test esi,esi
	jz Chain
	cmp esi,1
	je @f
	cmp esi,edi
	jne Chain
	jmp StopTrace
@@:
	lea eax,[ebx].Breaker
	cmp eax,edi
	ja @f
	add eax,8
	cmp eax,edi
	ja Chain
@@:
	mov [ebx].BugBreak,edi
StopTrace:
	and [edx].regEFlags,NOT(EFLAGS_TF)
	jmp Continue
TPF:
	mov esi,[ecx].ExceptionInformation + 4
; [ExceptionInformation]:
; +0 Тип доступа к памяти; 0 - чтение, 1 - запись.
; +4 Адрес к которому произошло обращение.
	cmp [ecx].NumberParameters,2
	lea ecx,[ebx].ManagerLock
	jne Chain
	push ecx
	Call [ebx].EntriesList.pRtlEnterCriticalSection
	; Результат не проверяем.
	cmp [ebx].BufferCount,0
	je LeaveLock
	mov ecx,DATABASE_BUFFERS_LIMIT
	lea edi,[ebx + sizeof(MANAGER_DATABASE)]
	assume edi:PBUFFER_INFORMATION
entry_:
	mov eax,[edi].BaseAddress
	test eax,eax
	jz Next
	cmp eax,esi
	ja Next
	and eax,NOT(PAGE_SIZE - 1)
	add eax,PAGE_SIZE*2
	cmp eax,esi
	jb Next
	mov edx,[edi].ThreadId
	test edx,edx
	jz @f
	cmp fs:[TEB.Cid.UniqueThread],edx
	jne LeaveLock	; Локальный буфер, используется другим тредом.
@@:
	cmp [edi].PageCount,0
	je LeaveLock	; (STATUS_BUFFER_OVERFLOW)
	push PAGE_EXECUTE_READWRITE
	lea ecx,RegionSize
	push MEM_COMMIT
	lea edx,[edi].BaseAddress
	push ecx
	add [edi].BaseAddress,PAGE_SIZE
	push 0
	mov RegionSize,PAGE_SIZE
	push edx
	push NtCurrentProcess
	Call [ebx].EntriesList.pZwAllocateVirtualMemory
	test eax,eax
	jnz LeaveLock
	dec [edi].PageCount
	lea ecx,[ebx].ManagerLock
	push ecx
	Call [ebx].EntriesList.pRtlLeaveCriticalSection
Continue:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	ret
Next:
	add edi,sizeof(BUFFER_INFORMATION)
	loop entry_
LeaveLock:
	lea ecx,[ebx].ManagerLock
	push ecx
	Call [ebx].EntriesList.pRtlLeaveCriticalSection
Chain:
	xor eax,eax
	ret
DispatchBufferOverflow endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Резервирует регион и выделяет первую страницу в нём.
;
InitializeBufferInternal proc uses ebx EntriesList:PNT_ENTRIES, SizeOfBufferReserve:ULONG, ThreadId:HANDLE, BufferInformation:PBUFFER_INFORMATION	;, SizeOfBufferCommit:ULONG
Local RegionAddress:PVOID, RegionSize:ULONG
	xor eax,eax
	mov ebx,EntriesList
	push PAGE_READWRITE
	lea ecx,SizeOfBufferReserve
	push MEM_RESERVE
	lea edx,RegionAddress
	push ecx
	mov RegionAddress,eax
	push eax
	push edx
	push NtCurrentProcess
	assume ebx:PNT_ENTRIES
	Call [ebx].pZwAllocateVirtualMemory
	test eax,eax
	jnz exit_
	push PAGE_EXECUTE_READWRITE
	lea ecx,RegionSize
	push MEM_COMMIT
	lea edx,RegionAddress
	push ecx
	push eax
	mov RegionSize,PAGE_SIZE
	push edx
	push NtCurrentProcess
	Call [ebx].pZwAllocateVirtualMemory
	test eax,eax
	mov edx,ThreadId
	jnz free_
	mov ebx,BufferInformation
	assume ebx:PBUFFER_INFORMATION
	.if Edx == NtCurrentThread
	assume fs:nothing
	mov edx,fs:[TEB.Cid.UniqueThread]
	.endif
	mov ecx,SizeOfBufferReserve
	push RegionAddress
	shr ecx,12	; Pages.
	mov [ebx].ThreadId,edx
	push RegionAddress
	dec ecx
	pop [ebx].AllocationBase
	mov [ebx].PageCount,ecx
	pop [ebx].BaseAddress
exit_:
	ret
free_:
	lea ecx,RegionSize
	push eax
	lea edx,RegionAddress
	push MEM_RELEASE
	push ecx
	push edx
	mov RegionSize,NULL
	push NtCurrentProcess
	Call NT_ENTRIES.pZwFreeVirtualMemory[ebx]
	pop eax
	jmp exit_
InitializeBufferInternal endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Инициализация менеджера памяти.
;
MmInitializeMemoryManagment proc uses ebx esi edi
Local Database:MANAGER_DATABASE
Local Crc32List[sizeof(NT_ENTRIES) + 4]:DWORD
Local RegionAddress:PVOID, RegionSize:ULONG
	xor eax,eax
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	lock cmpxchg dword ptr [ebx + PbManagerDatabase],eax
	lea ecx,Database.EntriesList
	je @f
	xor eax,eax
	jmp exit_	; STATUS_SUCCESS
@@:
	push ecx
	xor eax,eax
	lea edi,Crc32List
	cld
	push edi
	sub eax,0088A0439H
	stosd
	xor eax,02F555EB3H
	stosd
	add eax,021598060H
	stosd
	sub eax,06C032C30H
	stosd
	xor eax,0ED5518F8H
	stosd
	add eax,0F8DB6F08H
	stosd
	sub eax,0B9073113H
	stosd
	xor eax,025531D59H
	stosd
	add eax,0442CFF2EH
	stosd
	xor eax,eax
	stosd
	push eax
	push eax
	Call NtEncodeEntriesList
	test eax,eax
	jnz exit_
	push PAGE_READWRITE
	lea ecx,RegionSize
	push MEM_COMMIT
	lea edx,RegionAddress
	push ecx
	mov RegionAddress,eax
	push eax
	mov RegionSize,PAGE_SIZE
	push edx
	push NtCurrentProcess
	Call Database.EntriesList.pZwAllocateVirtualMemory
	test eax,eax
	lea edx,Database.ManagerLock
	jnz exit_
	push edx
	Call Database.EntriesList.pRtlInitializeCriticalSection
	test eax,eax
	jnz free_
	Call _$_DispatchBufferOverflow
	push eax
	push 1
	Call Database.EntriesList.pRtlAddVectoredExceptionHandler
	test eax,eax
	cld
	jz error_
	mov ecx,(MANAGER_DATABASE.BufferCount)/4
	mov Database.CalloutList,eax
	mov edi,RegionAddress
	lea esi,Database
	xor eax,eax
	mov edx,edi
	mov Database.BugBreak,eax
	mov dword ptr [Database.Breaker],00010068H
	mov dword ptr [Database.Breaker + 4],0C3F49D00H
comment '
	push EFLAGS_TF
	popfd
	hlt
	ret
	'
	rep movsd
	;stosd
	lock cmpxchg dword ptr [ebx + PbManagerDatabase],edx
	jnz error_
; Если возникнет исключение, отличное от трассировочного,
; то диспетчер исключений(KiUserExceptionDispatcher) полу
; чит управление с взведённым TF в контексте. После испол
; нения первой инструкции диспетчера возникнет трассирово
; чное исключение, диспетчер исключений вновь получит упр
; авление, TF будет сброшен. Это исключение необходимо пр
; опустить, сбросив TF и выполнив перезагрузку контекста.
; При переходе треда из ядра на диспетчер исключений оста
; нов генерируется после исполнения первой его инструкции, 
; тоесть Eip будет указывать на вторую инструкцию диспетч
; ера. Можно поступить двумя способами.
; - Статически найти адрес диспетчера исключений, который 
; экспортируется как KiUserExceptionDispatcher. В этом сл
; учае если первая инструкция диспетчера является ветвлен
; ием, то останов генерируется после ветвления и статичес
; кое определения адреса останова требует дизассемблирова
; ние и анализ первой инструкции.
; - Динамически определить адрес диспетчера посредством г
; енерации исключения с взведённым TF и обработкой его. Т
; ак как исключение является одним из событий при которых 
; на отладочный порт доставляется сообщение (если он подк
; лючен), то данный способ не является безопасным.
; Поступим втором способом.
	xor eax,eax
	assume edx:PMANAGER_DATABASE
	lea ecx,[edx].Breaker
	mov [edx].BugBreak,1
; Используем буфер в котором формируем код, генерирующий 
; останов. Использовать связку popfd/hlt в пермутирующем 
; коде нельзя, так как последовательность инструкций мож
; ет измениться и останов сработает не на инструкции Hlt.
	Call Ecx
exit_:
	ret
error_:
	lea eax,Database.ManagerLock
	push STATUS_UNSUCCESSFUL
	push eax
	Call Database.EntriesList.pRtlDeleteCriticalSection
	pop eax
free_:
	push eax
	lea ecx,RegionSize
	push MEM_RELEASE
	lea edx,RegionAddress
	push ecx
	push edx
	push NtCurrentProcess
	Call Database.EntriesList.pZwFreeVirtualMemory
	pop eax
	jmp exit_
MmInitializeMemoryManagment endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Определяет число вызовов системных сервисов.
;
QuerySystemCalls proc EntriesList:PNT_ENTRIES, EncodeMask:PVOID
Local SystemInformation:SYSTEM_PERFORMANCE_INFORMATION
	mov ecx,EntriesList
	push NULL
	lea edx,SystemInformation
	push sizeof(SYSTEM_PERFORMANCE_INFORMATION)
	push edx
	push SystemPerformanceInformation
	Call NT_ENTRIES.pZwQuerySystemInformation[ecx]
	mov ecx,EncodeMask
	test eax,eax
	mov edx,SystemInformation.SystemCalls
	.if Zero?
	mov dword ptr [ecx],edx
	.endif
	ret
QuerySystemCalls endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Создаёт расширяемый буфер.
; Хэндл буфера должен быть уникальным. Два одновременных 
; вызова не должны возвратить одинаковые значения. Для 
; этого используем число вызовов системных сервисов.
;
MmAllocateBuffer proc uses ebx esi edi SizeOfBufferReserve:ULONG, ThreadId:HANDLE, Buffer:PVOID, BufferHandle:PHANDLE
	xor eax,eax
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	lock cmpxchg dword ptr [ebx + PbManagerDatabase],eax
	jne @f
	mov eax,STATUS_UNSUCCESSFUL
	jmp exit_
@@:
	mov ebx,eax
	assume ebx:PMANAGER_DATABASE
	lea eax,[ebx].ManagerLock
	push eax
	Call [ebx].EntriesList.pRtlEnterCriticalSection
	test eax,eax
	jnz exit_
	mov ecx,DATABASE_BUFFERS_LIMIT
	lea esi,[ebx + sizeof(MANAGER_DATABASE)]
	assume esi:PBUFFER_INFORMATION
@@:
	cmp [esi].BaseAddress,eax
	je def_
	add esi,sizeof(BUFFER_INFORMATION)
	loop @b
reserr_:
	mov eax,STATUS_INSUFFICIENT_RESOURCES
	jmp leave_
def_:
	lea edi,[ebx].EntriesList
	invoke InitializeBufferInternal, Edi, SizeOfBufferReserve, ThreadId, Esi
	test eax,eax
	jnz leave_
	invoke QuerySystemCalls, edi, addr [esi].SystemCalls
	test eax,eax
	mov ecx,[esi].BaseAddress
	jnz leave_
	push [esi].SystemCalls
	mov edi,BufferHandle
	mov edx,Buffer
	pop dword ptr [edi]
	mov dword ptr [edx],ecx
	inc [ebx].BufferCount
	xor eax,eax
leave_:
	lea ecx,[ebx].ManagerLock
	push eax
	push ecx
	Call [ebx].EntriesList.pRtlLeaveCriticalSection
	pop eax
exit_:
	ret
MmAllocateBuffer endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Удаляет расширяемый буфер.
;
MmFreeBuffer proc uses ebx esi edi BufferHandle:HANDLE
Local RegionSize:ULONG
	xor eax,eax
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	lock cmpxchg dword ptr [ebx + PbManagerDatabase],eax
	jne @f
	mov eax,STATUS_UNSUCCESSFUL
	jmp exit_
@@:
	mov ebx,eax
	assume ebx:PMANAGER_DATABASE
	lea eax,[ebx].ManagerLock
	push eax
	Call [ebx].EntriesList.pRtlEnterCriticalSection
	test eax,eax
	mov esi,[ebx].BufferCount
	jnz exit_
	test esi,esi
	je error_
	mov ecx,DATABASE_BUFFERS_LIMIT
	lea edi,[ebx + sizeof(MANAGER_DATABASE)]
	assume edi:PBUFFER_INFORMATION
	mov edx,BufferHandle
entry_:
	mov eax,[edi].BaseAddress
	test eax,eax
	jz idle_
	cmp [edi].SystemCalls,edx
	je free_
	dec esi
	jz error_
idle_:
	add edi,sizeof(BUFFER_INFORMATION)
	loop entry_
	jmp error_
free_:
	lea ecx,RegionSize
	lea edx,[edi].AllocationBase
	push MEM_RELEASE
	push ecx
	push edx
	mov RegionSize,NULL
	push NtCurrentProcess
	Call [ebx].EntriesList.pZwFreeVirtualMemory
	xor eax,eax
	cld
	dec [Ebx].BufferCount
	stosd
	stosd
	stosd
	stosd
	stosd
leave_:
	lea ecx,[ebx].ManagerLock
	push eax
	push ecx
	Call [ebx].EntriesList.pRtlLeaveCriticalSection
	pop eax
exit_:
	ret
error_:
	mov eax,STATUS_INVALID_HANDLE
	jmp leave_
MmFreeBuffer endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Освобождение ресурсов менеджера и удаление ссылок.
;
MmUninitializeMemoryManagment proc uses ebx esi
Local RegionAddress:PVOID, RegionSize:ULONG
	xor eax,eax
	assume fs:nothing
	mov esi,fs:[TEB.Peb]
	lock cmpxchg dword ptr [esi + PbManagerDatabase],eax
	jne @f
	mov eax,STATUS_UNSUCCESSFUL
	jmp exit_
@@:
	mov ebx,eax
	assume ebx:PMANAGER_DATABASE
	lea eax,[ebx].ManagerLock
	push eax
	Call [ebx].EntriesList.pRtlEnterCriticalSection
	test eax,eax
	jnz exit_
	cmp [ebx].BufferCount,eax
	lea ecx,[ebx].ManagerLock
	je @f
	mov eax,STATUS_UNSUCCESSFUL
	jmp leave_
@@:
	mov eax,ebx
	xor edx,edx
	mov RegionAddress,ebx
	lock cmpxchg dword ptr [esi + PbManagerDatabase],edx
	push ecx
	Call [ebx].EntriesList.pRtlDeleteCriticalSection
	push [ebx].CalloutList
	Call [ebx].EntriesList.pRtlRemoveVectoredExceptionHandler
	lea ecx,RegionSize
	lea edx,RegionAddress
	push MEM_RELEASE
	push ecx
	push edx
	mov RegionSize,NULL
	push NtCurrentProcess
	Call [ebx].EntriesList.pZwFreeVirtualMemory
	xor eax,eax
exit_:
	ret
leave_:
	lea ecx,[ebx].ManagerLock
	push eax
	push ecx
	Call [ebx].EntriesList.pRtlLeaveCriticalSection
	pop eax
	jmp exit_
MmUninitializeMemoryManagment endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;end MmUninitializeMemoryManagment