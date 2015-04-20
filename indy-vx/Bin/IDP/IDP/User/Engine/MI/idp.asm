; o Захват разрушением указателей.
; o IDP Engine v3.0
; o Indy Clerk
; o User Mode.
; o Mutation Independent.
; o http://www.virustech.org/f/viewtopic.php?id=88
;
; \IDP\Public\User\Engine\MI\IDP.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	
	include hd.inc

PbManagerDatabase	equ (PAGE_SIZE - 4)	; Смещение указателя в PEB.

NT_ENTRIES struct
pZwSetLdtEntries				PVOID ?
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

SERVICES_LIST struct
_NtSetLdtEntries			ULONG ?
_NtAllocateVirtualMemory		ULONG ?
_NtFreeVirtualMemory		ULONG ?
SERVICES_LIST ends
PSERVICES_LIST typedef ptr SERVICES_LIST

SEGMENT_ENTRY struct
SegmentBase	PVOID ?
SegmentLimit	ULONG ?
SegmentAddress	PVOID ?	; Адрес области памяти.
Reference		PVOID ?	; Адрес переменной, ссылающейся на область памяти.
SEGMENT_ENTRY ends
PSEGMENT_ENTRY typedef ptr SEGMENT_ENTRY

MANAGER_DATABASE struct
BugBreak		ULONG ?	; Адрес второй инструкции диспетчера исключений.
Breaker		BYTE 8 DUP (?)	; Код для генерации останова.
EntriesList	NT_ENTRIES <>	; Список адресов апи.
;ServicesList	SERVICES_LIST <>
CalloutList	PVOID ?	; Указатель возвращенный RtlAddVectoredExceptionHandler().
ManagerLock	RTL_CRITICAL_SECTION <>	; Критическая секция для захвата базы данных.
SegmentCount	ULONG ?
;SegmentEntry	SEGMENT_ENTRY 1 DUP (<>)
MANAGER_DATABASE ends
PMANAGER_DATABASE typedef ptr MANAGER_DATABASE

DATABASE_BUFFERS_LIMIT equ ((PAGE_SIZE - sizeof(MANAGER_DATABASE))/sizeof(BUFFER_INFORMATION))

GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm
	
TbThreadState	equ (PAGE_SIZE - sizeof(THREAD_STATE))

MM_USER_HIGHEST_ADDRESS	equ 7FFEFFFFH	; Последняя выделенная страница 0x7FFE0000.

TABLE_MASK	equ 100B	; Тип таблицы в сегментном регистре(GDT/LDT).
RPL_MASK 		equ 011B	; RPL в сегментном регистре(UserMode).

.code
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PiEntry:
	test eax,eax
	jz IdpInitializeEngine
	dec eax
	jz IdpAddReference
	dec eax
	jz IdpAddVectoredExceptionHandler
	dec eax
	jz IdpRemoveVectoredExceptionHandler
	dec eax
	jz NtImageQueryEntryFromCrc32
	dec eax
	jz NtEncodeEntriesList
	mov eax,STATUS_INVALID_PARAMETER
	ret

	include ..\..\Bin\Graph\Mm\Img.asm
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
;
IdpAddVectoredExceptionHandler proc
	assume fs:nothing
	xor eax,eax
	mov ecx,fs:[TEB.Peb]
	lock cmpxchg dword ptr [ecx + PbManagerDatabase],eax
	jne @f
	mov eax,STATUS_UNSUCCESSFUL
	retn 2*4
@@:
	jmp MANAGER_DATABASE.EntriesList.pRtlAddVectoredExceptionHandler[eax]
IdpAddVectoredExceptionHandler endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
;
IdpRemoveVectoredExceptionHandler proc
	assume fs:nothing
	xor eax,eax
	mov ecx,fs:[TEB.Peb]
	lock cmpxchg dword ptr [ecx + PbManagerDatabase],eax
	jne @f
	mov eax,STATUS_UNSUCCESSFUL
	retn 2*4
@@:
	jmp MANAGER_DATABASE.EntriesList.pRtlRemoveVectoredExceptionHandler[eax]
IdpRemoveVectoredExceptionHandler endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
;
CreateDescriptor proc Base:PVOID, Limit:ULONG
	mov eax,Base
	mov edx,Limit
	mov ecx,eax
	and edx,0F0000H
	shr eax,16
	and ecx,0FF000000h
	and eax,0FFH
	lea edx,[eax + edx + 100H * 11110010B + 100000H * 1100B]	; Type 001B - data, R/W.
	or edx,ecx
	mov eax,Limit
	mov ecx,Base
	and eax,0FFFFH
	shl ecx,16
	lea ecx,[ecx + eax]
; Edx:Ecx
	ret
CreateDescriptor endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Создаёт дескриптор в LDT(первые 16 страниц не выделены!).
; Добавляет адрес в таблицу(индекс в ней является селектором).
;
IdpAddReference proc uses ebx esi edi Reference:PVOID, SpaceSize:ULONG
Local Address:PVOID, Database:PMANAGER_DATABASE, SegmentsList:PSEGMENT_ENTRY
	xor eax,eax
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	lock cmpxchg dword ptr [ebx + PbManagerDatabase],eax
	mov ebx,eax
	jne @f
	mov eax,STATUS_UNSUCCESSFUL
	jmp exit_
@@:
	assume ebx:PMANAGER_DATABASE
	lea ecx,[ebx].ManagerLock
	mov Database,ebx
	push ecx
	Call [ebx].EntriesList.pRtlEnterCriticalSection
	lea esi,[ebx + sizeof(MANAGER_DATABASE)]
	mov edi,Reference
	mov ecx,[ebx].SegmentCount
	mov edi,dword ptr [edi]
; Регионы не должны пересекаться!
	mov Address,edi
	cmp edi,10000H
	jna error_
	mov eax,edi
	mov edx,SpaceSize
	and edi,(PAGE_SIZE - 1)
	test edx,edx
	jz error_
	add edx,edi
	mov SegmentsList,esi
	jecxz free_
	cmp ecx,128
	jb chk_entry_
err_res_:
	mov eax,STATUS_INSUFFICIENT_RESOURCES
	jmp leave_
chk_limit_:
	assume esi:PSEGMENT_ENTRY
	cmp [esi].SegmentBase,edx
	jbe next_entry_
busy_:
	add edi,PAGE_SIZE
	dec edx
	jz err_res_
next_page_:
	mov esi,SegmentsList
	mov ecx,[ebx].SegmentCount
chk_entry_:
	cmp [esi].SegmentAddress,eax
	je redef_
	cmp [esi].SegmentBase,edi
	je busy_
	jnb chk_limit_
	cmp [esi].SegmentLimit,edi
	jnb busy_
next_entry_:
	add esi,sizeof(SEGMENT_ENTRY)
	loop chk_entry_
free_:
	mov eax,Address
	mov edx,MM_USER_HIGHEST_ADDRESS
	push esi
	sub edx,eax
	sub esi,SegmentsList
	sub eax,edi	; Base
; Limit = (HighestUserAddress - Base)/PAGE_SIZE
	shr esi,1	; /sizeof(SEGMENT_ENTRY)
	and eax,NOT(PAGE_SIZE - 1)
	shr edx,12	; Limit
	lea esi,[esi + 8 + (RPL_MASK or TABLE_MASK)]	; Sel.
	invoke CreateDescriptor, Eax, Edx	; Edx:Ecx
	push NULL
	push NULL
	push NULL
	push edx
	push ecx
	push esi
	Call [ebx].EntriesList.pZwSetLdtEntries
	pop esi
	test eax,eax
	mov ecx,Reference
	jnz leave_
	mov [esi].SegmentBase,edi
	mov [esi].Reference,ecx
	mov dword ptr [ecx],edi
	push Address
	inc [ebx].SegmentCount
	pop [esi].SegmentAddress
redef_:
	mov edx,SpaceSize
	xor eax,eax
	add edx,edi
	mov [esi].SegmentLimit,edx
leave_:
	lea ecx,[ebx].ManagerLock
	push eax
	push ecx
	Call [ebx].EntriesList.pRtlLeaveCriticalSection
	pop eax
exit_:
	ret
error_:
	mov eax,STATUS_INVALID_PARAMETER
	jmp leave_
IdpAddReference endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Eax - опкод.
; Ecx - последний префикс переопределения сегмента.
;
IdpIsMovsOpcode proc uses ebx esi edi Address:PVOID
Local InstructionLength:ULONG
Local PrefixTable[3*4]:BYTE
	mov esi,Address
	xor ebx,ebx
	mov InstructionLength,16 + 1
	mov dword ptr [PrefixTable],6766F2F0H	; AddrSize, DataSize, Repnz, Lock
	mov dword ptr [PrefixTable + 4],363E2EF3H	; Ss, Ds, Cs, Rep
	mov dword ptr [PrefixTable + 2*4],00656426H	; Gs, Fs, Es
	lea edx,PrefixTable
@@:
	dec InstructionLength
	jz error_
	lodsb
	mov edi,edx
	mov ecx,11
	repne scasb
	jne @f
	cmp ecx,6
	jnb @b
	movzx ebx,al
	jmp @b
@@:
	mov edx,eax
	sub al,0A4H	; movsb
	jz @f
	dec al	; movsd
	jnz error_
@@:
	mov eax,edx
exit_:
	mov ecx,ebx
	ret
error_:
	xor eax,eax
	jmp exit_
IdpIsMovsOpcode endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ACCESS_TYPE_READ	equ 0
ACCESS_TYPE_WRITE	equ 1
; +
; VEH
;
_$_IdpDispatchException:
	GET_CURRENT_GRAPH_ENTRY
IdpDispatchException proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local AccessType:ULONG
	assume fs:nothing
	mov edx,ExceptionPointers
	xor eax,eax
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[edx]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[edx]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	mov ebx,fs:[TEB.Peb]
	jnz chain_
	lock cmpxchg dword ptr [ebx + PbManagerDatabase],eax
	je chain_
	mov ebx,eax
	assume ebx:PMANAGER_DATABASE
	lea ecx,[ebx].ManagerLock
	push ecx
	Call [ebx].EntriesList.pRtlEnterCriticalSection
; Контекст всегда полный, не проверяем.
	cmp [esi].ExceptionCode,STATUS_ACCESS_VIOLATION
	jne is_trap_
; [ExceptionInformation]:
; +0 Тип доступа к памяти(0 - чтение, 1 - запись).
; +4 Адрес к которому произошло обращение.
	cmp [esi].ExceptionInformation,ACCESS_TYPE_READ
	mov eax,[esi].ExceptionInformation + 4
	setnz cl
	cmp [esi].NumberParameters,2
	movzx ecx,cl
	jne chain_leave_
	mov AccessType,ecx
	cmp eax,10000H
	jnb chain_leave_
	mov ecx,[ebx].SegmentCount
	lea esi,[ebx + sizeof(MANAGER_DATABASE)]
	mov edx,eax
; Индекс элемента является селектором.
	jecxz chain_leave_
	assume esi:PSEGMENT_ENTRY
@@:
	cmp [esi].SegmentBase,eax
	ja next_
	cmp [esi].SegmentLimit,eax
	ja @f
next_:
	add esi,sizeof(SEGMENT_ENTRY)
	loop @b
	jmp chain_leave_
chain_:
	xor eax,eax
	jmp exit_
@@:
	sub edx,eax
	push [edi].regEFlags
	or [edi].regEFlags,EFLAGS_TF
	pop fs:[THREAD_STATE.rEFlags + TbThreadState]
	mov fs:[THREAD_STATE.Entry + TbThreadState],esi
	lea esi,[edx*8 + 8 + (RPL_MASK or TABLE_MASK)]
	invoke IdpIsMovsOpcode, [edi].regEip
	test eax,eax
	jnz @f
; Не сохраняем сегментные регистры, а по возврату восстановим дефолтные значения.
; Иначе следует сохранить их в TEB, а при возврате загрузить в контекст.
	mov [edi].regSegFs,esi
	mov [edi].regSegGs,esi
	mov [edi].regSegEs,esi
	mov [edi].regSegDs,esi
	jmp break_
@@:
; (DS):[SI] -> ES:[DI]
	cmp AccessType,ACCESS_TYPE_READ
	je @f
; Значение Edi/Esi не проверяем.
	mov [edi].regSegEs,esi
break_:
	mov eax,ExceptionPointers
	mov eax,EXCEPTION_POINTERS.ExceptionRecord[eax]
	mov EXCEPTION_RECORD.ExceptionCode[eax],IDP_BREAKPOINT
chain_leave_:
	xor eax,eax
leave_:
	lea ecx,[ebx].ManagerLock
	push eax
	push ecx
	Call [ebx].EntriesList.pRtlLeaveCriticalSection
	pop eax
exit_:
	ret
@@:
	test ecx,ecx
	mov [edi].regSegDs,esi
	jz break_
; Сегмент переопределён.
	cmp cl,PREFIX_ES
	jne @f
	mov [edi].regSegEs,esi
	jmp break_
@@:
	mov [edi].regSegFs,esi
	mov [edi].regSegGs,esi
	jmp break_
is_trap_:
	assume esi:PEXCEPTION_RECORD
	cmp [esi].ExceptionCode,STATUS_SINGLE_STEP
	jne is_break_
; Если возникнет исключение, отличное от трассировочного, 
; то диспетчер исключений(KiUserExceptionDispatcher) получит 
; управление с взведённым TF в контексте. После исполнения 
; первой инструкции диспетчера возникнет трассировочное 
; исключение, диспетчер исключений вновь получит управление, 
; TF будет сброшен. Это исключение необходимо пропустить, 
; сбросив TF. Иначе сторонний VEH будет выполнять трассировку 
; диспетчера исключений до повторного входа в критическую 
; секцию, после чего возникнет деадлок.
	mov eax,[ebx].BugBreak
	mov ecx,[esi].ExceptionAddress
	test eax,eax
	lea edx,[ebx].Breaker
	je not_bug_
	cmp eax,1
	je @f
	cmp eax,ecx
	jne not_bug_
	jmp load_
@@:
	cmp ecx,edx
	jb @f
	add edx,8
	cmp ecx,edx
	jb chain_leave_
@@:
	mov [ebx].BugBreak,ecx
load_:
	and [edi].regEFlags,NOT(EFLAGS_TF)
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp leave_
not_bug_:
	cmp fs:[THREAD_STATE.rEFlags + TbThreadState],0
	je chain_leave_
	push fs:[THREAD_STATE.rEFlags + TbThreadState]
	mov fs:[THREAD_STATE.rEFlags + TbThreadState],0
	mov [esi].ExceptionCode,IDP_SINGLE_STEP
	mov [edi].regSegGs,0
	mov [edi].regSegFs,KGDT_R3_TEB or RPL_MASK
	mov [edi].regSegEs,KGDT_R3_DATA or RPL_MASK
	mov [edi].regSegDs,KGDT_R3_DATA or RPL_MASK
	pop [edi].regEFlags
	jmp chain_leave_
is_break_:
	cmp [esi].ExceptionCode,STATUS_PRIVILEGED_INSTRUCTION	; (Hlt)
	jne chain_leave_
	lea eax,[ebx].Breaker + 6
	cmp [esi].ExceptionAddress,eax	; ExceptionAddress = Eip
	jne chain_leave_
	inc [edi].regEip
	jmp load_
IdpDispatchException endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Инициализация.
;
IdpInitializeEngine proc uses ebx esi edi
Local Database:MANAGER_DATABASE
Local DatabaseAddress:PVOID, DatabaseSize:ULONG
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor eax,eax
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	lock cmpxchg dword ptr [ebx + PbManagerDatabase],eax
	lea ecx,Database.EntriesList
	je @f
	mov eax,STATUS_UNSUCCESSFUL
	jmp exit_
@@:
	push ecx
	xor eax,eax
	lea edi,Database.EntriesList
	sub eax,0D668E0A5H
	push edi
	cld
	stosd
	xor eax,0F1B7BA2FH
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
	push eax	; PartialCrc
	push eax
	Call NtEncodeEntriesList
	test eax,eax
	mov DatabaseSize,128*4 + sizeof(MANAGER_DATABASE)	; Определяется пределом LDT.
	jnz exit_
	mov DatabaseAddress,eax
	;invoke NtQueryServicesList, addr Database.EntriesList, addr Database.ServicesList, sizeof(SERVICES_LIST)/4
	lea ecx,DatabaseAddress
	lea edx,DatabaseSize
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT
	push edx
	push 0
	;mov eax,Database.ServicesList._NtAllocateVirtualMemory
	push ecx
	;test eax,eax
	push NtCurrentProcess
	;.if Zero?
	Call Database.EntriesList.pZwAllocateVirtualMemory
	;.else
	;mov edx,esp
	;Int 2EH	; NtAllocateVirtualMemory
	;lea esp,[esp + 6*4]
	;.endif
	test eax,eax
	lea edx,Database.ManagerLock
	jnz exit_
	push edx
	Call Database.EntriesList.pRtlInitializeCriticalSection
	test eax,eax
	jnz free_
	Call _$_IdpDispatchException
	push eax
	push 1
	Call Database.EntriesList.pRtlAddVectoredExceptionHandler
	test eax,eax
	cld
	jz error_
	mov ecx,sizeof(MANAGER_DATABASE)/4 - 4
	mov Database.CalloutList,eax
	mov edi,DatabaseAddress
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
	jne error_
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
	jmp exit_
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
exit_:
	Call SEH_Epilog
	ret
error_:
	lea eax,Database.ManagerLock
	push STATUS_UNSUCCESSFUL
	push eax
	Call Database.EntriesList.pRtlDeleteCriticalSection
	pop eax
free_:
	push eax
	lea ecx,DatabaseSize
	push MEM_RELEASE
	lea edx,DatabaseAddress
	push ecx
	push edx
	push NtCurrentProcess
	Call Database.EntriesList.pZwFreeVirtualMemory
	pop eax
	jmp exit_
IdpInitializeEngine endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
end IdpInitializeEngine