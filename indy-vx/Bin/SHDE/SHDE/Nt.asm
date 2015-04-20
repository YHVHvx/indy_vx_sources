; o Валидация ядерной SFC для определения наличия фильтров.
; 
; Первый адрес на стеке ядра это kss60, инструкция следующая за процедурным ветвлением kssdoit, вызывающим NT-вектор. Второй адрес 
; принадлежит телу NTAPI. Модель вызова сервисов(KiSystemService()/KiFastCallEntry()) не изменяется. Если вектор в SST направлен в 
; фильтр, либо начало сервиса пропатчено(сплайсинг), то второй адрес будет принадлежать не NTAPI, а фильтру. Возможно что фильтров 
; несколько, в этом случае SFC удлинится. Возможно фильтр не стоит на NTAPI, а находится глубже, например в менеджере обьектов. В 
; этом случае он не следит за вызов сервисов непосредственно(eg.: DrWeb ставит фильтр на OBTYPE.OpenProcedure). Однозначно определ
; ить NTAPI-фильтр можно только первый. Косвенная фильтрация не может служить для однозначной детекции.
; 
; Фильтр может быть установлен в юзермоде на ZWAPI, системном шлюзе(KiFastSystemCall()) etc. В таком случае вызов сервисов через с
; табы даст детект. Можно выполнить проверку пользовательской SFC и обнаружить фильтр. При его обнаружении придётся вызывать апи н
; е через стабы, посему не будем их использовать, а будем вызывать сервисы через свой шлюз.
; 
; В многопоточном приложении непрерывно накапливается лог. Найти вход в нём, который был сохранён при вызове тестовой NTAPI можно 
; по описателю обьекта, CID-у или адресу в SFC. Для NTAPI создающих описатель, поиск входа возможен по созданному описателю(HANDLE
; _TRACE_DB_OPEN). Так как логгер может быть запущен ранее, то в логе могут быть описатели со значением вновь созданного. Отличить 
; такие события можно по адресу в SFC. При этом не закрывается описатель, а выполняется вызов следующей NTAPI, создающей описатель.
; 
; Прочие NTAPI, которые описатели не создают, анализируем по событию HANDLE_TRACE_DB_BADREF. При этом генерируется #STATUS_INVALID
; _HANDLE посредством KiRaiseUserExceptionDispatcher(). Значение описателя должно быть < 0x80000000(!KERNEL_HANDLE_MASK). На каждо
; й итерации изменяем значение описателя и по нему находим событие в логе.
;
; ; NtQuerySecurityObject
; - obtype ???

KERNEL_HANDLE_MASK	equ 80000000H

%NTCALL macro
	Call ApiGate
endm

ifdef OPT_ENABLE_DBG
	GATE$	CHAR "GATE_FAILED: DB: 0x%p, STATUS: 0x%p", 13, 10, 0
endif

ApiGate proc C
	assume ebx:PSYSENTRY
	xchg dword ptr [esp],edi
	movzx eax,[ebx].Id
	mov edx,esp
SYSGATE::
	Int 2EH
SYSGATERET::
	.if Eax != STATUS_INVALID_HANDLE
		ifdef OPT_ENABLE_DBG
			pushad
			invoke DbgPrint, addr GATE$, Edi, Eax
			popad
		endif
		or [ebx].Flags,FLG_ANALYSIS_FAILURE
	.endif
	xchg dword ptr [esp],edi
	movzx ecx,[ebx].Args
	mov edx,dword ptr [esp]	; Ip
	add edi,4	; Handle
	add ebx,sizeof(SYSENTRY)
	add esp,ecx
; Eax: NTSTATUS
	jmp edx
ApiGate endp

%NTCALL2 macro
	Call ApiGate2
endm

ApiGate2 proc C
	assume ebx:PSYSENTRY
	movzx eax,[ebx].Id
	lea edx,[esp + 4]
	mov OBJECT_ATTRIBUTES.uLength[esi],sizeof(OBJECT_ATTRIBUTES)
	mov OBJECT_ATTRIBUTES.hRootDirectory[esi],edi
SYSGATE2::
	Int 2EH
SYSGATERET2::
	.if Eax != STATUS_INVALID_HANDLE
		ifdef OPT_ENABLE_DBG
			pushad
			invoke DbgPrint, addr GATE$, Edi, Eax
			popad
		endif
		or [ebx].Flags,FLG_ANALYSIS_FAILURE
	.endif
	pop ecx	; Ip
	movzx edx,[ebx].Args
	add edi,4	; Handle
	add esp,edx
	add ebx,sizeof(SYSENTRY)
; Eax: NTSTATUS
	jmp ecx
ApiGate2 endp

ifdef OPT_ENABLE_DBG
	GATE3$	CHAR "GATE_FAILED: 0x%p", 13, 10, 0
endif

%NTCALL3 macro
	Call ApiGate3
endm

ApiGate3 proc C
	assume esi:PSYSENTRY
	movzx eax,[esi].Id
	lea edx,[esp + 4]
SYSGATE3::
	Int 2EH
SYSGATERET3::
	.if Eax
		ifdef OPT_ENABLE_DBG
			pushad
			invoke DbgPrint, addr GATE3$, Eax
			popad
		endif
		or [esi].Flags,FLG_ANALYSIS_FAILURE
	.endif
	pop ecx	; Ip
	movzx edx,[esi].Args
	add esp,edx
; Eax: NTSTATUS
	jmp ecx
ApiGate3 endp

GenerateBadrefLog proc uses ebx esi edi Info:PSYSENTRY
Local Buffer[500H]:BYTE
	lea esi,Buffer
	mov edi,BADREF_MAGIC_BASE
	mov ebx,Info
	assume ebx:PSYSENTRY
; NtQueryInformationProcess
	push NULL
	push sizeof(PROCESS_BASIC_INFORMATION)
	push esi
	push ProcessBasicInformation
	%NTCALL
; NtSetInformationProcess
	mov dword ptr [esi],1
	push sizeof(KAFFINITY)
	push esi
	push ProcessAffinityMask
	%NTCALL
	push 7
	.repeat
; NtSuspendProcess
; NtResumeProcess
; NtAlertThread
; NtFlushKey
; NtDeleteKey
; NtCompleteConnectPort
; NtMakeTemporaryObject
		%NTCALL
		dec dword ptr [esp]
	.until Zero?
	add esp,4
; NtQueryInformationThread
	push NULL
	push sizeof(THREAD_BASIC_INFORMATION)
	push esi
	push ThreadBasicInformation
	%NTCALL
; NtSetInformationThread
	push sizeof(KAFFINITY)
	push esi
	push ThreadAffinityMask
	%NTCALL
	push 8
	.repeat
; NtTerminateProcess
; NtSuspendThread
; NtResumeThread
; NtGetContextThread
; NtSetContextThread
; NtTerminateThread
; NtUnmapViewOfSection
; NtExtendSection
		push esi
		%NTCALL
		dec dword ptr [esp]
	.until Zero?
	add esp,4
; NtQueueApcThread
	push NULL
	push NULL
	push NULL
	push esi
	%NTCALL
; NtImpersonateThread
	push esi
	push edi
	%NTCALL
; NtAllocateVirtualMemory
	mov dword ptr [esi],X86_PAGE_SIZE
	mov dword ptr [esi + 4],NULL
	lea ecx,dword ptr [esi + 4]
	push PAGE_READWRITE
	push MEM_COMMIT
	push esi
	push 0
	push ecx
	%NTCALL
; NtProtectVirtualMemory
	lea ecx,dword ptr [esi + 4]
	mov dword ptr [esi + 4],edi
	push esi
	push PAGE_READWRITE
	push esi
	push ecx
	%NTCALL
; NtFlushVirtualMemory
	lea ecx,dword ptr [esi + 4]
	push esi
	push esi
	push ecx
	%NTCALL
; NtFreeVirtualMemory
	push MEM_RELEASE
	push esi
	push esi
	%NTCALL
; NtQueryVirtualMemory
	push NULL
	push sizeof(MEMORY_BASIC_INFORMATION)
	push esi
	push MemoryBasicInformation
	push esi
	%NTCALL
; NtReadVirtualMemory
	push NULL
	push 4
	push esi
	push edi
	%NTCALL
; NtWriteVirtualMemory
	push NULL
	push 4
	push esi
	push edi
	%NTCALL
; NtAllocateUserPhysicalPages
	mov dword ptr [esi],4
	push esi
	push esi
	%NTCALL
; NtFreeUserPhysicalPages
	push esi
	push esi
	%NTCALL
; NtQuerySection
	push NULL
	push sizeof(SECTION_BASIC_INFORMATION)
	push esi
	push SectionBasicInformation
	%NTCALL
; NtMapViewOfSection
	push PAGE_READWRITE
	push 0
	push ViewShare
	push esi	; IN OUT PULONG ViewSize
	push NULL	; IN OUT PLARGE_INTEGER SectionOffset OPTIONAL
	push X86_PAGE_SIZE	; CommitSize
	push 0
	push esi	; IN OUT PVOID *BaseAddress
	push NtCurrentProcess
	mov dword ptr [esi],NULL
	%NTCALL
; NtQuerySecurityObject
	push esi	; OUT PULONG ReturnLength
	push 0	; IN ULONG SecurityDescriptorLength
	push NULL	; OUT PSECURITY_DESCRIPTOR SecurityDescriptor
	push DACL_SECURITY_INFORMATION
	%NTCALL
; NtSetSecurityObject
	push esi
	push OWNER_SECURITY_INFORMATION
	%NTCALL
; NtQueryDirectoryObject
	push NULL	; OUT PULONG ReturnLength OPTIONAL
	push esi	; IN OUT PULONG Context
	push FALSE; IN BOOLEAN RestartScan
	push TRUE	; IN BOOLEAN ReturnSingleEntry
	push 0	; IN ULONG BufferLength
	push esi	; OUT PVOID Buffer
	%NTCALL
; NtPrivilegeCheck
	push FALSE
	push esi
	%NTCALL
; NtQueryObject
	push NULL
	push sizeof(OBJECT_BASIC_INFORMATION)
	push esi
	push ObjectBasicInformation
	%NTCALL
; NtQueryInformationToken
	push esi
	push sizeof(TOKEN_USER)
	push esi
	push TokenUser
	%NTCALL
; NtSetInformationToken
	push sizeof(TOKEN_OWNER)
	push esi
	push TokenOwner
	%NTCALL
; NtAdjustPrivilegesToken
	push NULL
	push NULL
	push sizeof(TOKEN_PRIVILEGES)
	push esi
	push FALSE
	%NTCALL
; NtDuplicateObject
	push DUPLICATE_SAME_ACCESS or DUPLICATE_SAME_ATTRIBUTES
	push 0
	push 0
	push esi
	push edi
	push edi
	%NTCALL
; NtAlertResumeThread
	push NULL
	%NTCALL
; NtFlushInstructionCache
	push 4
	push esi
	%NTCALL
; NtImpersonateClientOfPort
	xor eax,eax
	mov PORT_MESSAGE.MessageSize[esi],sizeof(PORT_MESSAGE)
	push esi
	mov PORT_MESSAGE.MessageType[esi],LPC_NEW_MESSAGE
	mov PORT_MESSAGE.VirtualRangesOffset[esi],ax
	mov PORT_MESSAGE.DataSize[esi],ax
	mov PORT_MESSAGE.SectionSize[esi],eax
	mov PORT_MESSAGE.MessageId[esi],1
	mov ecx,fs:[TEB.Cid.UniqueProcess]
	mov edx,fs:[TEB.Cid.UniqueThread]
	mov PORT_MESSAGE.ClientId.UniqueProcess[esi],ecx
	mov PORT_MESSAGE.ClientId.UniqueThread[esi],edx
	%NTCALL
	push 4
	.repeat
; NtListenPort
; NtRequestPort
; NtReplyPort
; NtReplyWaitReplyPort
		push esi
		%NTCALL
		dec dword ptr [esp]
	.until Zero?
	add esp,4
; NtRequestWaitReplyPort
	push esi
	push esi
	%NTCALL
; NtReplyWaitReceivePort
	push esi
	push NULL
	push 0
	%NTCALL
; NtReplyWaitReceivePortEx
	push esi	; IN PLARGE_INTEGER Timeout
	push esi	; OUT PPORT_MESSAGE Message
	push NULL	; IN PPORT_MESSAGE ReplyMessage OPTIONAL
	push 0	; OUT PULONG PortIdentifier OPTIONAL
	%NTCALL
; NtReadRequestData
	push NULL	; OUT PULONG ReturnLength OPTIONAL
	push 4	; IN ULONG BufferLength
	push esi	; OUT PVOID Buffer
	push 0	; IN ULONG Index
	push esi	; IN PPORT_MESSAGE Message
	mov PORT_MESSAGE.VirtualRangesOffset[esi],1
	%NTCALL
; NtWriteRequestData
	push NULL	; OUT PULONG ReturnLength OPTIONAL
	push 4	; IN ULONG BufferLength
	push esi	; OUT PVOID Buffer
	push 0	; IN ULONG Index
	push esi	; IN PPORT_MESSAGE Message
	%NTCALL
; NtQueryKey
	push esi
	push sizeof(KEY_BASIC_INFORMATION) + MAX_PATH*2
	push esi
	push KeyBasicInformation
	%NTCALL
; NtDeleteValueKey
	lea ecx,[esi + sizeof(UNICODE_STRING)]
	push esi
	mov dword ptr [esi],00080006H
	mov UNICODE_STRING.Buffer[esi],ecx
	mov dword ptr [ecx],0
	%NTCALL
; NtSetValueKey
	push 4
	push esi
	push REG_DWORD
	push 0
	push esi	; IN PUNICODE_STRING ValueName
	%NTCALL
; NtQueryValueKey
	push esi
	push sizeof(KEY_VALUE_BASIC_INFORMATION) + MAX_PATH*2
	push esi
	push KeyValueBasicInformation
	push esi
	%NTCALL
; NtSetInformationKey
	push sizeof(KEY_USER_FLAGS_INFORMATION)
	push esi
	push KeyUserFlagsInformation
	%NTCALL
; NtEnumerateKey
	push esi
	push sizeof(KEY_BASIC_INFORMATION) + MAX_PATH*2
	push esi
	push KeyBasicInformation
	push 0
	%NTCALL
; NtEnumerateValueKey
	push esi
	push sizeof(KEY_VALUE_BASIC_INFORMATION) + MAX_PATH*2
	push esi
	push KeyValueBasicInformation
	push 0
	%NTCALL
; NtNotifyChangeKey
	push FALSE; IN BOOLEAN Asynchronous
	push 4	; IN ULONG BufferLength
	push esi	; IN PVOID Buffer
	push FALSE; IN BOOLEAN WatchSubtree
	push REG_NOTIFY_CHANGE_ATTRIBUTES	; IN ULONG NotifyFilter
	push esi	; OUT PIO_STATUS_BLOCK IoStatusBlock
	push NULL	; IN PVOID ApcContext OPTIONAL
	push NULL	; IN PIO_APC_ROUTINE ApcRoutine OPTIONAL
	push edi	; IN HANDLE EventHandle
	%NTCALL
; NtOpen*
	xor eax,eax
	lea ecx,[esi + sizeof(OBJECT_ATTRIBUTES)]
	lea edx,[esi + sizeof(OBJECT_ATTRIBUTES) + sizeof(UNICODE_STRING)]
	assume esi:POBJECT_ATTRIBUTES
	mov [esi].pSecurityDescriptor,eax
	mov [esi].pSecurityQualityOfService,eax
	mov [esi].uAttributes,eax
	mov [esi].pObjectName,ecx
	mov UNICODE_STRING.Buffer[ecx],edx
	mov dword ptr [ecx],00040002H
	mov dword ptr [edx],"D"
	push 3
	.repeat
; NtOpenSection
; NtOpenDirectoryObject
; NtOpenSymbolicLinkObject
		push esi
		push 1
		push esi
		%NTCALL2
		dec dword ptr [esp]
	.until Zero?
	add esp,4
; NtOpenThreadToken
	push esi
	push FALSE
	push GENERIC_READ
	push edi
	%NTCALL2
; NtOpenThreadTokenEx
	push esi
	push 0
	push FALSE
	push GENERIC_READ
	push edi
	%NTCALL2
	ret
GenerateBadrefLog endp