; Создание слепка для WSPSocket на NL = 2.
;
; (c) Indy, 2011.
;
; Многоуровневый граф, так как NL не фиксирован. Поиск ссылки для маршрутизации выполняется в одноуровневом графе.
; В связи с этим можно поступить следующим образом:
; o Найти начало процедуры и описать её графом на !NL.
; o Конвертировать граф в линейный.
; o Трассировать на !NL.
; Используется последний способ. Расширяемый буфер не используется.
;
.code
	assume eax:nothing, ecx:nothing, edx:nothing, ebx:nothing, esi:nothing, edi:nothing

OP_MOVS	equ 0A5H

CALLBACK_DATA struct
pIsSameImage	PVOID ?
Data			PVOID ?
CALLBACK_DATA ends
PCALLBACK_DATA typedef ptr CALLBACK_DATA

; o GCBE_PARSE_SEPARATE
;
xWspQuerySockProcTableTraceCallback:
	%GET_CURRENT_GRAPH_ENTRY
WspQuerySockProcTableTraceCallback proc uses ebx esi edi GpEntry:PVOID, ClbkData:PCALLBACK_DATA
	mov edi,GpEntry
	assume edi:PBLOCK_HEADER
	test dword ptr [edi + EhEntryType],TYPE_MASK
	mov ebx,[edi].Address
	jne Next
; Line
	cmp byte ptr [ebx],0BEH	; mov esi,offset SockProcTable
	jne Next
	mov eax,[edi].Link.Flink
	assume eax:PBLOCK_HEADER
	and eax,NOT(TYPE_MASK)
	mov ecx,[eax].Address
	test dword ptr [eax + EhEntryType],TYPE_MASK
	jne Next
	cmp [eax]._Size,2
	jne Next
	cmp word ptr [ecx],PREFIX_REP or (OP_MOVS shl 8)	; rep movsd
	jne Next
	mov ebx,dword ptr [ebx + 1]	; @SockProcTable
	mov esi,ClbkData
	assume esi:PCALLBACK_DATA
	push ecx
	push ebx
	Call [esi].pIsSameImage	; NtAreMappedFilesTheSame
	test eax,eax
	jnz Next	; STATUS_NOT_SAME_DEVICE/STATUS_INVALID_ADDRESS
Back:
	mov edi,[edi].Link.Blink
	and edi,NOT(TYPE_MASK)
	jz Next
	test dword ptr [edi + EhEntryType],TYPE_MASK
	mov eax,[edi].Address
	jnz Next
	cmp byte ptr [eax],0B9H	; mov ecx,#
	jne @f
	cmp dword ptr [eax + 4],30
	jne Next
Store:
	mov [esi].Data,ebx
	mov eax,STATUS_MORE_ENTRIES
	jmp Exit	
@@:
	cmp byte ptr [eax],59H	; pop ecx
	jne Back
	mov edi,[edi].Link.Blink
	and edi,NOT(TYPE_MASK)
	jz Next
	cmp [edi]._Size,2
	mov eax,[edi].Address
	jne Next
	cmp word ptr [eax],1E6AH	; push byte 30
	je Store
Next:
	xor eax,eax
Exit:
	ret
WspQuerySockProcTableTraceCallback endp

; o GCBE_PARSE_SEPARATE
;
xWspParseWSPSocketTraceCallback:
	%GET_CURRENT_GRAPH_ENTRY
WspParseWSPSocketTraceCallback proc uses ebx esi edi GpEntry:PVOID, ClbkData:PCALLBACK_DATA
	mov ebx,GpEntry
	assume ebx:PBLOCK_HEADER
	test dword ptr [ebx + EhEntryType],TYPE_MASK
	mov esi,[ebx].Address
	jne Next
; Line
	cmp byte ptr [esi],68H	; push PWCHAR "\Device\Afd\Endpoint"
	jne Next
	push esi
	mov edi,ClbkData
	assume edi:PCALLBACK_DATA
	mov esi,dword ptr [esi + 1]	; PWCHAR 
	push esi
	Call [edi].pIsSameImage
	test eax,eax
	lea ecx,[esi + 28H]
	jnz Next
	push ecx
	push esi
	Call [edi].pIsSameImage
	test eax,eax
	jnz Next
	invoke LdrCalculateHash, Eax, Esi, 28H
	cmp eax,3E2B0DF4H	; HASH("\Device\Afd\Endpoint")
	jne Next
Scan:
	mov ebx,[ebx].Link.Flink
	and ebx,NOT(TYPE_MASK)
	jz Next
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	cmp eax,HEADER_TYPE_CALL
	jne Scan
	assume ebx:PCALL_HEADER
	mov eax,[ebx].Address
	cmp word ptr [eax],015FFH
	jne Next
	mov eax,dword ptr [eax + 2]
	mov eax,dword ptr [eax]	; @RtlInitUnicodeString
	cmp [edi].Data,eax
	jne Next
	mov [edi].Data,ebx
	mov eax,STATUS_MORE_ENTRIES
	jmp Exit
Next:
	xor eax,eax
Exit:
	ret
WspParseWSPSocketTraceCallback endp

Public DBG_WSP_LdrLoadDll
Public DBG_WSP_PARSE_WSPStartup
Public DBG_WSP_TRACE_WSPStartup
Public DBG_WSP_PARSE_WSPSocket
Public DBG_WSP_TRACE_WSPSocket
Public DBG_WSP_QUERY_ENTRY

; +
; Цикл быстрой очистки ACCESSED_MASK_FLAG.
; Данная манипуляция оптимизирует анализ графа.
; Иначе трассировку графа нельзя прерывать.
;
GpCleaningCycle proc Snapshot:PGP_SNAPSHOT
	mov eax,Snapshot
	mov ecx,GP_SNAPSHOT.GpLimit[eax]
	mov eax,GP_SNAPSHOT.GpBase[eax]
@@:
	and dword ptr [eax + EhAccessFlag],NOT(ACCESSED_MASK_FLAG)
	add eax,ENTRY_HEADER_SIZE
	cmp eax,ecx
	jb @b
	xor eax,eax
	ret
GpCleaningCycle endp

; +
; Поиск, создание слепка и валидация WSPSocket().
;
; o Счётчик ссылок модуля в случае успеха инкрементирован.
; o Анализ графа не в конструкторе.
; o Не линейный граф.
; o Макро не используется(GCBE_PARSE_SEPARATE).
; o Граф не освобождается, далее он используется при маршрутизации.
; o Буфер фиксированного размера(не расширяется).
; o Валидация ссылок в NtAreMappedFilesTheSame.
; o Загрузка образа посредством LdrLoadDll(). Релокация(загрузка ориг. модуля по другой базе) не используется.
; o STPT не используется.
; o Извлечение базы нтдлл из LDR.
; 
WspInitialize proc uses ebx esi edi Apis:PAPIS, Result:PWSP_PARSE_DATA
Local $WsName[12]:CHAR, WsName:UNICODE_STRING
Local WsHandle:PVOID, Wsp[2]:PVOID
Local GpSize:ULONG, Snapshot:GP_SNAPSHOT
Local ClbkData:CALLBACK_DATA, Gp:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor eax,eax
	mov ebx,Apis
	assume ebx:PAPIS
	mov Snapshot.GpBase,eax
	mov GpSize,50H * X86_PAGE_SIZE	; ~30 pages
	lea ecx,GpSize
	lea edx,Snapshot.GpBase
	push PAGE_READWRITE
	push MEM_COMMIT
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	Call [ebx].pZwAllocateVirtualMemory
	test eax,eax
	mov esi,Snapshot.GpBase
	jnz Exit
	add Snapshot.GpBase,04FH * X86_PAGE_SIZE
	mov GpSize,X86_PAGE_SIZE
	lea eax,Snapshot.GpLimit	; Old protect.
	lea ecx,GpSize
	lea edx,Snapshot.GpBase
	push eax
	push PAGE_NOACCESS
	push ecx
	push edx
	push NtCurrentProcess
	Call [ebx].pZwProtectVirtualMemory
	test eax,eax
	mov Snapshot.GpLimit,esi
	mov Snapshot.GpBase,esi
	jnz Free
	lea ecx,$WsName
	lea edx,WsName
	mov dword ptr [$WsName],"swsm"
	push ecx
	mov dword ptr [$WsName + 4],".kco"
	push edx
	mov dword ptr [$WsName + 2*4],"lld"
	Call [ebx].pRtlCreateUnicodeStringFromAsciiz	; "mswsock.dll"
	test eax,eax
	lea ecx,WsHandle
	lea edx,WsName
	.if Zero?
	   mov eax,STATUS_INVALID_PARAMETER
	   jmp Free
	.endif
	push ecx
	push edx
	push NULL
	push NULL
DBG_WSP_LdrLoadDll::
	Call [ebx].pLdrLoadDll
	lea ecx,WsName
	push eax
	push ecx
	Call [ebx].pRtlFreeUnicodeString
	pop eax
	mov Wsp[0],60F8831FH	; HASH("WSPStartup")
	test eax,eax
	mov Wsp[4],eax
	jnz Free
	invoke LdrEncodeEntriesList, WsHandle, 0, addr Wsp
	test eax,eax
	lea ecx,Snapshot.GpLimit
	jnz Unload
	push eax
	push eax
	push eax
	push eax
	push eax
	push eax	; !NL
	push GCBE_PARSE_IPCOUNTING or GCBE_PARSE_SEPARATE
	push ecx
	push Wsp[0]
DBG_WSP_PARSE_WSPStartup::
; Выполняем анализ далее посредством трассировки.
; Конструктор заполняет граф частями, на этом этапе анализ затруднителен.
	%GPCALL GP_PARSE	; !OPT_EXTERN_SEH_MASK - расширяемый буфер не используем.
	test eax,eax
	lea ecx,ClbkData
	mov edx,[ebx].pZwAreMappedFilesTheSame
	jnz Unload	; #AV etc.
	mov ClbkData.Data,eax
	mov ClbkData.pIsSameImage,edx
; Граф не линейный, только трассировка, не последовательный перебор.
	push ecx
	%GET_GRAPH_ENTRY xWspQuerySockProcTableTraceCallback
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push esi
DBG_WSP_TRACE_WSPStartup::
	%GPCALL GP_TRACE
	test eax,eax
	mov ecx,ClbkData.Data
	jz Error
	cmp eax,STATUS_MORE_ENTRIES
	jne Unload
	mov edi,dword ptr [ecx + 28*4]	; WSPSocket()
	push WsHandle
	push edi
	Call [ebx].pZwAreMappedFilesTheSame
	test eax,eax
	lea ecx,Snapshot.GpLimit
	jnz Unload
	mov Snapshot.GpLimit,esi
	push eax
	push eax
	push eax
	push eax
	push eax
	push 2	; NL
	push GCBE_PARSE_IPCOUNTING or GCBE_PARSE_SEPARATE
	push ecx
	push edi
DBG_WSP_PARSE_WSPSocket::
	%GPCALL GP_PARSE	; !OPT_EXTERN_SEH_MASK
	test eax,eax
	lea ecx,ClbkData
	mov edx,[ebx].pRtlInitUnicodeString
	jnz Unload
	mov Snapshot.Ip,edi
	mov ClbkData.Data,edx
	push ecx
	%GET_GRAPH_ENTRY xWspParseWSPSocketTraceCallback
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push esi
DBG_WSP_TRACE_WSPSocket::
	%GPCALL GP_TRACE
	test eax,eax
	jz Error
	cmp eax,STATUS_MORE_ENTRIES
	lea ecx,Gp
	lea edx,Snapshot
	jne Unload
	push ecx
	push 0
	push NULL
	push ClbkData.Data
	push edx
DBG_WSP_QUERY_ENTRY::
; Маршрутизация возможна только на !NL. Определяем начало процедуры, далее только эта часть графа будет использоваться.
	%GPCALL GP_SEARCH_ROUTINE_ENTRY
	test eax,eax
	mov edi,Result
	jnz Unload
	mov ebx,Gp
	assume edi:PWSP_PARSE_DATA
	mov [edi].WSPSocketLvl0.GpLimit,eax	; Лимит не используем, не линейная трассировка.
	mov [edi].WSPSocketLvl0.GpBase,ebx
	invoke GpCleaningCycle, addr Snapshot
	push dword ptr [ebx + EhAddress]
	mov eax,Snapshot.Ip
	mov ecx,Snapshot.GpBase
	mov edx,Snapshot.GpLimit
	mov esi,WsHandle
	pop [edi].WSPSocketLvl0.Ip
	mov [edi].WSPSocketLvl2.Ip,eax
	mov [edi].WSPSocketLvl2.GpBase,ecx
	mov [edi].WSPSocketLvl2.GpLimit,edx
	mov [edi].WsHandle,esi
	xor eax,eax
	jmp Exit
Error:
	mov eax,STATUS_NOT_FOUND
Unload:
	assume ebx:PAPIS
; Deref.
	push eax
	push WsHandle
	Call [ebx].pLdrUnloadDll
	pop eax
Free:
	push eax
	mov GpSize,NULL
	lea eax,GpSize
	lea ecx,Snapshot.GpBase
	push MEM_RELEASE
	push eax
	push ecx
	push NtCurrentProcess
	Call [ebx].pZwFreeVirtualMemory
	pop eax
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
WspInitialize endp