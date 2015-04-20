; SHDE
; UM, MI
; (c) Indy, 2012
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.code
; OPT_ENABLE_DBG	equ TRUE

FLG_ENABLE_SEH	equ TRUE

	jmp Initialize
	
	include Hdr.asm
	include Hash.asm
	include Img.asm
	include Nt.asm

; +
; VEH.
;
xXcptDispatch:
	%GET_CURRENT_GRAPH_ENTRY
XcptDispatch proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
	mov ebx,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[ebx]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[ebx]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jne Chain
	cmp [esi].ExceptionCode,STATUS_INVALID_HANDLE
	jne Chain
; o Ip ~ KiRaiseUserExceptionDispatcher(), эмулируем leave/ret.
	mov eax,[edi].regEbp
	mov ecx,STACK_FRAME.Next[eax]
	mov edx,STACK_FRAME.Ip[eax]	; @SYSGATERET
	mov [edi].regEbp,ecx
	add eax,sizeof(STACK_FRAME)
	mov [edi].regEip,edx
	mov [edi].regEsp,eax
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp Exit
Chain:
	xor eax,eax
Exit:
	ret
XcptDispatch endp

.data
SERVICE_COUNT	equ 68	; Число тестируемых сервисов.

PUBLIC Alloc

.code
FindEntryForAddress proc Snap:PVOID, Ip:PVOID
	mov edx,Snap
	lea eax,[edx + 4]
	mov edx,dword ptr [edx]
	assume eax:PRTL_PROCESS_MODULE_INFORMATION	; NT
	.repeat
		mov ecx,[eax].ImageBase
		cmp Ip,ecx
		jb @f
		add ecx,[eax].ImageSize
		cmp Ip,ecx
		jb Exit
@@:
		add eax,sizeof(RTL_PROCESS_MODULE_INFORMATION)
		dec edx
	.until Zero?
	xor eax,eax
Exit:
	ret
FindEntryForAddress endp

DATABASE struct
Snapshot	PVOID ?	; Слепок модулей.
NtList	PVOID ?	; Список сервисов(SYSLIST).
AvList	PSYSENTRY ? 
DATABASE ends
PDATABASE typedef ptr DATABASE

ifdef OPT_ENABLE_DBG
	ANALYSIS_FAILURE$	CHAR "ANALYSIS_FAILURE: DB: 0x%p, TotalTraces: 0x%p, HandleTrace.Type: 0x%p, InfoLength: 0x%p",  13, 10, 0
endif

Initialize proc uses ebx esi edi pDatabase:PDATABASE
Local NtView:PVOID
Local Apis:APIS
Local DbBase:PVOID
Local DbSize:ULONG
Local AvList[32]:PVOID
Local Sentry:PVOID
Local InfoLength:ULONG
Local SysApi[SERVICE_COUNT + 1]:PVOID	; Список тестируемых NTAPI.
Local ApiCount:ULONG
Local Tracing:PROCESS_HANDLE_TRACING_ENABLE
Local TraceInformation:PROCESS_HANDLE_TRACING_QUERY
Local SystemInformation:SYSTEM_BASIC_INFORMATION
Local NtBase:PVOID, NtLimit:PVOID
Local VehHandle:HANDLE
Local ObjAttr:OBJECT_ATTRIBUTES
	%SEHPROLOG
	invoke LdrGetNtBase
	mov esi,eax
; Получаем базовые сервисы.
	invoke LdrInitializeApis, Esi, addr Apis
	test eax,eax
	jnz Exit
	mov NtView,eax
	invoke LdrMapViewOfImage, addr Apis, Esi, addr NtView
	test eax,eax
	cld
	lea edi,SysApi
	jl Exit
; Заполняем буфер хэшами тестируемых NTAPI.
	%APIGEN
; Аллоцируем память под список всех NTAPI.
	mov DbBase,eax
	mov DbSize,80H * X86_PAGE_SIZE - X86_PAGE_SIZE
	Call Alloc
	mov ebx,DbBase
	jnz Unmap
; Получаем все NTAPI.
	invoke LdrQueryServicesList, NtView, Esi, addr DbBase
	test eax,eax
	jnz DbFree
; Аллоцируем память под массив описателей тестируемых сервисов(массив структур SYSENTRY).
	mov DbBase,eax
	mov DbSize,SERVICE_COUNT * sizeof(SYSENTRY)
	Call Alloc
	mov edi,ebx
	jnz DbFree
; Инициализируем массив SYSENTRY.
	mov esi,DbBase
	assume esi:PSYSENTRY
	xor eax,eax
	cld
	mov ApiCount,SERVICE_COUNT
	push ebx
	mov Sentry,esi
Next:
; [Name][0].4[Addr].2[Id].2[Args].4[Hash]
	cmp byte ptr [edi],EOL
	je Error
	mov ecx,80H
@@:
	mov ebx,edi
	repne scasb
	assume edi:PSYSLIST
	mov ecx,[edi].Hash
	lea edx,SysApi		; В конце массива EOL.
@@:
	cmp dword ptr [edx],ecx
	je @f
	add edx,sizeof(PVOID)
	cmp dword ptr [edx],EOL
	jne @b
	add edi,sizeof(SYSLIST)
	jmp Next
@@:
	lea ecx,SysApi
	sub edx,ecx
	cmp [esi + edx * (sizeof(SYSENTRY)/sizeof(PVOID))].Id,NULL
	jne Next		; Сервисы расположены в алфавитном порядке. В W8 порядок изменён на противоположный(!ID(NtYieldExecution)).
	movzx ecx,[edi].Id
	mov [esi + edx * (sizeof(SYSENTRY)/sizeof(PVOID))].SsList,ebx
	mov [esi + edx * (sizeof(SYSENTRY)/sizeof(PVOID))].Id,cx
	mov [esi + edx * (sizeof(SYSENTRY)/sizeof(PVOID))].AvList,NULL
	movzx ecx,[edi].Args
	dec ApiCount
	mov [esi + edx * (sizeof(SYSENTRY)/sizeof(PVOID))].Args,cl
	jz @f
	add edi,sizeof(SYSLIST)
	jmp Next
@@:
; Получаем слепок модулей.
	pop ebx
	lea edx,DbSize
	push edx
	push eax
	push eax
	push SystemModuleInformation
	Call Apis.pZwQuerySystemInformation
	cmp eax,STATUS_INFO_LENGTH_MISMATCH
	jne SsFree
	add DbSize,X86_PAGE_SIZE*3
	mov DbBase,NULL
	Call Alloc
	mov ecx,DbBase
	jnz SsFree
	push eax
	push DbSize
	push DbBase
	push SystemModuleInformation
	Call Apis.pZwQuerySystemInformation
	test eax,eax
	lea ecx,SystemInformation
	jnz LdFree
	push eax
	push sizeof(SYSTEM_BASIC_INFORMATION)
	push ecx
	push SystemBasicInformation
	Call Apis.pZwQuerySystemInformation
	test eax,eax
	mov ecx,DbBase
	jnz LdFree
	mov edx,RTL_PROCESS_MODULE_INFORMATION.ImageBase[ecx + 4]	; NT
	mov ecx,RTL_PROCESS_MODULE_INFORMATION.ImageSize[ecx + 4]
	mov NtBase,edx
	mov Tracing,eax
	add ecx,edx
	lea eax,Tracing
	mov NtLimit,ecx
; Запускаем трассировку описателей.
	push sizeof(PROCESS_HANDLE_TRACING_ENABLE)
	push eax
	push ProcessHandleTracing
	push NtCurrentProcess
	Call Apis.pZwSetInformationProcess
	test eax,eax
	jnz LdFree
	%GET_GRAPH_ENTRY xXcptDispatch
	push eax
	push 1
	Call Apis.pRtlAddVectoredExceptionHandler
	mov VehHandle,eax
	.if !Eax
		mov eax,STATUS_INTERNAL_ERROR
		jmp LdFree
	.endif
; Создаём лог. Каждый сервис генерирует #STATUS_INVALID_HANDLE.
	invoke GenerateBadrefLog, Esi
; Анализ лога. В цикле запрашиваем инфу для каждого описателя и парсим её.
	mov edi,BADREF_MAGIC_BASE
	mov ApiCount,SERVICE_COUNT - 2	; NtOpenProcess & NtOpenThread.
	.repeat
		mov TraceInformation.Handle,edi
		Call DbAnalyze
		add edi,4
		dec ApiCount
	.until Zero?
; * BUGBUG: На W7 NtOpenProcess & NtOpenThread возвращают STATUS_INVALID_PARAMETER_MIX, 
;           так как нельзя открывать процессы и потоки по имени. Используем HANDLE_TRA
;           CE_DB_OPEN для текущего CID, это не приведёт к детекту вызова фильтром.
	mov ecx,fs:[TEB.Tib.Self]
	xor eax,eax
	lea ecx,TEB.Cid[ecx]
	lea edx,ObjAttr
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	mov ObjAttr.pSecurityDescriptor,eax
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.uAttributes,eax
	mov ObjAttr.pObjectName,eax
	mov ObjAttr.hRootDirectory,eax
; NtOpenProcess
	push ecx	; CID
	push edx
	push ecx
	push edx
	lea eax,TraceInformation.Handle
	push PROCESS_QUERY_INFORMATION
	push eax
	%NTCALL3
	.if Eax
		or [esi].Flags,FLG_ANALYSIS_FAILURE
	.else
		Call DbAnalyze
		push TraceInformation.Handle
		Call Apis.pZwClose
	.endif
; NtOpenThread
	lea eax,TraceInformation.Handle
	push THREAD_QUERY_INFORMATION
	push eax
	%NTCALL3
	.if Eax
		or [esi].Flags,FLG_ANALYSIS_FAILURE
	.else
		Call DbAnalyze
		push TraceInformation.Handle
		Call Apis.pZwClose
	.endif
	mov eax,pDatabase
	mov ecx,DbBase
	mov edx,Sentry
	push VehHandle
	mov DATABASE.Snapshot[eax],ecx
	mov DATABASE.NtList[eax],ebx
	mov DATABASE.AvList[eax],edx
	Call Apis.pRtlRemoveVectoredExceptionHandler
	xor eax,eax
	jmp Unmap
DbAnalyze:
	test [esi].Flags,FLG_ANALYSIS_FAILURE
	jnz Success
	lea eax,InfoLength
	lea ecx,TraceInformation
	push eax
	push sizeof(PROCESS_HANDLE_TRACING_QUERY)
	push ecx
	push ProcessHandleTracing
	push NtCurrentProcess
	Call Apis.pZwQueryInformationProcess
	test eax,eax
	jz @f
	cmp eax,STATUS_INFO_LENGTH_MISMATCH
	jne Skip
@@:
	cmp InfoLength,sizeof(PROCESS_HANDLE_TRACING_QUERY)
	jne Skip
	cmp TraceInformation.TotalTraces,1
	jb Skip
;	cmp TraceInformation.HandleTrace._Type,HANDLE_TRACE_DB_BADREF
	mov InfoLength,PROCESS_HANDLE_TRACING_MAX_STACKS
;	jne Skip
Parse:
	mov ecx,InfoLength
	mov eax,TraceInformation.HandleTrace.Stacks[ecx*4 - 4]
	test eax,eax
	jz @f
	cmp SystemInformation.MaximumUserModeAddress,eax
	ja @f
; Kernel SFC.
	invoke FindEntryForAddress, DbBase, Eax
	jz Present	; kss60
	mov edx,RTL_PROCESS_MODULE_INFORMATION.ImageBase[eax]
	cmp NtBase,edx
	mov ecx,InfoLength
	jne Defined
	dec InfoLength
	jz Present
	mov eax,TraceInformation.HandleTrace.Stacks[ecx*4 - 2*4]
	test eax,eax
	jz Success
	invoke FindEntryForAddress, DbBase, Eax
	jz Present
	mov edx,RTL_PROCESS_MODULE_INFORMATION.ImageBase[eax]
	cmp NtBase,edx
	jne Defined
Success:
	add esi,sizeof(SYSENTRY)
	retn
@@:
	dec InfoLength
	jnz Parse
Skip:
	ifdef OPT_ENABLE_DBG
		invoke DbgPrint, addr ANALYSIS_FAILURE$, Edi, TraceInformation.TotalTraces, TraceInformation.HandleTrace._Type, InfoLength
	endif
	mov [esi].AvList,FLG_ANALYSIS_FAILURE
	jmp Success
Defined:
	or [esi].Flags,FLG_FILTER_DEFINED
Present:
	mov ecx,InfoLength
	or [esi].Flags,FLG_FILTER_PRESENT
	mov ecx,TraceInformation.HandleTrace.Stacks[ecx*4 - 4]
	test eax,eax
	mov [esi].AvList,eax
	mov [esi].Filter,ecx
	jmp Success
LdFree:
	Call AllocFree
SsFree:
	push Sentry
	pop DbBase
	Call AllocFree
DbFree:
	mov DbBase,ebx
	Call AllocFree
Unmap:
	push eax
	push NtView
	push NtCurrentProcess
	Call Apis.pZwUnmapViewOfSection
	pop eax
	%SEHEPILOG
	ret
Error:
	pop ebx
	mov eax,STATUS_PROCEDURE_NOT_FOUND
	jmp SsFree
Alloc::
	xor eax,eax
	lea ecx,DbSize
	lea edx,DbBase
	add DbSize,X86_PAGE_SIZE
	mov DbBase,eax
	push PAGE_NOACCESS
	push MEM_RESERVE
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	Call Apis.pZwAllocateVirtualMemory
	test eax,eax
	lea ecx,DbSize
	lea edx,DbBase
	jnz AllocFail
	sub DbSize,X86_PAGE_SIZE
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	Call Apis.pZwAllocateVirtualMemory
	test eax,eax
	jnz AllocFree
AllocFail:
	retn
AllocFree:
	push eax
	mov DbSize,NULL
	lea eax,DbSize
	lea ecx,DbBase
	push MEM_RELEASE
	push eax
	push ecx
	push NtCurrentProcess
	Call Apis.pZwFreeVirtualMemory
	pop eax
	test eax,eax
	retn
Initialize endp
end Initialize

.data
gDb	DATABASE <>

.code
$Fail	CHAR "Analysis failure: %s", 13, 10, 0
$Present	CHAR "Hook: %s, 0x%p", 13, 10, 0
$Defined	CHAR "Hook: %s, 0x%p, %s", 13, 10, 0

Entry proc
	invoke Initialize, addr gDb
	; Int 3
	mov ebx,gDb.AvList
	assume ebx:PSYSENTRY
	mov esi,SERVICE_COUNT
Log:
	test [ebx].Flags,FLG_ANALYSIS_FAILURE
	.if !Zero?
		invoke DbgPrint, addr $Fail, [ebx].SsList
	.else
		test [ebx].Flags,FLG_FILTER_PRESENT
		.if !Zero?
			test [ebx].Flags,FLG_FILTER_DEFINED
			.if !Zero?
				mov ecx,[ebx].AvList
				lea ecx,RTL_PROCESS_MODULE_INFORMATION.FullPathName[ecx]
				invoke DbgPrint, addr $Defined, [ebx].SsList, [ebx].Filter, Ecx
			.else
				invoke DbgPrint, addr $Present, [ebx].SsList, [ebx].Filter
			.endif
		.endif
	.endif
	add ebx,sizeof(SYSENTRY)
	dec esi
	jnz Log
	ret
Entry endp
end Entry