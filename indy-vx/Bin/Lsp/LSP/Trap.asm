; Трап-процессинг.
;
; (c) Indy, 2011.
;
.code
	include Tls.inc

;	DBG_ENABLE_EXTENSIONS - если задефинить, то трейс не прекращается на открытии девайса, а продолжается до возврата из WSPSocket().

DBG_PRINTEXCEPTION_C	equ 40010006H

OP_CALL_REL		equ 0E8H

TRACE_ACTIVE_FLAG			equ 001B
STRACE_PROCESSING_FLAG		equ 010B
AFD_OPENED_FLAG			equ 100B

%STOP_TRACE macro
	and [edi].regEFlags,NOT(EFLAGS_TF)
endm

%START_TRACE macro
	or [edi].regEFlags,EFLAGS_TF
endm

xAllocateHeap2ndfStub:
	%GET_CURRENT_GRAPH_ENTRY
AllocateHeap2ndfStub proc C
	push eax
	invoke TlsGet, NULL
	mov ecx,EFLAGS_TF or EFLAGS_IF or EFLAGS_MASK
	xchg dword ptr [esp],eax
	xchg dword ptr [esp],ecx
;	mov ecx,eax
;	pop eax
;	push EFLAGS_TF or EFLAGS_IF or EFLAGS_MASK
	popfd	; Трап возникнет после ветвления. Стаб может быть отморфлен, поэтому трассировщик пропускает останов в теле.
	jmp dword ptr TLS.Ip2ndf[ecx]
AllocateHeap2ndfStub endp

xRtlpCheckHeapSignatureStub:
	%GET_CURRENT_GRAPH_ENTRY
RtlpCheckHeapSignatureStub proc C
	invoke TlsGet, NULL
	mov ecx,eax
	mov eax,TRUE
	jmp dword ptr TLS.RouteIp[ecx]
RtlpCheckHeapSignatureStub endp

xXcptSkipTraceStub:
	%GET_CURRENT_GRAPH_ENTRY
XcptSkipTraceStub proc C
	push eax
	ifdef DBGBUILD
	   %GET_ENV_PTR Eax
	   inc ENVIRONMENT.SkipTraceStubCount[eax]
	endif
	invoke TlsGet, NULL
	mov ecx,EFLAGS_TF or EFLAGS_IF or EFLAGS_MASK
	xchg dword ptr [esp],eax
	xchg dword ptr [esp],ecx
;	mov ecx,eax
;	pop eax
;	push EFLAGS_TF or EFLAGS_IF or EFLAGS_MASK
	popfd
	jmp dword ptr TLS.SkipIp[ecx]
XcptSkipTraceStub endp

xXcptPostTraceStub:
	%GET_CURRENT_GRAPH_ENTRY
XcptPostTraceStub proc C
	push eax
	invoke TlsGet, NULL
	mov ecx,eax
	pop eax
	jmp dword ptr TLS.PostIp[ecx]
XcptPostTraceStub endp

SYSTUB struct
OpMovEax		BYTE ?
ServiceId		ULONG ?
OpMovEdx		BYTE ?
Gate			PVOID ?
OpCall		WORD ?
OpRet		BYTE 3 DUP (?)	; 1/3
SYSTUB ends
PSYSTUB typedef ptr SYSTUB

xBadrefDispatchStub:
	%GET_CURRENT_GRAPH_ENTRY
BadrefDispatchStub proc C
	push ebx
	push eax
	%GET_ENV_PTR Ebx
	assume ebx:PENVIRONMENT
	ifdef DBGBUILD
	   inc [ebx].BadrefStubCount
	endif
	mov eax,dword ptr [esp + 4*4]	; Handle
	lea ecx,ENVIRONMENT.HandleTable[ebx]
	test eax,eax
	jnz @f
	
	ifdef DBGBUILD
	   %HALT
	endif
	
	pop eax
	pop ebx
	retn
@@:
	lea edx,ENVIRONMENT.HandleTable[ebx][sizeof(HT_ENTRY)*HT_ENTRIES]
	.repeat
	   .if HT_ENTRY.Magic[Ecx] == Eax
	      mov eax,HT_ENTRY.Handle[ecx]
	      mov dword ptr [esp + 4*4],eax
	      jmp @f
	   .endif
	   add ecx,sizeof(HT_ENTRY)
	.until Ecx >= Edx
@@:
	add esp,4
	mov edx,ENVIRONMENT.Apis.pZwDeviceIoControlFile[ebx]
	sub dword ptr [esp + 4],SYSTUB.OpRet
	cmp dword ptr [esp + 4],edx
; Описатель передаётся в сервисы всегда первым параметром.
	.if Zero?
	   ifdef DBGBUILD
	      inc [ebx].IoControlCount
	   endif
; NTSTATUS
; ZwDeviceIoControlFile(
;    IN HANDLE FileHandle,
;    IN HANDLE Event OPTIONAL,
;    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
;    IN PVOID ApcContext OPTIONAL,
;    OUT PIO_STATUS_BLOCK IoStatusBlock,
;    IN ULONG IoControlCode,
;    IN PVOID InputBuffer OPTIONAL,
;    IN ULONG InputBufferLength,
;    OUT PVOID OutputBuffer OPTIONAL,
;    IN ULONG OutputBufferLength
;    );
	   mov ecx,dword ptr [esp + 10*4]	; InputBufferLength
	   mov edx,dword ptr [esp + 9*4]	; InputBuffer
	   shr ecx,2
	   .if Edx && Ecx
	      push esi
	      push edi
	      .repeat
	         lea esi,[ebx].HandleTable
	         mov eax,dword ptr [edx]
	         lea edi,[ebx].HandleTable[sizeof(HT_ENTRY)*HT_ENTRIES]
	         .repeat
	            .if Eax && (HT_ENTRY.Magic[Esi] == Eax)
	               mov eax,HT_ENTRY.Handle[esi]
	               mov dword ptr [edx],eax
	               jmp @f
	            .endif
	            add esi,sizeof(HT_ENTRY)
	         .until Esi >= Edi
	      @@:
	         add edx,4
	         dec ecx
	      .until !Ecx
	      pop edi
	      pop esi
	   .endif
	.endif
	pop ebx
	retn
BadrefDispatchStub endp

xXcptUnwindStub:
	%GET_CURRENT_GRAPH_ENTRY
XcptUnwindStub proc C
; *** Локальный SEH.
	%HALT
XcptUnwindStub endp

XcptValidateHandle proc Handle:HANDLE
Local ObjInfo:OBJECT_BASIC_INFORMATION
	lea ecx,ObjInfo
	push NULL
	push sizeof(OBJECT_BASIC_INFORMATION)
	push ecx
	%GET_ENV_PTR Eax
	push ObjectBasicInformation
	push Handle
	Call ENVIRONMENT.Apis.pZwQueryObject[eax]
	ret
XcptValidateHandle endp

Public DBG_XCPT_TRAP
Public DBG_XCPT_TRAP_IS_WSP_SNAP
Public DBG_XCPT_TRAP_POST_SKIP
Public DBG_XCPT_TRAP_DIS
Public DBG_XCPT_TRAP_IS_AFD
Public DBG_XCPT_TRAP_PRE_SKIP
Public DBG_XCPT_PRINT_IS_HMGR_MSG
Public DBG_XCPT_IS_HMGR_SNAP
Public DBG_XCPT_ROUTE_RtlpCheckHeapSignature
Public DBG_XCPT_ROUTE_AllocateHeap
Public DBG_XCPT_TRAP_AFD_OPEN
Public DBG_XCPT_BREAK_DISPATCH
Public DBG_XCPT_SKIP_ROUTE
Public DBG_XCPT_TRAP_IS_BODY
Public DBG_XCPT_BADREF
Public DBG_XCPT_SKIP_INT3
Public DBG_XCPT_TRAP_INSERT_WAH

; +
; Диспетчер исключений. Выполняет следующие функции:
; o Трассировка с пропусканием процедур до открытия девайса.
; o Обработка останова в RtlpCheckHeapSignature(), маршрутизация и начало трассировки.
; o Локальную обработку исключений в сех.
;
; o Можно использовать быструю S-маршрутизацию, либо через механизм исключений(взвести 
;   старший бит в адресе возврата). Быстрая маршрутизация требует указатель в тлс. Так 
;   как трассировка с пропусканием процедур, то можно не использовать тлс. Тогда трасс
;   ировку следует прекратить при обнаружении останова за пределами слепка. В качестве 
;   тлс можно использовать конец пеб(при возникновении коллизий, например с IDPE следу
;   ет использовать иной тлс), дно стека и пр.
; o В диспетчере исключений возможен деадлок при возникновении исключения, отличного о
;   т #STATUS_SINGLE_STEP и сгенерированном при TF. Останов в диспетчере возникает на 
;   второй инстуркции(trap).
; o Генерацию DBG_PRINTEXCEPTION_C можно отключить установкой флажка в TEB.InDbgPrint.
;
; o Среда загружена в PEB.
;
xXcptDispatch:
	%GET_CURRENT_GRAPH_ENTRY
XcptDispatch proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local Caller:GP_CALLER, Caller2ndf:GP_CALLER, Gp:PVOID	
Local WspSnapshot:GP_SNAPSHOT, AfdHandle:HANDLE
Local Tls:PTLS, ObjInfo:DWORD
	mov ebx,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[ebx]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[ebx]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jne Chain
	%GET_ENV_PTR Ebx
	assume ebx:PENVIRONMENT
	test ebx,ebx
	jz Chain
	invoke TlsGet, Ebx
	test eax,eax
	mov ecx,[esi].ExceptionCode
	jz Chain	; Критическая ошибка, дальнейшая обработка не возможна.
	mov Tls,eax
	cmp ecx,DBG_PRINTEXCEPTION_C
	je Load	; Хэндлим весь вывод.
	cmp ecx,STATUS_BREAKPOINT
	je XcptBreak
	cmp ecx,STATUS_SINGLE_STEP
	je XcptTrap
	cmp ecx,STATUS_INVALID_HANDLE
	je XcptBadref
	cmp ecx,STATUS_HANDLE_NOT_CLOSABLE
	je _ZwClose
	cmp ecx,STATUS_ACCESS_VIOLATION
	jne Chain
	lea ecx,Gp
	lea edx,[ebx].BodySnapshot
	push ecx
	push [esi].ExceptionAddress
	push edx
	%GPCALL GP_CS_CHECK_IP_BELONG_TO_SNAPSHOT
	test eax,eax
	jnz Chain	; Фолт за пределами тела, пропускаем его.
Unwind:
	%GET_GRAPH_ENTRY xXcptUnwindStub
	jmp Load

; +
DBG_XCPT_TRAP::
XcptTrap:
	mov eax,[esi].ExceptionAddress
	cmp [ebx].Apis.pKiUserExceptionDispatcher,eax
	ja @f
	je ResetTF	; TF перенесён в диспетчер, сбрасываем TF, иначе будет деадлок.
	sub eax,MAX_INSTRUCTION_LENGTH*2
	cmp [ebx].Apis.pKiUserExceptionDispatcher,eax
	ja ResetTF
@@:
	ifdef DBGBUILD
	   mov eax,[esi].ExceptionAddress
	   inc [ebx].TraceIntoCount
	   mov [ebx].LastTraceIp,eax
	endif
	
	%TLS_IS_STRACE
	jc SkipPost
	%TLS_IS_TRACE
	jnc Chain	; Трассировка не запущена, передаём фолт в вышестоящий хэндлер без поправок контекста.
; Проверяем что останов при возврате из WSPSocket() на стабе, тогда прекращаем трассировку - она начата после открытия девайса.
	%GET_GRAPH_ENTRY xXcptPostTraceStub
	cmp [esi].ExceptionAddress,eax
	je StopTrace
DBG_XCPT_TRAP_IS_WSP_SNAP::
	lea ecx,Gp
	lea edx,[ebx].WspSnapshot.WSPSocketLvl0
	push ecx
	push [esi].ExceptionAddress
	push GCBE_PARSE_NL_PRIMARY
	push edx
	%GPCALL GP_RW_CHECK_IP_BELONG_TO_SNAPSHOT
	test eax,eax
	lea ecx,Gp
	jz IsCall
DBG_XCPT_TRAP_IS_BODY::
; Возможно останов в стабах(могут быть отморфлены).
	push ecx
	push [esi].ExceptionAddress
	lea edx,[ebx].BodySnapshot
	push edx
	%GPCALL GP_CS_CHECK_IP_BELONG_TO_SNAPSHOT
	test eax,eax
	ifdef DBGBUILD
	   %STOP_TRACE
	   jmp Load
	else
	   jz SetTF	; Останов в теле, продолжаем трассировку.
	endif
StopTrace:
	%STOP_TRACE	; Изза ошибки не произошло открытие девайса, либо возник фолт и передан в системный сех.
	%TLS_STOP_TRACE
	jmp Load

; +
; Останов в слепке. Проверяем на вызов стаба ZwCreateFile.
DBG_XCPT_TRAP_DIS::
IsCall:
	%START_TRACE
	push [esi].ExceptionAddress
	%GPCALL GP_PFX
	test eax,eax
	mov ecx,[esi].ExceptionAddress
	jnz Load
	movzx eax,byte ptr [ecx]	; Opcode
	cmp al,OP_CALL_REL
	je Skip
	cmp al,0FFH
	jne Load
; Grp 5.
	movzx eax,byte ptr [ecx + 1]
	and al,MODRM_REG_MASK
	shr al,3
	cmp al,10B
	jne Load
DBG_XCPT_TRAP_PRE_SKIP::
Skip:
	%TLS_START_STRACE
	jmp Load

; +
DBG_XCPT_PRINT_IS_HMGR_MSG::
XcptPrint:
	ifdef DBGBUILD
	   inc [ebx].PrintCount
	endif
; Отладочный вывод может быть отключен. Маршрутизация при отстанове в RtlpBreakpointHeap().
;	cmp [esi].NumberParameters,2
;	jne Load
;	cmp [esi].ExceptionInformation[0],MSG_HEAP_INVALID_SIGNATURE_LENGTH
;	jna Load
;	push MSG_HEAP_INVALID_SIGNATURE_LENGTH
;	push [esi].ExceptionInformation[4]
;	push 0
;	Call LdrCalculateHash
;	cmp eax,MSG_HEAP_INVALID_SIGNATURE
;	jne Load
;	...

; +
XcptBreak:
DBG_XCPT_IS_HMGR_SNAP::
	ifdef DBGBUILD
	   inc [ebx].BreakCount
	endif
	lea ecx,Caller
	lea edx,[ebx].HmgrSnapshot
	push ecx
	push FALSE
	push UserMode
	push [edi].regEbp
	push GCBE_PARSE_NL_UNLIMITED
	push edx
	%GPCALL GP_FIND_CALLER_BELONG_TO_SNAPSHOT
	test eax,eax
	ifdef DBGBUILD
	   jnz DBG_XCPT_SKIP_INT3
	else
	   jnz Chain
	endif
; Выполняем S-маршрутизацию для корректировки возвращаемого значения из RtlpCheckHeapSignature().
DBG_XCPT_BREAK_DISPATCH::
	%TLS_IS_TRACE
	jc HmgrLoad	; Трассировка запущена, маршрутизация была выполнена.
	lea ecx,Caller2ndf
	lea edx,[ebx].WspSnapshot.WSPSocketLvl0
	push ecx
	push TRUE
	push UserMode
	push [edi].regEbp
	push GCBE_PARSE_NL_PRIMARY
	push edx
	%GPCALL GP_FIND_CALLER_BELONG_TO_SNAPSHOT
	test eax,eax
	mov edx,Tls
	.if Zero?
	   mov ecx,Caller2ndf.Frame
	   %GET_GRAPH_ENTRY xXcptPostTraceStub
	   mov ecx,STACK_FRAME.Next[ecx]
	   .if STACK_FRAME.Ip[Ecx] != Eax
	      xchg STACK_FRAME.Ip[ecx],eax
	      %TLS_SET_POST_STUB Eax, Edx
DBG_XCPT_ROUTE_AllocateHeap::
	      %GET_GRAPH_ENTRY xAllocateHeap2ndfStub
	      mov ecx,Caller2ndf.Frame
	      xchg STACK_FRAME.Ip[ecx],eax
	      %TLS_SET_2NDF_STUB Eax, Edx
	      %TLS_START_TRACE Edx
	   .endif
	.endif
DBG_XCPT_ROUTE_RtlpCheckHeapSignature::
HmgrLoad:
	ifdef DBGBUILD
	   inc [ebx].RtlpCheckHeapSignatureCalls
	endif
	%GET_GRAPH_ENTRY xRtlpCheckHeapSignatureStub
	mov ecx,Caller.Frame
	mov edx,Tls
	mov ecx,STACK_FRAME.Next[ecx]	; NL = 1
	xchg STACK_FRAME.Ip[ecx],eax
	%TLS_SET_SROUTE_STUB Eax, Edx
DBG_XCPT_SKIP_INT3::
	inc [edi].regEip	; Int3
	jmp Load

; +
DBG_XCPT_TRAP_POST_SKIP::
SkipPost:
	ifdef DBGBUILD
	   inc [ebx].TraceOverCount
	endif
	mov eax,[esi].ExceptionAddress
	cmp [ebx].Apis.pZwCreateFile,eax
	mov ecx,[edi].regEsp
	mov edx,Tls
	je IsAfd
;	%TLS_IS_AFD_OPEN Edx
;	jnc SkipRoute
;	cmp [ebx].pWahInsertHandleContext,eax
;	lea eax,[ebx].HandleTable
;	jne SkipRoute
DBG_XCPT_TRAP_INSERT_WAH::

DBG_XCPT_SKIP_ROUTE::
SkipRoute:
	%STOP_TRACE
	%GET_GRAPH_ENTRY xXcptSkipTraceStub
	mov ecx,[edi].regEsp
	mov edx,Tls
	xchg dword ptr [ecx],eax
	%TLS_STOP_STRACE Edx
	%TLS_SET_SKIP_STUB Eax, Edx
	jmp Load
Stop:
	mov eax,Tls
	%STOP_TRACE
	%TLS_STOP_TRACE_END_STRACE Eax
	jmp Load
DBG_XCPT_TRAP_IS_AFD::
IsAfd:
; NTSTATUS
; ZwCreateFile(
;	OUT PHANDLE FileHandle,
;	IN ACCESS_MASK DesiredAccess,
;	IN POBJECT_ATTRIBUTES ObjectAttributes,
;	OUT PIO_STATUS_BLOCK IoStatusBlock,
;	IN PLARGE_INTEGER AllocationSize OPTIONAL,
;	IN ULONG FileAttributes,
;	IN ULONG ShareAccess,
;	IN ULONG CreateDisposition,
;	IN ULONG CreateOptions,
;	IN PVOID EaBuffer OPTIONAL,
;	IN ULONG EaLength
;	);
	mov eax,dword ptr [ecx + 3*4]	; POBJECT_ATTRIBUTES
	test eax,eax
	jz SkipRoute
	assume eax:POBJECT_ATTRIBUTES
	cmp [eax].uLength,sizeof(OBJECT_ATTRIBUTES)
	jne SkipRoute
	mov eax,[eax].pObjectName
	test eax,eax
	jz SkipRoute
	mov eax,UNICODE_STRING.Buffer[eax]
	invoke LdrCalculateHash, 0, Eax, 28H
	cmp eax,3E2B0DF4H	; HASH("\Device\Afd\Endpoint")
	jne SkipRoute
DBG_XCPT_TRAP_AFD_OPEN::
AfdOpen:
	mov edx,[edi].regEsp
	mov ecx,10	; Arg's
	push dword ptr [edx + 4]	; @Handle
	push dword ptr [edx]	; @Ip
	.repeat
	   push dword ptr [edx + ecx*4 + 4]
	   dec ecx
	.until !Ecx
	lea eax,AfdHandle
	push eax
	Call [ebx].Apis.pZwCreateFile	; HANDLE_TRACE_DB_OPEN
	pop [edi].regEip
	mov [edi].regEax,eax	; Status
	pop ecx
	add [edi].regEsp,12*4
	test eax,eax
	jl Stop
	lea eax,[ebx].HandleTable
	lea edx,[eax + sizeof(HT_ENTRY)*HT_ENTRIES]
	.repeat
	   cmp HT_ENTRY.Magic[eax],NULL
	   je @f
	   add eax,sizeof(HT_ENTRY)
	.until Eax >= Edx
; Лимит описателей исчерпан.
	mov eax,AfdHandle
	mov dword ptr [ecx],eax
	jmp Stop
@@:
	ifdef DBGBUILD
	   inc [ebx].OpenCount
	endif
	lea edx,[ebx].HandleTable
	push AfdHandle
; Можно прибавить к описателю BADREF_MAGIC_BASE, но лучше хранить в таблице, 
; так как изза рандомизации алгоритм вычисления описателей может измениться.
	sub edx,eax
	add edx,BADREF_MAGIC_BASE
	pop HT_ENTRY.Handle[eax]
	mov HT_ENTRY.Magic[eax],edx
	mov dword ptr [ecx],edx
	mov dword ptr [ObjInfo],0100H	; ProtectFromClose
	lea eax,ObjInfo
	push sizeof(OBJECT_HANDLE_FLAG_INFORMATION)	; 2
	push eax
	push ObjectHandleInformation
	push AfdHandle
	Call [ebx].Apis.pZwSetInformationObject

	mov eax,Tls
	%TLS_STOP_STRACE Eax
	%TLS_AFD_OPEN Eax
	ifdef DBG_ENABLE_EXTENSIONS
	   jmp SetTF
	else
	   %TLS_STOP_TRACE Eax
	   jmp ResetTF
	endif

DBG_XCPT_BADREF::	
XcptBadref:
	ifdef DBGBUILD
	   inc [ebx].BadrefCount
	endif
; Ip ~ KiRaiseUserExceptionDispatcher().
; (leave/ret)

	mov eax,[edi].regEbp
	mov ecx,dword ptr [eax + sizeof(STACK_FRAME)]
	mov edx,eax
	sub ecx,SYSTUB.OpRet
	.if [Ebx].Apis.pZwClose == Ecx
; ~ ZwClose()
_ZwClose:
	   ifdef DBGBUILD
	      inc [ebx].CloseCount
	   endif
	   mov eax,dword ptr [edx + sizeof(STACK_FRAME) + 2*4]	; Handle
	   lea ecx,[ebx].HandleTable
	   test eax,eax
	   lea edx,[ebx].HandleTable[sizeof(HT_ENTRY)*HT_ENTRIES]
	   jz SkipClose
	   .repeat
	      .if HT_ENTRY.Magic[Ecx] == Eax
	         mov eax,HT_ENTRY.Handle[ecx]
	         push eax
         	    mov HT_ENTRY.Handle[ecx],NULL
         	    mov HT_ENTRY.Magic[ecx],NULL
	
         	    lea ecx,ObjInfo
	         mov dword ptr [ObjInfo],0000H
         	    push sizeof(OBJECT_HANDLE_FLAG_INFORMATION)	; 2
         	    mov [edi].regEax,STATUS_SUCCESS
         	    push ecx
              push ObjectHandleInformation
         	    push eax
         	    Call [ebx].Apis.pZwSetInformationObject
         	    test eax,eax
         	    pop ecx
         	    .if Zero?
         	       push ecx
         	       Call [ebx].Apis.pZwClose
         	    .endif
SkipClose:
         	    mov eax,[edi].regEbp
              mov ecx,STACK_FRAME.Next[eax]
         	    mov edx,dword ptr [eax + sizeof(STACK_FRAME) + 4]
         	    mov [edi].regEbp,ecx
         	    add eax,sizeof(STACK_FRAME) + 3*4
         	    mov [edi].regEip,edx
         	    mov [edi].regEsp,eax
         	    jmp Load
	      .endif
	      add ecx,sizeof(HT_ENTRY)
	   .until Ecx >= Edx
	   jmp SkipClose
	.endif
	mov ecx,STACK_FRAME.Next[eax]
	mov [edi].regEbp,ecx
	add eax,sizeof(STACK_FRAME)
	mov [edi].regEsp,eax
	%GET_GRAPH_ENTRY xBadrefDispatchStub
	mov [edi].regEip,eax
	jmp Load
SetTF:
	%START_TRACE
	jmp Load
ResetTF:
	%STOP_TRACE
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp Exit
Chain:
	xor eax,eax
Exit:
	ret
XcptDispatch endp