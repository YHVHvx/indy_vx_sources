; Трап-процессинг.
;
.code
MAX_INSTRUCTION_LENGTH	equ 15

HEAP_SIGNATURE	equ 0EEFFEEFFH

MSG_HEAP_INVALID_SIGNATURE		equ 033391F16H	; HASH("Invalid heap signature for heap "), 0x20
MSG_HEAP_INVALID_SIGNATURE_LENGTH	equ 32

DBG_PRINTEXCEPTION_C	equ 40010006H

PEB_ENV_PTR	equ X86_PAGE_SIZE - 4

%GET_ENV_PTR macro Reg32
	mov Reg32,fs:[TEB.Peb]
	mov Reg32,dword ptr [Reg32 + PEB_ENV_PTR]
endm

%SET_ENV_PTR macro pEnv
	mov eax,fs:[TEB.Peb]
	mov dword ptr [eax + PEB_ENV_PTR],pEnv
endm

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

OP_CALL_REL		equ 0E8H
OP_CALL_FAR_PTR	equ 9AH

ENVIRONMENT struct
Apis			APIS <>
WspSnapshot	WSP_PARSE_DATA <>
HmgrSnapshot	GP_SNAPSHOT <>
BodySnapshot	GP_SNAPSHOT <>
ENVIRONMENT ends
PENVIRONMENT typedef ptr ENVIRONMENT

TLS struct
Ip		PVOID ?
Ip2ndf	PVOID ?
Flags	ULONG ?
TLS ends
PTLS typedef ptr TLS

TEB_TLS_PTR	equ X86_PAGE_SIZE - sizeof(TLS)

TRACE_ACTIVE_FLAG			equ 01B
STRACE_PROCESSING_FLAG		equ 10B

; Загрузка пост-хэндлера при S-маршрутизации.
;
%TLS_SET_STUB macro Reg32
	mov dword ptr fs:[TEB_TLS_PTR + TLS.Ip],Reg32
endm

%TLS_GET_STUB macro Reg32
	mov Reg32,dword ptr fs:[TEB_TLS_PTR + TLS.Ip]
endm

%TLS_SET_2NDF_STUB macro Reg32
	mov dword ptr fs:[TEB_TLS_PTR + TLS.Ip2ndf],Reg32
endm

%TLS_GET_2NDF_STUB macro Reg32
	mov Reg32,dword ptr fs:[TEB_TLS_PTR + TLS.Ip2ndf]
endm

%TLS_START_TRACE macro
	bts dword ptr fs:[TEB_TLS_PTR + TLS.Flags],0
endm

%TLS_STOP_TRACE macro
	btr dword ptr fs:[TEB_TLS_PTR + TLS.Flags],0
endm

%TLS_IS_TRACE macro
	bt dword ptr fs:[TEB_TLS_PTR + TLS.Flags],0
endm

%TLS_START_STRACE macro
	bts dword ptr fs:[TEB_TLS_PTR + TLS.Flags],1
endm

%TLS_STOP_STRACE macro
	btr dword ptr fs:[TEB_TLS_PTR + TLS.Flags],1
endm

%TLS_IS_STRACE macro
	bt dword ptr fs:[TEB_TLS_PTR + TLS.Flags],1
endm

; Возврат из стаба, после S-маршрутизации.
;
%SROUTE_CONTINUE macro
	jmp dword ptr fs:[TEB_TLS_PTR + TLS.Ip]
endm

%SROUTE_2NDF_CONTINUE macro
	jmp dword ptr fs:[TEB_TLS_PTR + TLS.Ip2ndf]
endm

%STOP_TRACE macro
	and [edi].regEFlags,NOT(EFLAGS_TF)
endm

%START_TRACE macro
	or [edi].regEFlags,EFLAGS_TF
endm

xRtlAllocateHeap2ndfStub:
	%GET_CURRENT_GRAPH_ENTRY
RtlAllocateHeap2ndfStub proc C
	%TLS_START_TRACE
	push EFLAGS_TF or EFLAGS_IF or EFLAGS_MASK
	popfd
	%SROUTE_2NDF_CONTINUE
RtlAllocateHeap2ndfStub endp

xRtlpCheckHeapSignatureStub:
	%GET_CURRENT_GRAPH_ENTRY
RtlpCheckHeapSignatureStub proc C
	mov eax,TRUE
	%SROUTE_CONTINUE
RtlpCheckHeapSignatureStub endp

xXcptSkipTraceStub:
	%GET_CURRENT_GRAPH_ENTRY
XcptSkipTraceStub proc C
	push EFLAGS_TF or EFLAGS_IF or EFLAGS_MASK
	popfd
	%SROUTE_CONTINUE	; Трап возникнет после ветвления.
XcptSkipTraceStub endp

xXcptUnwindStub:
	%GET_CURRENT_GRAPH_ENTRY
XcptUnwindStub proc C


XcptUnwindStub endp

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

PcStackBase	equ 4
PcStackLimit	equ 8

DbgIsTargetCaller proc uses ebx esi edi
	assume esi:PSTACK_FRAME
	mov esi,ebp
Scan:
	cmp fs:[PcStackBase],esi
	jna Error
	cmp fs:[PcStackLimit],esi
	ja Error
Check:
	cmp [esi].Ip,71A3475FH
	je lTarget
	mov esi,[esi].Next
	inc edi
	jmp Scan
Error:	
	xor eax,eax
	jmp Exit
lTarget:
	mov eax,esi
Exit:
	ret
DbgIsTargetCaller endp

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
XcptDispatch proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS, ContinueHandler:PVOID, Tls:PVOID
Local Caller:GP_CALLER, Caller2ndf:GP_CALLER, Gp:PVOID	
Local WspSnapshot:GP_SNAPSHOT
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
	mov eax,[esi].ExceptionCode
	jz Chain
	cmp eax,DBG_PRINTEXCEPTION_C
	je Load	; Хэндлим весь вывод.
	cmp eax,STATUS_BREAKPOINT
	je XcptBreak
	cmp eax,STATUS_SINGLE_STEP
	je XcptTrap
	cmp eax,STATUS_INVALID_HANDLE
	je XcptBadref
	cmp eax,STATUS_ACCESS_VIOLATION
	jne Chain
; Если фолт в текущем коде, то пропускаем его.
; VOID
; RtlUnwind (
;    IN PVOID TargetFrame OPTIONAL,
;    IN PVOID TargetIp OPTIONAL,
;    IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
;    IN PVOID ReturnValue
;    );
	lea ecx,Gp
	lea edx,[ebx].BodySnapshot
	push ecx
	push [esi].ExceptionAddress
	push edx
	%GPCALL GP_CS_CHECK_IP_BELONG_TO_SNAPSHOT
	test eax,eax
	jnz Chain
Unwind:
	%GET_GRAPH_ENTRY xXcptUnwindStub
;	mov edx,[ebx].Apis.RtlUnwind
	mov [edi].regEcx,eax
	mov [edi].regEdx,edx
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
	%TLS_IS_STRACE
	jc SkipPost
	%TLS_IS_TRACE
	jnc Chain	; Трассировка не запущена, передаём фолт в вышестоящий хэндлер.
DBG_XCPT_TRAP_IS_WSP_SNAP::
	lea ecx,Gp
	lea edx,[ebx].WspSnapshot
	push ecx
	push [esi].ExceptionAddress
	push 0
	push edx
	%GPCALL GP_RW_CHECK_IP_BELONG_TO_SNAPSHOT
	test eax,eax
	jz IsCall
	%STOP_TRACE	; Изза ошибки не произошло открытие девайса, либо возник фолт и передан в системный сех.
	jmp Load

; +
; Останов в слепке. Проверяем на вызов стаба ZwCreateFile.
DBG_XCPT_TRAP_DIS::
IsCall:
	push [esi].ExceptionAddress
	%GPCALL GP_PFX
	test eax,eax
	mov ecx,[esi].ExceptionAddress
	jnz SetTF
	movzx eax,byte ptr [ecx]	; Opcode
	cmp al,OP_CALL_REL
	je Skip
	cmp al,OP_CALL_FAR_PTR
	je SetTF
	cmp al,0FFH
	jne SetTF
; Grp 5.
	movzx eax,byte ptr [ecx + 1]
	and al,MODRM_REG_MASK
	shr al,3
	cmp al,10B
	jne SetTF
DBG_XCPT_TRAP_PRE_SKIP::
Skip:
	%TLS_START_STRACE
	%START_TRACE
	jmp Load

; +
DBG_XCPT_PRINT_IS_HMGR_MSG::
XcptPrint:
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
	jnz Chain
	
	; jmp HmgrLoad
	
; Выполняем S-маршрутизацию для корректировки возвращаемого значения из RtlpCheckHeapSignature().
DBG_XCPT_BREAK_DISPATCH::
HmgrRoute:
	%TLS_IS_TRACE
	jc HmgrLoad	; Трассировка запущена, маршрутизация была выполнена.
	lea ecx,Caller2ndf
	mov eax,[ebx].WspSnapshot.GpRoutine
	lea edx,WspSnapshot
	mov WspSnapshot.GpBase,eax
	mov WspSnapshot.GpLimit,NULL
	push ecx
	push TRUE
	push UserMode
	push [edi].regEbp
	push 0
	push edx
	%GPCALL GP_FIND_CALLER_BELONG_TO_SNAPSHOT
	test eax,eax
	.if Zero?
DBG_XCPT_ROUTE_AllocateHeap::
	   %GET_GRAPH_ENTRY xRtlAllocateHeap2ndfStub
	   mov ecx,Caller2ndf.Frame
	   xchg STACK_FRAME.Ip[ecx],eax
	   %TLS_SET_2NDF_STUB Eax
	.endif
DBG_XCPT_ROUTE_RtlpCheckHeapSignature::
HmgrLoad:
	%GET_GRAPH_ENTRY xRtlpCheckHeapSignatureStub
	mov ecx,Caller.Frame
	mov ecx,STACK_FRAME.Next[ecx]	; NL = 1
	xchg STACK_FRAME.Ip[ecx],eax
	%TLS_SET_STUB Eax
	inc [edi].regEip	; Int3
	jmp Load

; +
DBG_XCPT_TRAP_POST_SKIP::
SkipPost:
	mov eax,[esi].ExceptionAddress
	cmp [ebx].Apis.pZwCreateFile,eax
	mov ecx,[edi].regEsp
	jne SkipRoute	; S-маршрутизация на !NL для пропускания процедуры.
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
DBG_XCPT_TRAP_IS_AFD::
	mov eax,dword ptr [ecx + 2*4]	; POBJECT_ATTRIBUTES
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
	nop

DBG_XCPT_SKIP_ROUTE::
SkipRoute:
	%STOP_TRACE
	%TLS_STOP_STRACE
	%GET_GRAPH_ENTRY xXcptSkipTraceStub
	mov ecx,[edi].regEsp
	xchg dword ptr [ecx],eax
	%TLS_SET_STUB Eax
	jmp Load
	
XcptBadref:

SetTF:
	%START_TRACE
	jmp Load
ResetTF:
	%STOP_TRACE
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp Exit
Chain:
	jmp $
	
	xor eax,eax
Exit:
	ret
XcptDispatch endp