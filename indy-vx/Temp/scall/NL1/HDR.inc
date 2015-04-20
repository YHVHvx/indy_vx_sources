PPVOID	typedef ptr PVOID

	assume fs:nothing
SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	%GET_GRAPH_ENTRY xSEH_GetRef
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	push ecx
	ret
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 2*4]
	pop ebp
	push ecx
	ret
SEH_Epilog endp

xSEH_GetRef:
	%GET_CURRENT_GRAPH_ENTRY
SEHP proc C
	mov eax,dword ptr [esp + 4]
	mov ecx,dword ptr [esp + 3*4]	; Ctx.
;	mov edx,dword ptr [esp]	; ~ nt!ExecuteHandler2().
	mov ebx,CONTEXT.regEbx[ecx]
	mov esi,CONTEXT.regEsi[ecx]
	mov edi,CONTEXT.regEdi[ecx]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov ecx,EXCEPTION_RECORD.ExceptionAddress[eax]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	push dword ptr [esp + 2*4]
	ret
SEHP endp

%SEHPROLOG macro EpilogLabel
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog_Reference
		Call SEH_Prolog
	endif
endm

%SEHPROLOGEX macro EpilogLabel
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog_Reference
		Call SEH_PrologEx
	endif
endm

%SEHEPILOG macro ExitLabel
	ifdef FLG_ENABLE_SEH
		jmp Exit
 	SEH_Epilog_Reference:
		%GET_CURRENT_GRAPH_ENTRY
	endif
	ifndef ExitLabel
  Exit:
  	else
  ExitLabel:
 	endif
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog
	endif
endm

L0	equ <>

LOCK_ZERO		equ 0
LOCK_WAIT		equ 1
LOCK_INIT		equ 2
LOCK_FAIL		equ 3

%SPINWAIT macro pLock
	.repeat
		cmp pLock,LOCK_WAIT
	.until !Zero?
endm

%SPINLOCK macro pLock, pInit, pFail
	mov ecx,1
	xor eax,eax
	.repeat
		lock cmpxchg pLock,ecx
		je pInit
		dec eax
	.until !Zero?
	ifdef pFail
		dec eax
		jz pFail
	endif
endm

%LOCKREAD macro pLock, pInit, pFail
	mov ecx,1
	.repeat
	xor eax,eax
		lock cmpxchg pLock,ecx
		je pInit
		dec eax
	.until !Zero?
	ifdef pFail
		dec eax
		jz pFail
		inc eax
	endif
	inc eax
endm

%ISLOCKZ macro pLock
	cmp pLock,LOCK_WAIT
endm

%UNLOCK macro pLock, Event
	mov pLock,Event
endm

APISTUB struct
	; typedef NTSTATUS (NTAPI *PCSR_SERVER_API_ROUTINE)(IN PPORT_MESSAGE Request, IN PPORT_MESSAGE Reply);
	Gate		PVOID ?	; Call [CsrServerApiRoutine]
	Link		PVOID ?	; CsrServerApiRoutine
	; PCSR_SERVER_API_ROUTINE CsrServerApiRoutine
	Back		PVOID ?	; Ip'
	pFlag	PVOID ?	; CsrServerProcess
	Flag		ULONG ?	; BYTE [CsrServerProcess]
	Cookie	PVOID ?	;
	Chain	PVOID ?	; [CsrServerApiRoutine]
APISTUB ends
PAPISTUB typedef ptr APISTUB

XCPT_SNAPS struct
RwSnap	GP_SNAPSHOT <>	; Нелинейный граф.
CsSnap	GP_SNAPSHOT <>	; Линейный граф для билдера.
BdSnap	GP_SNAPSHOT <>	; Выходной буфер.
XCPT_SNAPS ends
PXCPT_SNAPS typedef ptr XCPT_SNAPS

XCPT_COOKIE_REG	equ <Edx>

; +
; o Ссылка на среду защищена спинлоком.
;
UENV struct
pZwAllocateVirtualMemory			PVOID ?
pZwProtectVirtualMemory			PVOID ?
pZwFreeVirtualMemory			PVOID ?

LockGate						ULONG ?
	FastGate					PVOID ?	; ~ KiFastSystemCall()
	SysGate					PVOID ?	; ~ KiIntSystemCall()


LockXcpt						ULONG ?	
	pKiUserExceptionDispatcher	PVOID ?
	pRtlAddVectoredExceptionHandler	PVOID ?
	pZwQueryInformationProcess	PVOID ?
	XcptSnap					XCPT_SNAPS <>
	VEH						PLIST_ENTRY ?

XcptIp						PVOID ?	; ~ RtlCallVectoredExceptionHandlers()
XcptCookie					PVOID ?	; Системный хэндлер, значение передаёт менеджер фолтов в SEH: rEdx

LpZwQueryVirtualMemory			ULONG ?
	pZwQueryVirtualMemory		PVOID ?

LpRtlRaiseStatus				ULONG ?
	pRtlRaiseStatus			PVOID ?

LpZwSetLdtEntries				ULONG ?
	pZwSetLdtEntries			PVOID ?

LpZwQuerySystemInformation		ULONG ?
	pZwQuerySystemInformation	PVOID ?

LpZwAreMappedFilesTheSame		ULONG ?
	pZwAreMappedFilesTheSame		PVOID ?

LpZwQueryPerformanceCounter		ULONG ?
	pZwQueryPerformanceCounter	PVOID ?

Tsc							LARGE_INTEGER <>	; Edx:Eax
Tick							LARGE_INTEGER <>

LockApi						ULONG ?
	ApiStub					APISTUB <>

;pZwContinue					PVOID ?	; @ZwContinue()
;pZwGetContextThread				PVOID ?	; @ZwGetContextThread()
UENV ends
PUENV typedef ptr UENV

KENV struct
pExAllocatePool				PVOID ?
pExFreePool					PVOID ?

NtBase						PVOID ?

LockGate						ULONG ?
	SysGate					PVOID ?	; @KiSystemService()
Tsc							LARGE_INTEGER <>
Tick							LARGE_INTEGER <>

LpKeQueryPerformanceCounter		ULONG ?
	pKeQueryPerformanceCounter	PVOID ?

KENV ends
PKENV typedef ptr KENV

EOL	equ NULL
CRLF	equ <13, 10, EOL>

ENV_OFFSET	equ (X86_PAGE_SIZE - 4)

; defin ks386.inc
TePeb	equ 30H	; TEB.Peb
PcSelfPcr	equ 1CH
PcIdt	equ 38H

; +
; Определение мода(CF/ZF ~ K-mode).
; 
; 1.
;	push cs
;	test dword ptr [esp],MODE_MASK
;	pop ecx
; 2.
;	mov cx,KGDT_R0_DATA
;	verr cx
;
%CPLCF0 macro
	bt esp,31
endm

%IDT macro Base
	sub esp,2*4
	sidt qword ptr [esp]
	mov Base,dword ptr [esp + 2]	; IDT Base
	add esp,2*4
endm

EFLAGS_V86_MASK equ 020000H

%DBG macro Msg$, ArgList:VARARG
	ifdef OPT_ENABLE_DBG_LOG
		pushfd
		pushad
		Args = 1
		For Arg, <ArgList>
			Args = Args + 1
			push Arg
		Endm
		push offset Msg$
		Call DbgPrint
		add esp,Args * 4
		popad
		popfd
	endif
endm