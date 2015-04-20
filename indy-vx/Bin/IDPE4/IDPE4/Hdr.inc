; OPT_DISABLE_TEB	equ TRUE
TLS_SLOTS_NUMBER	equ 1	; Расширенная инфа.

PPVOID	typedef ptr PVOID

%GET_CURRENT_GRAPH_ENTRY macro
	Call GPREF
endm

%GET_GRAPH_ENTRY macro PGET_CURRENT_GRAPH_ENTRY
	Call PGET_CURRENT_GRAPH_ENTRY
endm

%GET_GRAPH_REFERENCE macro
GPREF::
	pop eax
	ret
endm

	%GET_GRAPH_REFERENCE

RDMUX	equ 0
WRMUX	equ 1

%BLOCK macro Mux, Bit
	.repeat
		bts Mux,Bit
	.until !Carry?
endm

%BUNLOCK macro Mux, Bit
	btr Mux, Bit
endm

RWLOCK struct
Mux		DWORD ?
Rc		ULONG ?
RWLOCK ends
PRWLOCK typedef ptr RWLOCK

; Ecx: PRWLOCK
;
EvReadLock proc C
	assume ecx:PRWLOCK	
	%BLOCK [Ecx].Mux, RDMUX
	inc [ecx].Rc	; mb XADD
	.if [Ecx].Rc == 1
		%BLOCK [Ecx].Mux, WRMUX
	.endif
	%BUNLOCK [Ecx].Mux, RDMUX
	ret
EvReadLock endp

EvReadUnlock proc C
	%BLOCK [Ecx].Mux, RDMUX
	dec [ecx].Rc
	.if Zero?
		%BUNLOCK [Ecx].Mux, WRMUX
	.endif
	%BUNLOCK [Ecx].Mux, RDMUX
	ret
EvReadUnlock endp

EvWriteLock proc C
	%BLOCK RWLOCK.Mux[ecx], WRMUX
	ret
EvWriteLock endp

EvWriteUnlock proc C
	%BUNLOCK RWLOCK.Mux[ecx], WRMUX
	ret
EvWriteUnlock endp

%RLOCK macro pLock
	lea ecx,pLock
	Call EvReadLock
endm

%RUNLOCK macro pLock
	lea ecx,pLock
	Call EvReadUnlock
endm

%WLOCK macro pLock
	lea ecx,pLock
	Call EvWriteLock
endm

%WUNLOCK macro pLock
	lea ecx,pLock
	Call EvWriteUnlock
endm

%ISRLOCK macro Mux
	bt Mux, RDMUX
endm

%ISWLOCK macro Mux
	bt Mux, WRMUX
endm

%GETENVPTR macro
	Call EvGetPtr
endm

L0	equ <>

LOCK_INIT		equ 0	; Переменная не инициализирована.
LOCK_WAIT		equ 1	; Выполняется инициализация.
LOCK_FAIL		equ 2	; Инициализация прошла с ошибкой.

%PLOCK macro pLock, pInit, pFail
	mov ecx,LOCK_WAIT
	xor eax,eax	; LOCK_INIT
@@:
	cmpxchg pLock,ecx
	je pInit
	dec eax	; LOCK_WAIT
	jz @b
	ifdef pFail
		dec eax
		jz pFail
		inc eax
	endif
	inc eax
endm

%PUNLOCK macro pLock, Event
	ifdef Event
		mov pLock,Event
	else
		pop pLock
	endif
endm

SEGMENT_ENTRY struct
Base			PVOID ?
Limit		ULONG ?
Address		PVOID ?	; Адрес области памяти.
Reference		PVOID ?	; Адрес переменной, ссылающейся на область памяти.
SegBase		PVOID ?	; База сегмента.
Selector		DWORD ?
SEGMENT_ENTRY ends
PSEGMENT_ENTRY typedef ptr SEGMENT_ENTRY

FACILITY_IDP_ENGINE	equ 0FEH

STATUS_SCALE_FACILITY	equ 16
STATUS_SCALE_R			equ 28
STATUS_SCALE_C			equ 29
STATUS_SCALE_SEVERITY	equ 30

STATUS_SEVERITY_WARNING	equ 2

IDP_BREAKPOINT		equ ((STATUS_SEVERITY_WARNING shl STATUS_SCALE_SEVERITY) or (FACILITY_IDP_ENGINE shl STATUS_SCALE_FACILITY) or 0001H)	; Code = 1, 0x80FE0001
IDP_SINGLE_STEP	equ ((STATUS_SEVERITY_WARNING shl STATUS_SCALE_SEVERITY) or (FACILITY_IDP_ENGINE shl STATUS_SCALE_FACILITY) or 0002H)	; Code = 2, 0x80FE0002

THREAD_STATE struct
rEFlags		DWORD ?
rDs			DWORD ?
rEs			DWORD ?
rFs			DWORD ?
rGs			DWORD ?
pSegment		PSEGMENT_ENTRY ?
THREAD_STATE ends
PTHREAD_STATE typedef ptr THREAD_STATE

TLS_IDP_BIT		equ 0
TLS_IDP_MASK		equ 001B

TLS_ENTRY struct
Teb		PTEB ?
Tid		HANDLE ?	; Thread Id
Flags	ULONG ?	; TLS_*
Idp		THREAD_STATE <>
Exts		PVOID TLS_SLOTS_NUMBER DUP (?)
TLS_ENTRY ends
PTLS_ENTRY typedef ptr TLS_ENTRY

%TLS_START_IDP macro pTls
	bts TLS_ENTRY.Flags[pTls],TLS_IDP_BIT
endm

%TLS_STOP_IDP macro pTls
	btr TLS_ENTRY.Flags[pTls],TLS_IDP_BIT
endm

%TLS_IS_IDP macro pTls
	bt TLS_ENTRY.Flags[pTls],TLS_IDP_BIT
endm

IDP_MAX_ENTRIES	equ 128

IDP_TEB_OFFSET		equ (X86_PAGE_SIZE - 4)

%TLSSET macro Value
	mov dword ptr fs:[IDP_TEB_OFFSET],Value
endm

%TLSGET macro Reg32
	mov Reg32,dword ptr fs:[IDP_TEB_OFFSET]
endm

TLS_MAX_ENTRIES	equ 800H

; +
; o Ссылка на среду защищена спинлоком.
;
UENV struct
pZwAllocateVirtualMemory			PVOID ?
pZwProtectVirtualMemory			PVOID ?
pZwFreeVirtualMemory			PVOID ?

LpZwQueryVirtualMemory			ULONG ?
LpZwSetLdtEntries				ULONG ?
LpZwQueryInformationThread		ULONG ?

SegCount						ULONG ?	; ~SegList
LastSelector					ULONG ?	; SegList[SegCount].Selector

IdpCount						ULONG ?
IdpLock						RWLOCK <>
	pKiUserExceptionDispatcher	PVOID ?
	pRtlAddVectoredExceptionHandler	PVOID ?
	pRtlRemoveVectoredExceptionHandler	PVOID ?
	pDbgBreakPoint				PVOID ?
	BugIp					PVOID ?
	BugEvent					ULONG ?	; XCPT_*
	Handle					PLIST_ENTRY ?
	SegList					SEGMENT_ENTRY IDP_MAX_ENTRIES DUP (<>)
	
TlsLock						RWLOCK <>
Tls							TLS_ENTRY TLS_MAX_ENTRIES DUP (<>)
UENV ends
PUENV typedef ptr UENV

XCPT_INIT		equ 0
XCPT_BREAK	equ 1
XCPT_TRAP		equ 2
XCPT_SKIP		equ 3
XCPT_END		equ 4

EOL	equ NULL
CRLF	equ <13, 10, EOL>

ENV_OFFSET	equ (X86_PAGE_SIZE - 4)

%APICALL macro pApi, Args
	Call pApi
endm

; defin ks386.inc
TePeb	equ 30H	; TEB.Peb
PcSelfPcr	equ 1CH

%DBG macro Msg$, ArgList:VARARG
Local S$
	ifdef OPT_ENABLE_DBG_LOG
		pushfd
		pushad
		Args = 1
		For Arg, <ArgList>
			Args = Args + 1
			push Arg
		Endm
	.data
		S$ CHAR Msg$, CRLF
	.code
		push offset S$
		Call DbgPrint
		add esp,Args * 4
		popad
		popfd
	endif
endm

SEL_TABLE_MASK	equ 100B

DESCRIPTOR_TABLE_ENTRY struct
Selector		ULONG ?
Descriptor	DWORD 2 DUP (?)	; LDT_ENTRY
DESCRIPTOR_TABLE_ENTRY ends
PDESCRIPTOR_TABLE_ENTRY typedef ptr DESCRIPTOR_TABLE_ENTRY