; o GCBE
; o (c) Indy, 2011.

GP_SNAPSHOT struct
Ip		PVOID ?	; Адрес разбираемой процедуры.
GpBase	PVOID ?	; Базовый адрес буфера с графом.
GpLimit	PVOID ?	; Лимит графа(размер + GpBase).
GP_SNAPSHOT ends
PGP_SNAPSHOT typedef ptr GP_SNAPSHOT

; +
; Быстрый поиск(не трассирока графа) описателя.
;
CsCheckIpBelongToSnapshot proc uses ebx esi edi Snapshot:PGP_SNAPSHOT, Ip:PVOID, GpEntry:PVOID
	mov ebx,Snapshot
	assume ebx:PGP_SNAPSHOT
	mov edi,GpEntry
	mov eax,[ebx].GpBase
	cld
	cmp [ebx].GpLimit,eax
	jbe Error
	assume eax:PBLOCK_HEADER
Entry:
	mov edx,[eax].Address
	cmp Ip,edx
	je Load
	jb Next
	mov ecx,dword ptr [eax + EhEntryType]
	and ecx,TYPE_MASK
	jnz Next
	add edx,[eax]._Size
	cmp Ip,edx
	jb Load
Next:
	add eax,ENTRY_HEADER_SIZE
	cmp [ebx].GpLimit,eax
	ja Entry
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
Load:
	stosd
	xor eax,eax
Exit:
	ret
CsCheckIpBelongToSnapshot endp

STACK_FRAME struct
Next		PVOID ?	; PSTACK_FRAME
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

GP_CALLER struct
GpEntry		PVOID ?	; 1st
Frame		PSTACK_FRAME ?
SFN			ULONG ?
GP_CALLER ends
PGP_CALLER typedef ptr GP_CALLER

PcStackBase	equ 4
PcStackLimit	equ 8

TsDbgArgMark	equ 00008H	; KTRAP_FRAME.DbgArgMark

KernelMode	equ 0
UserMode		equ 1

TRACE_CALLBACK_DATA struct
Ip			PVOID ?
GpEntry		PVOID ?
TRACE_CALLBACK_DATA ends
PTRACE_CALLBACK_DATA typedef ptr TRACE_CALLBACK_DATA

RwCheckIpBelongToSnapshotTraceCallback:
	%GET_CURRENT_GRAPH_ENTRY
RwCheckIpBelongToSnapshotTraceCallbackInternal proc uses ebx GpEntry:PVOID, CallbackData:PTRACE_CALLBACK_DATA
	mov ebx,CallbackData
	assume ebx:PTRACE_CALLBACK_DATA
	mov edx,GpEntry
	assume edx:PBLOCK_HEADER
	mov eax,[edx].Address
	cmp [ebx].Ip,eax
	je Load
	jb Exit
	mov ecx,dword ptr [edx + EhEntryType]
	and ecx,TYPE_MASK
	jnz Exit
	add eax,[edx]._Size
	cmp [ebx].Ip,eax
	jae Exit
Load:
	mov [ebx].GpEntry,edx
Exit:
	xor eax,eax
	ret
RwCheckIpBelongToSnapshotTraceCallbackInternal endp

; +
;
RwCheckIpBelongToSnapshot proc uses ebx SnapshotInformation:PGP_SNAPSHOT, NL:ULONG, Ip:PVOID, GpEntry:PVOID
Local CallbackData:TRACE_CALLBACK_DATA
	mov eax,Ip
	lea ecx,CallbackData
	mov CallbackData.GpEntry,NULL
	mov CallbackData.Ip,eax
	push ecx
	mov edx,SnapshotInformation
	%GET_GRAPH_ENTRY RwCheckIpBelongToSnapshotTraceCallback
	push eax
	push NL
	push GP_SNAPSHOT.GpBase[edx]
	Call RwTrace
	mov ecx,GpEntry
	test eax,eax
	mov edx,CallbackData.GpEntry
	.if Zero?
	   mov dword ptr [ecx],edx
	   .if !Edx
	      mov eax,STATUS_NOT_FOUND
	   .endif
	.endif
	ret
RwCheckIpBelongToSnapshot endp

; +
; Разворачивает SFC и ищет для каждого адреса возврата описатель в графе.
;
; o Только для текущего потока.
;
GpFindCallerBelongToSnapshot proc uses ebx esi edi Snapshot:PGP_SNAPSHOT, Raw:BOOLEAN, NL:ULONG, Sfc:PSTACK_FRAME, Mode:ULONG, Trace:BOOLEAN, Caller:PGP_CALLER
	mov esi,Sfc
	mov ebx,Caller
	xor edi,edi	; SFN
	assume esi:PSTACK_FRAME
	assume ebx:PGP_CALLER
	.if !Esi
	   mov esi,ebp
	.endif
Scan:
	cmp fs:[PcStackBase],esi
	jna Error
	cmp fs:[PcStackLimit],esi
	ja Error
	cmp Mode,KernelMode
	jne Check
	cmp dword ptr [esi + TsDbgArgMark],0BADB0D00H
	je Error	; Trap frame.
Check:
	cmp Raw,FALSE
	push Caller
	push [esi].Ip
	.if !Zero?
	   push NL
	   push Snapshot
	   Call RwCheckIpBelongToSnapshot 
	.else
	   push Snapshot
	   Call CsCheckIpBelongToSnapshot
	.endif
	test eax,eax
	jz Found
	cmp eax,STATUS_NOT_FOUND
	jne Exit	; #AV etc.
	mov esi,[esi].Next
	inc edi
	jmp Scan
Found:
	mov [ebx].Frame,esi
	mov [ebx].SFN,edi
	jmp Exit
Error:	
	mov eax,STATUS_NOT_FOUND
Exit:
	ret
GpFindCallerBelongToSnapshot endp