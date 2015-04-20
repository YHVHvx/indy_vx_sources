; o GCBE
; o (c) Indy, 2011.

GP_SNAPSHOT struct
Ip		PVOID ?	; Адрес разбираемой процедуры.
GpBase	PVOID ?	; Базовый адрес буфера с графом.
GpLimit	PVOID ?	; Лимит графа(размер + GpBase).
GP_SNAPSHOT ends
PGP_SNAPSHOT typedef ptr GP_SNAPSHOT

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
RwFindCallerBelongToSnapshot proc uses ebx esi edi Snapshot:PGP_SNAPSHOT, NL:ULONG, Sfc:PSTACK_FRAME, Mode:ULONG, Trace:BOOLEAN, Caller:PGP_CALLER
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
	invoke RwCheckIpBelongToSnapshot, Snapshot, NL, [esi].Ip, Caller
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
RwFindCallerBelongToSnapshot endp

; +
;
CsDirectSearchEntryReferenceInternal proc uses ebx GpBase:PVOID, GpLimit:PVOID, GpEntry:PVOID
	mov ebx,GpBase
Check:
	cmp GpLimit,ebx
	ja @f
	xor eax,eax
	jmp Exit
@@:
	cmp GpEntry,ebx
	mov eax,dword ptr [ebx + EhEntryType]
	je Next
	mov ecx,dword ptr [ebx + EhFlink]
	and ecx,NOT(TYPE_MASK)
	cmp GpEntry,ecx
	je Save
	and eax,TYPE_MASK
	jz Next
	cmp eax,HEADER_TYPE_JCC
	mov ecx,dword ptr [ebx + EhBranchLink]
	je IsValid
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz Next
	dec eax
	.if Zero?	; Call
		test dword ptr [ebx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
		jz Next
	.endif
IsValid:
	and ecx,NOT(TYPE_MASK)
	cmp GpEntry,ecx
	je Save
Next:
	add ebx,ENTRY_HEADER_SIZE
	jmp Check
Save:
	mov eax,ebx
Exit:
	ret
CsDirectSearchEntryReferenceInternal endp

; +
; Быстрый поиск описателя.
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

; +
; Ищет начало процедуры.
;
comment '
typedef PVOID (*PSEARCH_HEAD_CALLBACK)(
   IN PGP_SNAPSHOT Snapshot,
   IN PVOID GraphEntryForSearch,
   IN PVOID GraphEntryForCheck
   );
   
typedef NTSTATUS (*PENTRY)(
   IN PGP_SNAPSHOT Snapshot,
   IN PVOID Gp OPTIONAL,
   IN PVOID Ip,
   IN ULONG NestingLevel,
   OUT PCALL_HEADER GraphEntry
   );
   '
CsSearchRoutineEntry proc uses ebx esi edi Snapshot:PGP_SNAPSHOT, Gp:PVOID, Ip:PVOID, NestingLevel:ULONG, GraphEntry:PVOID
	mov esi,Gp
	inc NestingLevel
	test esi,esi
	mov ebx,Snapshot
	assume ebx:PGP_SNAPSHOT
	.if Zero?
	   invoke CsCheckIpBelongToSnapshot, Ebx, Ip, addr Gp
	   test eax,eax
	   mov esi,Gp
	   jnz Exit
	.endif
	cld
	cmp [ebx].GpLimit,esi
	jbe Error
FindHead:
	mov edx,dword ptr [esi + EhBlink]
	and edx,NOT(TYPE_MASK)
	jnz @f
	mov edi,[ebx].GpBase
	jmp NewBlock
@@:
	mov esi,edx
	jmp FindHead
NewBlock:
	invoke CsDirectSearchEntryReferenceInternal, Edi, [ebx].GpLimit, Esi
	mov Gp,eax
	test eax,eax
	jnz @f
	mov ecx,GraphEntry
	mov eax,STATUS_NO_MORE_ENTRIES
	mov dword ptr [ecx],esi
	jmp Exit
@@:
	mov esi,eax
	mov ecx,dword ptr [esi + EhEntryType]
	and ecx,TYPE_MASK
	jz FindHead	; line
	dec ecx
	jnz FindHead	; jcc/jxx
; call
	dec NestingLevel
	mov ecx,GraphEntry
	jnz FindHead
	mov dword ptr [ecx],esi
Exit:
	xor eax,eax
	ret
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
CsSearchRoutineEntry endp