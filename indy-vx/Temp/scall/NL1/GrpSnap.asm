; o GCBE
; o (c) Indy, 2011.

%IS_VALID_FRAME macro pFrame, pError
	cmp fs:[PcStackBase],pFrame
	jna pError
	cmp fs:[PcStackLimit],pFrame
	ja pError
endm

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
	assume eax:PBLOCK_ENTRY
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
	add eax,ENTRY_SIZE
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
NL			ULONG ?
GpEntry		PVOID ?
TRACE_CALLBACK_DATA ends
PTRACE_CALLBACK_DATA typedef ptr TRACE_CALLBACK_DATA

RwCheckIpBelongToSnapshotTraceCallback:
	%GET_CURRENT_GRAPH_ENTRY
RwCheckIpBelongToSnapshotTraceCallbackInternal proc uses ebx GpEntry:PVOID, NL:ULONG, List:PVOID, CallbackData:PTRACE_CALLBACK_DATA
	mov ebx,CallbackData
	assume ebx:PTRACE_CALLBACK_DATA
	mov edx,GpEntry
	assume edx:PBLOCK_ENTRY
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
	mov ecx,NL
	mov [ebx].GpEntry,edx
	mov [ebx].NL,ecx
Exit:
	xor eax,eax
	ret
RwCheckIpBelongToSnapshotTraceCallbackInternal endp

; +
; Поиск описателя.
;
RwCheckIpBelongToSnapshot proc GpBase:PVOID, NL:ULONG, NLip:PULONG, Ip:PVOID, GpEntry:PVOID
Local CallbackData:TRACE_CALLBACK_DATA
	mov eax,Ip
	lea ecx,CallbackData
	mov CallbackData.GpEntry,NULL
	mov CallbackData.Ip,eax
	push ecx
	%GET_GRAPH_ENTRY RwCheckIpBelongToSnapshotTraceCallback
	push eax
	push NL
	push GpBase
	Call RwTrace
	.if NL != GCBE_NL_UNLIMITED
; Трассировка части графа требует восстановление AF.
		push eax
		push NULL
		push NULL
		push NL
		push GpBase
		Call RwTrace
		pop eax
	.endif
	mov ecx,GpEntry
	test eax,eax
	mov edx,CallbackData.GpEntry
	.if Zero?
		mov dword ptr [ecx],edx
		.if !Edx
			mov eax,STATUS_NOT_FOUND
		.else
			cmp NLip,eax
			mov ecx,NLip
			mov edx,CallbackData.NL
			.if !Zero?
				mov dword ptr [ecx],edx
			.endif
		.endif
	.endif
	ret
RwCheckIpBelongToSnapshot endp

; +
; Разворачивает SFC и ищет для каждого адреса возврата описатель в графе.
;
; o Только для текущего потока.
;
GpFindCallerBelongToSnapshot proc uses ebx esi edi Snapshot:PGP_SNAPSHOT, Raw:BOOLEAN, NL:ULONG, Sfc:PSTACK_FRAME, Mode:ULONG, Caller:PGP_CALLER
	mov esi,Sfc
	mov ebx,Caller
	xor edi,edi	; SFN
	assume esi:PSTACK_FRAME
	assume ebx:PGP_CALLER
	.if !Esi
		mov esi,ebp
	.endif
Scan:
	%IS_VALID_FRAME Esi, Error
	cmp Mode,KernelMode
	jne Check
	cmp dword ptr [esi + TsDbgArgMark],0BADB0D00H
	je Error	; Trap frame.
Check:
	cmp Raw,FALSE
	push Caller
	push [esi].Ip
	mov eax,Snapshot
	.if !Zero?
		push NULL
		push NL
		push GP_SNAPSHOT.GpBase[eax]
		Call RwCheckIpBelongToSnapshot 
	.else
		push eax
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

GP_FRAME struct
First	PVOID ?
Last		PVOID ?	; "STACK_FRAME.Next[First]"
GP_FRAME ends
PGP_FRAME typedef ptr GP_FRAME

; +
; Валидация одного стекового фрейма.
;
RwValidateFrame proc GpBase:PVOID, IpFirst:PVOID, IpNext:PVOID, Frame:PGP_FRAME, NL:PULONG
Local GpFirst:PCALL_ENTRY, GpNext:PCALL_ENTRY
	invoke RwCheckIpBelongToSnapshot, GpBase, GCBE_NL_UNLIMITED, NL, IpNext, addr GpNext
	test eax,eax
	mov ecx,GpNext
	jnz Exit
	mov eax,dword ptr [ecx + EhBlink]
	and eax,NOT(TYPE_MASK)
	jz Error
	mov ecx,dword ptr [eax + EhEntryType]
	and ecx,TYPE_MASK
	cmp cl,ENTRY_TYPE_CALL
	jne Error
	test dword ptr [eax + EhBranchType],BRANCH_DEFINED_FLAG
	jz Error
	test dword ptr [eax + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	mov ecx,dword ptr [eax + EhBranchLink]
	jz Error
	and ecx,NOT(TYPE_MASK)
	invoke RwCheckIpBelongToSnapshot, Ecx, GCBE_NL_PRIMARY, NULL, IpFirst, addr GpFirst
	test eax,eax
	mov ecx,GpFirst
	jnz Exit
	mov eax,dword ptr [ecx + EhBlink]
	and eax,NOT(TYPE_MASK)
	jz Error
	mov ecx,dword ptr [eax + EhEntryType]
	and ecx,TYPE_MASK
	cmp cl,ENTRY_TYPE_CALL
	mov edx,Frame
	jne Error
	.if Edx
		push GpFirst
		push GpNext
		pop GP_FRAME.Last[edx]
		pop GP_FRAME.First[edx]
	.endif
	xor eax,eax
Exit:
	ret
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
RwValidateFrame endp

; +
;
RwIsValidCaller proc uses ebx esi edi GpBase:PVOID, StFrame:PSTACK_FRAME, Frame:PGP_FRAME
Local GpEntry:PVOID
Local NL:ULONG
	mov ebx,StFrame
	.if !Ebx
		mov ebx,ebp
	.endif
	assume ebx:PSTACK_FRAME
Next:
	%IS_VALID_FRAME Ebx, Error
	mov edi,ebx
	.repeat
		mov esi,[ebx].Next
		%IS_VALID_FRAME Esi, Error
		assume esi:PSTACK_FRAME
		invoke RwValidateFrame, GpBase, [Ebx].Ip, [Esi].Ip, NULL, addr NL
		test eax,eax
		mov ebx,esi
		jnz Next
	.until NL == Eax
	mov ecx,Frame
	mov GP_FRAME.First[ecx],edi
	mov GP_FRAME.Last[ecx],ebx
Exit:
	ret
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
RwIsValidCaller endp