; Парсинг и анализ HMGR для захвата инвалидацией сигнатуры.
;
; (c) Indy, 2011.
;
; o Одноуровневый граф.
;
.code
	assume eax:nothing, ecx:nothing, edx:nothing, ebx:nothing, esi:nothing, edi:nothing

MSG_HEAP_INVALID_SIGNATURE		equ 033391F16H	; HASH("Invalid heap signature for heap "), 0x20
MSG_HEAP_INVALID_SIGNATURE_LENGTH	equ 32

CALLBACK_DATA struct
pIsSameImage	PVOID ?
Data			PVOID ?
CALLBACK_DATA ends
PCALLBACK_DATA typedef ptr CALLBACK_DATA

OP_CALL	equ 0E8H
OP_PUSH	equ 68H

GpValidateCall proc uses ebx esi GpEntry:PVOID, pIsSameImage:PVOID, Hash:ULONG, HashLength:ULONG, First:BOOLEAN
	mov esi,GpEntry
	assume esi:PCALL_HEADER
	mov eax,dword ptr [esi + EhEntryType]
	and eax,TYPE_MASK
	cmp eax,HEADER_TYPE_CALL
	mov ebx,[esi].Address
	jne Next
; Call
	test dword ptr [esi + EhBranchType],BRANCH_DEFINED_FLAG	; & !DISCLOSURE_CALL_FLAG, так как !NL.
	jz Next
	cmp byte ptr [ebx],OP_CALL
	jne Next
	push ebx
	push [esi].BranchAddress	; @DbgPrint()
	Call pIsSameImage
	test eax,eax
	mov ebx,[esi].Link.Blink
	jnz Next
; Не используем STBAL' engine.
	and ebx,NOT(TYPE_MASK)
	jz Next
	assume ebx:PBLOCK_HEADER
	test dword ptr [ebx + EhEntryType],TYPE_MASK
	jnz Next
	.if First != Eax
	   mov ebx,[ebx].Link.Blink
	   and ebx,NOT(TYPE_MASK)
	   jz Next
	   test dword ptr [ebx + EhEntryType],TYPE_MASK
	   jnz Next
	.endif
	mov eax,[ebx].Address
	cmp byte ptr [eax],OP_PUSH
	jne Next
	mov ebx,dword ptr [eax + 1]
	push [esi].Address
	push ebx
	Call pIsSameImage
	mov ecx,HashLength
	test eax,eax
	lea ecx,[ebx + ecx - 1]
	jnz Next
	push [esi].Address
	push ecx
	Call pIsSameImage
	test eax,eax
	jnz Next
	invoke LdrCalculateHash, 0, Ebx, HashLength
	cmp Hash,eax
	jne Next
	mov eax,[esi].BranchAddress
Exit:
	ret
Next:
	xor eax,eax
	jmp Exit
GpValidateCall endp

; o GCBE_PARSE_SEPARATE
;
xHmgrQueryRtlpCheckHeapSignatureTraceCallback:
	%GET_CURRENT_GRAPH_ENTRY
HmgrQueryRtlpCheckHeapSignatureTraceCallback proc uses ebx GpEntry:PVOID, ClbkData:PCALLBACK_DATA
	mov ebx,ClbkData
	assume ebx:PCALLBACK_DATA
; BOOLEAN
; RtlpCheckHeapSignature (
;    IN PHEAP Heap,
;    IN PCHAR Caller
;    );
	invoke GpValidateCall, GpEntry, [ebx].pIsSameImage, 07E983898H, 12, TRUE	; sizeof("RtlLockHeap") + sizeof(EOL) - 1, &EOL
	.if Eax
	   mov [ebx].Data,eax
	   mov eax,STATUS_MORE_ENTRIES
	.endif
	ret
HmgrQueryRtlpCheckHeapSignatureTraceCallback endp

; o GCBE_PARSE_SEPARATE
;
xHmgrValidateRtlpCheckHeapSignatureTraceCallback:
	%GET_CURRENT_GRAPH_ENTRY
HmgrValidateRtlpCheckHeapSignatureTraceCallback proc uses ebx GpEntry:PVOID, ClbkData:PCALLBACK_DATA
	mov ebx,ClbkData
	assume ebx:PCALLBACK_DATA
; DbgPrint("Invalid heap signature for heap ", )
	invoke GpValidateCall, GpEntry, [ebx].pIsSameImage, MSG_HEAP_INVALID_SIGNATURE, MSG_HEAP_INVALID_SIGNATURE_LENGTH, FALSE	; sizeof("Invalid heap signature for heap ")
	test eax,eax
	.if !Zero?
	   .if [ebx].Data == Eax
	      mov eax,STATUS_MORE_ENTRIES
	   .else
	      xor eax,eax
	   .endif
	.endif
	ret
HmgrValidateRtlpCheckHeapSignatureTraceCallback endp

Public DBG_HMGR_PARSE_RtlLockHeap
Public DBG_HMGR_TRACE_RtlLockHeap
Public DBG_HMGR_PARSE_RtlpCheckHeapSignature
Public DBG_HMGR_TRACE_RtlpCheckHeapSignature

; +
;
HmgrInitialize proc uses ebx esi edi Apis:PAPIS, Result:PGP_SNAPSHOT
Local GpSize:ULONG, Snapshot:GP_SNAPSHOT
Local ClbkData:CALLBACK_DATA
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor eax,eax
	mov ebx,Apis
	assume ebx:PAPIS
	mov Snapshot.GpBase,eax
	mov GpSize,10H * X86_PAGE_SIZE	; < 1 page
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
	add Snapshot.GpBase,0FH * X86_PAGE_SIZE
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
	lea ecx,Snapshot.GpLimit
	push eax
	push eax
	push eax
	push eax
	push eax
	push eax	; !NL
	push GCBE_PARSE_IPCOUNTING or GCBE_PARSE_SEPARATE
	push ecx
	push [ebx].pRtlLockHeap
DBG_HMGR_PARSE_RtlLockHeap::
	%GPCALL GP_PARSE	; !OPT_EXTERN_SEH_MASK
	test eax,eax
	lea ecx,ClbkData
	mov edx,[ebx].pZwAreMappedFilesTheSame
	jnz Free
	mov ClbkData.Data,eax
	mov ClbkData.pIsSameImage,edx
	push ecx
	%GET_GRAPH_ENTRY xHmgrQueryRtlpCheckHeapSignatureTraceCallback
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push esi
DBG_HMGR_TRACE_RtlLockHeap::
	%GPCALL GP_TRACE
	test eax,eax
	jz SignalAndFree
	cmp eax,STATUS_MORE_ENTRIES
	lea ecx,Snapshot.GpLimit
	jne Free
	xor eax,eax
	mov edi,ClbkData.Data
	mov Snapshot.GpLimit,esi
	push eax
	push eax
	push eax
	push eax
	push eax
	push eax	; !NL
; RtlpBreakPointHeap не анализируем, достаточно слепка для RtlpCheckHeapSignature().
	push GCBE_PARSE_IPCOUNTING or GCBE_PARSE_SEPARATE
	push ecx
	push edi	; @RtlpCheckHeapSignature()
DBG_HMGR_PARSE_RtlpCheckHeapSignature::
	%GPCALL GP_PARSE	; !OPT_EXTERN_SEH_MASK	
	test eax,eax
	mov ecx,[ebx].pDbgPrint
	jnz Free
	lea edx,ClbkData
	mov ClbkData.Data,ecx
	push edx
	%GET_GRAPH_ENTRY xHmgrValidateRtlpCheckHeapSignatureTraceCallback
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push esi
DBG_HMGR_TRACE_RtlpCheckHeapSignature::
	%GPCALL GP_TRACE
	test eax,eax
	mov ebx,Result
	jz SignalAndFree
	cmp eax,STATUS_MORE_ENTRIES
	jne Free
	invoke GpCleaningCycle, addr Snapshot
	mov ecx,Snapshot.GpBase
	assume ebx:PGP_SNAPSHOT
	mov edx,Snapshot.GpLimit
	mov [ebx].Ip,edi
	mov [ebx].GpBase,ecx
	mov [ebx].GpLimit,edx
	xor eax,eax
	jmp Exit
SignalAndFree:
	mov eax,STATUS_NOT_FOUND
Free:
	push eax
	mov GpSize,NULL
	lea eax,GpSize
	lea ecx,Snapshot.GpBase
	push MEM_RELEASE
	push eax
	push ecx
	push NtCurrentProcess
	Call APIS.pZwFreeVirtualMemory[ebx]
	pop eax
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
HmgrInitialize endp