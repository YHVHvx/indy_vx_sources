; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; Удаление ветвей.
;
; +
; Трассировка графа без соблюдения приоритетов.
;
RwSlipTrace proc uses ebx Gp:PVOID, CallbackRoutine:PVOID, CallbackContext:PVOID
Local AccessFlag:ULONG
	mov ebx,Gp
	cld
	mov eax,dword ptr [ebx + EhAccessFlag]
	push NULL	; Mark stc.
	and eax,ACCESSED_MASK_FLAG
	mov AccessFlag,eax
Step:
	mov eax,dword ptr [ebx + EhAccessFlag]
	and eax,ACCESSED_MASK_FLAG
	cmp AccessFlag,eax
	jne PopEntry
	xor dword ptr [ebx + EhAccessFlag],ACCESSED_MASK_FLAG
	push CallbackContext
	push ebx
	Call CallbackRoutine
	test eax,eax
	mov ecx,dword ptr [ebx + EhEntryType]
	jnz Exit
	and ecx,TYPE_MASK
	.if Zero?	; Line
ToFlink:
	   mov ebx,dword ptr [ebx + EhFlink]
	   and ebx,NOT(TYPE_MASK)
	   jz PopEntry
	   jmp Step
	.endif
	.if Ecx == ENTRY_TYPE_JMP
	   test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	   jz PopEntry
	   jmp Flow
	.endif
	; Call/Jcc
	dec ecx
	.if Zero?	; Call
	   test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	   jz ToFlink
	.endif
	push ebx
Flow:
	mov ebx,dword ptr [ebx + EhBranchLink]
	and ebx,NOT(TYPE_MASK)
	jmp Step
PopEntry:
	pop ebx
	test ebx,ebx
	jnz Step
	xor eax,eax
Exit:
	ret
RwSlipTrace endp

RwUnlinkFlowTraceCallback:
	%GET_CURRENT_GRAPH_ENTRY
RwUnlinkFlowTraceCallbackInternal proc Gp:PVOID, Context:PVOID
	mov ecx,Gp
	xor eax,eax
	xor dword ptr [ecx + EhFlowMark],FLOW_UNLINK_MARK
	ret
RwUnlinkFlowTraceCallbackInternal endp

RwUnlinkFlowTraceCallback2nd:
	%GET_CURRENT_GRAPH_ENTRY
RwUnlinkFlowTraceCallback2ndInternal proc Gp:PVOID, Mark:ULONG
	mov ecx,Gp
	mov edx,dword ptr [ecx + EhBlink]
	and edx,NOT(TYPE_MASK)
	.if !Zero?
	   mov eax,dword ptr [edx + EhFlowMark]
	   and eax,FLOW_UNLINK_MARK
	   cmp Mark,eax
	   .if Zero?
	      and dword ptr [ecx + EhBlink],TYPE_MASK
	   .endif
	.endif
	xor eax,eax
	ret
RwUnlinkFlowTraceCallback2ndInternal endp

; +
; Удаление ветви.
;
RwUnlinkFlow proc GpBase:PVOID
	%GET_GRAPH_ENTRY RwUnlinkFlowTraceCallback
	push NULL
	push eax
	push GpBase
	Call RwSlipTrace
	test eax,eax
	mov ecx,GpBase
	.if !Eax
	   mov edx,dword ptr [ecx + EhFlowMark]
	   %GET_GRAPH_ENTRY RwUnlinkFlowTraceCallback2nd
	   and ecx,FLOW_UNLINK_MARK
	   push ecx
	   push eax
	   push GpBase
	   Call RwSlipTrace
	.endif
	ret
RwUnlinkFlow endp