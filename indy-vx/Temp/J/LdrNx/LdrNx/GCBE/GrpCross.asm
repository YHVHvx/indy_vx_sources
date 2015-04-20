; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; Конвертация графа в линейный.
;
Public ConvertRawTableToCrossTableTraceCallbackInternal
Public ConvertRawTableToCrossTableTraceCallback2ndInternal
Public RwConvertRawTableToCrossTable
Public CsCalculateBranchDisplacement
Public CsAdjustBranches

; +
; Копирование описателей и создание перекрёстных ссылок.
;
ConvertRawTableToCrossTableTraceCallback::
	%GET_CURRENT_GRAPH_ENTRY
ConvertRawTableToCrossTableTraceCallbackInternal proc uses ebx esi edi RawTableEntry:PVOID, CrossTableEntry:PVOID
	mov ebx,CrossTableEntry
	mov esi,RawTableEntry
	mov edi,dword ptr [ebx]
	mov ecx,(ENTRY_HEADER_SIZE/4) - 1	; - CrossLink
	cld
	mov eax,edi
	mov edx,esi
	rep movsd
; * Очистка флажка трассировщика, необходима при обьединении графов.
	and dword ptr [eax + EhBlink],TYPE_MASK and NOT(ACCESSED_MASK_FLAG)
	and dword ptr [eax + EhFlink],TYPE_MASK
	mov dword ptr [esi],eax	; CrossLink
	mov dword ptr [edi],edx
	add dword ptr [ebx],ENTRY_HEADER_SIZE
	xor eax,eax
	ret
ConvertRawTableToCrossTableTraceCallbackInternal endp

; +	
; Связка входов таблицы.
;
ConvertRawTableToCrossTableTraceCallback2nd::
	%GET_CURRENT_GRAPH_ENTRY
ConvertRawTableToCrossTableTraceCallback2ndInternal proc uses ebx esi edi RawTableEntry:PVOID, Reserved:PVOID
	mov esi,RawTableEntry
	mov edi,dword ptr [esi + EhCrossLink]
	mov ecx,dword ptr [esi + EhFlink]
	mov ebx,ecx
	mov edx,dword ptr [esi + EhBlink]
	and ecx,NOT(TYPE_MASK)
	.if !Zero?
		mov ecx,dword ptr [ecx + EhCrossLink]
	.endif
	and edx,NOT(TYPE_MASK)
	.if !Zero?
		mov edx,dword ptr [edx + EhCrossLink]
	.endif
	and ecx,NOT(TYPE_MASK)
	and edx,NOT(TYPE_MASK)
	or dword ptr [edi + EhFlink],ecx
	or dword ptr [edi + EhBlink],edx
	and ebx,TYPE_MASK
	jz Exit	; Line
	cmp bl,HEADER_TYPE_JCC
	mov eax,dword ptr [esi + EhBranchLink]
	.if !Zero?
		test dword ptr [esi + EhBranchType],BRANCH_DEFINED_FLAG
		jz Exit
	.endif
	dec ebx
	.if Zero?	; Call
		test dword ptr [esi + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
		jz Exit
	.endif
	and eax,NOT(TYPE_MASK)
	and dword ptr [edi + EhBranchLink],TYPE_MASK
	mov eax,dword ptr [eax + EhCrossLink]
	and eax,NOT(TYPE_MASK)
	or dword ptr [edi + EhBranchLink],eax
Exit:
	xor eax,eax
	ret
ConvertRawTableToCrossTableTraceCallback2ndInternal endp

comment '
 Создание таблицы перекрёстных ссылок.

NTSTATUS
PVOID
RwConvertRawTableToCrossTable(
  IN PVOID RawTable,
  IN PVOID CrossTable,
  )'

RwConvertRawTableToCrossTable proc RawTable:PVOID, CrossTable:PVOID
	%GET_GRAPH_ENTRY ConvertRawTableToCrossTableTraceCallback
	push CrossTable
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push RawTable
	Call RwTrace
	.if !Eax
	   push eax
	   %GET_GRAPH_ENTRY ConvertRawTableToCrossTableTraceCallback2nd
	   push eax
	   push GCBE_PARSE_NL_UNLIMITED
	   push RawTable
	   Call RwTrace
	.endif
	ret
RwConvertRawTableToCrossTable endp

; +
; Определяет смещение в ветвлении.
;
CsCalculateBranchDisplacement proc uses ebx esi edi GpEntry:PJMP_HEADER
	mov esi,GpEntry
	xor ebx,ebx
	mov edi,dword ptr [esi + EhBranchLink]
	and edi,NOT(TYPE_MASK)
	cmp esi,edi
	je Save
	.if !Carry?
	   xchg esi,edi
	.endif
Next:
	mov eax,dword ptr [esi + EhEntryType]
	and eax,TYPE_MASK
	jnz @f
; Line
	add ebx,dword ptr [esi + EhSize]
	jmp Check
@@:
	dec eax
	jnz Jxx
; Call
	test dword ptr [esi + EhBranchType],BRANCH_DEFINED_FLAG
	jz Undef
	test dword ptr [esi + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	jz Undef
;	invoke QueryPrefixLength, dword ptr [esi + EhAddress]
;	lea ebx,[ebx + eax + 5]
	add ebx,5
	jmp Check
Jxx:
	test dword ptr [esi + EhIdleBranch],BRANCH_IDLE_FLAG
	jnz Check
	dec eax
	jnz Jcc
; Jxx
	test dword ptr [esi + EhBranchType],BRANCH_DEFINED_FLAG
	jz Undef
	test dword ptr [esi + EhBranchSize],BRANCH_SIZE_MASK
	jz jShort
	add ebx,5	; Near
	jmp Check
Undef:
	movzx eax,byte ptr [esi + EhIpLength]
	add ebx,eax 
	jmp Check
Jcc:
	test dword ptr [esi + EhBranchSize],BRANCH_SIZE_MASK
	.if !Zero?
 	   add ebx,6	; Near
	.else
jShort:
	   add ebx,2	; Short
	.endif
Check:
	add esi,ENTRY_HEADER_SIZE
	cmp esi,edi
	jb Next
Save:
	mov esi,GpEntry
	and dword ptr [esi + EhJccType],NOT(BRANCH_DELTA_SIGN)
	cmp esi,edi
	mov eax,dword ptr [esi + EhEntryType]
	mov dword ptr [esi + EhBranchOffset],ebx	; Absolute!
	.if !Carry?
	   or dword ptr [esi + EhJccType],BRANCH_DELTA_SIGN
	.endif
	and eax,TYPE_MASK
	.if (!Zero?) && (al != HEADER_TYPE_CALL)	; Jxx/Jcc
	   and dword ptr [esi + EhBranchSize],NOT(BRANCH_SIZE_MASK)
	   cmp ebx,0FFH/2
	   setnc al
;	   movzx eax,al
	   or byte ptr [esi + EhBranchSize],al	; BRANCH_SIZE_MASK: i0
	.endif
	xor eax,eax
Exit:
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
CsCalculateBranchDisplacement endp

; +
; Определение размера ветвлений.
;
CsAdjustBranches proc uses ebx esi edi CsBase:PVOID, CsLimit:ULONG
Rst:
	mov ebx,CsBase
	mov esi,CsLimit
Next:
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	jz jNext
	dec eax
	jnz Jxx
; Call
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz jNext
	test dword ptr [ebx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	jz jNext
	invoke CsCalculateBranchDisplacement, Ebx
	test eax,eax	; #XCPT etc.
	jnz Exit
	jmp jNext
Jxx:
	test dword ptr [ebx + EhIdleBranch],BRANCH_IDLE_FLAG
	jnz jNext
	dec eax
	jnz Jcc
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz jNext
Jcc:
	mov edi,dword ptr [ebx + EhBranchSize]
	invoke CsCalculateBranchDisplacement, Ebx
	test eax,eax
	mov ecx,dword ptr [ebx + EhBranchSize]
	jnz Exit
	and edi,BRANCH_SIZE_MASK
	and ecx,BRANCH_SIZE_MASK
	cmp ecx,edi
	jne Rst
jNext:
	add ebx,ENTRY_HEADER_SIZE
Check:
	cmp ebx,esi
	jb Next
	xor eax,eax
Exit:
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
CsAdjustBranches endp