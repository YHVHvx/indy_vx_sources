; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; Билдер.
;
; o Префиксы перед ветвлениями не копируются.
;
Public CsBuildJcc
Public CsBuildJxx
Public CsBuildCall
Public CsBuild
Public GpBuildGraph

; +
; Сборка условного ветвления.
;
; Ebx: PXX_BRANCH_HEADER
; Edi: @Buffer
;
CsBuildJcc proc C uses esi
	cld
	assume ebx:PJCC_HEADER
	mov ecx,dword ptr [ebx + EhJccType]
	and ecx,JCC_TYPE_MASK
	cmp cl,15
	ja CsBuildError
	test dword ptr [ebx + EhJcxType],BRANCH_CX_FLAG
	jnz Jcx
	test dword ptr [ebx + EhBranchSize],BRANCH_SIZE_MASK
	.if Zero?	; Short
	   cmp dword ptr [ebx + EhBranchOffset],0FFH/2
	   ja CsBuildError
	   lea eax,[ecx + JCC_SHORT_OPCODE_BASE]
	   jmp jShort
	.endif
; Near
	mov byte ptr [edi],0FH
	inc edi
	lea eax,[ecx + JCC_NEAR_OPCODE_BASE]
	stosb
	test dword ptr [ebx + EhJccType],BRANCH_DELTA_SIGN
	mov eax,dword ptr [ebx + EhBranchOffset]
	.if Zero?
	   sub eax,6
	.else
	   not eax
	   sub eax,5
	.endif
	stosd	
	jmp CsBuildSuccess
Jcx:
	cmp dword ptr [ebx + EhBranchOffset],0FFH/2
	ja CsBuildError
	test dword ptr [ebx + EhJccType],JCC_X16_MASK
	.if !Zero?
	      mov byte ptr [edi],PREFIX_ADDR_SIZE	; 0x67
	      inc edi
	.endif
	mov eax,dword ptr [ebx + EhJccType]
	and eax,JCC_TYPE_MASK
	cmp eax,4
	jnb CsBuildError
	add eax,JCX_OPCODE_BASE
jShort:
	stosb
	test dword ptr [ebx + EhJccType],BRANCH_DELTA_SIGN
	mov eax,dword ptr [ebx + EhBranchOffset]
	.if Zero?
	   sub al,2
	.else
	   test dword ptr [ebx + EhJccType],JCC_X16_MASK
	   setnz cl
	   add al,cl
	   not al
	   dec al
	.endif
	stosb
CsBuildSuccess::
	xor eax,eax
CsBuildExit::
	ret
CsBuildError::
	mov eax,STATUS_UNSUCCESSFUL
	jmp CsBuildExit
CsBuildJcc endp

; +
; Сборка безусловного ветвления.
;
; Ebx: PXX_BRANCH_HEADER
; Edi: @Buffer
; Edx: Ip
;
CsBuildJxx proc C uses esi
	cld
	assume ebx:PJMP_HEADER
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	mov esi,edx	; [ebx].Address
	jnz @f
	mov ecx,dword ptr [ebx + EhIpLength]
	rep movsb
	jmp CsBuildSuccess
@@:
	test dword ptr [ebx + EhBranchSize],BRANCH_SIZE_MASK
	mov eax,dword ptr [ebx + EhBranchOffset]
	.if Zero?	; Short
	   cmp dword ptr [ebx + EhBranchOffset],0FFH/2
	   ja CsBuildError
	   mov byte ptr [edi],0EBH
	   inc edi
 	   test dword ptr [ebx + EhJccType],BRANCH_DELTA_SIGN
	   .if Zero?
	      sub al,2
	   .else
	      not al
	      dec al
	   .endif
	   stosb
	   jmp CsBuildSuccess
	.endif
; Near
	mov byte ptr [edi],0E9H
	inc edi
	test dword ptr [ebx + EhJccType],BRANCH_DELTA_SIGN
	.if Zero?
	   sub eax,5
	.else
	   not eax
	   sub eax,4
	.endif
	stosd
	jmp CsBuildSuccess
CsBuildJxx endp

; +
; Сборка процедурного ветвления.
;
; Ebx: PXX_BRANCH_HEADER
; Edi: @Buffer
; Edx: Ip
;
CsBuildCall proc C uses esi
	cld
	assume ebx:PCALL_HEADER
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	mov esi,edx	; [ebx].Address
	jnz @f
	mov ecx,dword ptr [ebx + EhIpLength]
	rep movsb
	jmp CsBuildSuccess
@@:
	mov dword ptr [edi],0E8H
	inc edi
	test dword ptr [ebx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	.if Zero?	; Closed
	; Recalc disp.
	   mov eax,dword ptr [ebx + EhBranchAddress]
	   sub eax,edi
	   sub eax,4
	   stosd
	   jmp CsBuildSuccess
	.endif
	test dword ptr [ebx + EhJccType],BRANCH_DELTA_SIGN
	mov eax,dword ptr [ebx + EhBranchOffset]
	.if Zero?
	   sub eax,5
	.else
	   not eax
	   sub eax,4
	.endif
	stosd
	jmp CsBuildSuccess
CsBuildCall endp

; +
; Компиляция.
; o В поле Address описателя загружается текущий адрес инструкции в собираемом буфере.
;
CsBuild proc uses ebx esi edi CsBase:PVOID, CsLimit:ULONG, OutBuffer:PVOID
	mov ebx,CsBase
	mov edi,OutBuffer
	cld
@@:
	and ebx,NOT(TYPE_MASK)
	mov eax,dword ptr [ebx + EhEntryType]
	mov esi,dword ptr [ebx + EhAddress]
	and eax,TYPE_MASK
	mov edx,esi
	mov dword ptr [ebx + EhAddress],edi
	.if Zero?	; Line
	   mov ecx,dword ptr [ebx + EhSize]
	   rep movsb
	.else
	   dec eax
	   .if Zero?	; Call
	      invoke CsBuildCall
	   .else
	      test dword ptr [ebx + EhIdleBranch],BRANCH_IDLE_FLAG
	      jnz Next
	      dec eax
	      .if Zero?	; Jxx
  	         invoke CsBuildJxx
	      .else	; Jcc
	         invoke CsBuildJcc
	      .endif
	   .endif
	   test eax,eax
	   jnz @f
	.endif
Next:
	add ebx,ENTRY_HEADER_SIZE
	cmp CsLimit,ebx
	ja @b
@@:
	ret
CsBuild endp

; +
; Стаб для расширения стека.
;
GpBuildGraph proc C
	test dword ptr [esp - X86_PAGE_SIZE],eax
	test dword ptr [esp - 2*X86_PAGE_SIZE],eax
	jmp GpBuildGraphInternal
GpBuildGraph endp

; +
; Сборка графа.
;
GpBuildGraphInternal proc uses ebx esi GpBase:PVOID, GpLimit:PVOID, CsBase:PVOID, BuildBuffer:PVOID
Local GraphLimit:PVOID
Local CsLimit:PVOID
Local CxBuffer[CX_REPLACE_TABLE_LENGTH + CX_REPLACE_GRAPH_LENGTH]:BYTE
	mov eax,GpLimit
	mov esi,CsBase
	mov ebx,GpBase
	mov GraphLimit,eax
	mov CsLimit,esi
	invoke CxMorphGraph, addr CxBuffer, Ebx, addr GraphLimit
	test eax,eax
	jnz Exit
	invoke RwConvertRawTableToCrossTable, Ebx, addr CsLimit
	test eax,eax
	jnz Exit
;	invoke CsMarkAndUnlinkIdleBranches, Esi, CsLimit
;	test eax,eax
;	jnz Exit
	invoke CsAdjustBranches, Esi, CsLimit
	test eax,eax
	jnz Exit
	invoke CsBuild, Esi, CsLimit, BuildBuffer
Exit:
	ret
GpBuildGraphInternal endp