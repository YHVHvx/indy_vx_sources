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

GCBE_BUILD_LOCAL_DISPATCH	equ 00000001B
GCBE_BUILD_CROSS_UNLINK		equ 00000010B
GCBE_BUILD_MORPH_SYSENTER	equ 00000100B
GCBE_BUILD_MORPH_INT2E		equ 00001000B
GCBE_BUILD_MORPH_INT2A		equ 00010000B
GCBE_BUILD_MORPH_RDTSC		equ 00100000B

; +
; Сборка условного ветвления.
;
; Ebx: PJCC_ENTRY
; Edi: @Buffer
;
CsBuildJcc proc C uses esi
	cld
	assume ebx:PJCC_ENTRY
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
; Ebx: PXX_BRANCH_ENTRY
; Edi: @Buffer
; Edx: Ip
;
CsBuildJxx proc C uses esi
	cld
	assume ebx:PJMP_ENTRY
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	mov esi,edx	; [ebx].Address
	jnz @f
	movzx ecx,byte ptr [ebx + EhIpLength]
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
; Ebx: PXX_BRANCH_ENTRY
; Edi: @Buffer
; Edx: Ip
;
CsBuildCall proc C uses esi
	cld
	assume ebx:PCALL_ENTRY
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	mov esi,edx	; [ebx].Address
	jnz @f
	movzx ecx,byte ptr [ebx + EhIpLength]
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
CsBuild proc uses ebx esi edi CsBase:PVOID, CsLimit:ULONG, OutBuffer:PVOID, Flags:BOOLEAN
	mov ebx,CsBase
	mov edi,OutBuffer
	cld
@@:
	and ebx,NOT(TYPE_MASK)
	mov eax,dword ptr [ebx + EhEntryType]
	mov esi,dword ptr [ebx + EhAddress]
	mov edx,esi
	test Flags,GCBE_BUILD_CROSS_UNLINK
	mov dword ptr [ebx + EhAddress],edi
	.if !Zero?
		mov ecx,dword ptr [ebx + EhCrossLink]
		mov dword ptr [ebx + EhCrossLink],esi
		and ecx,NOT(TYPE_MASK)
		and dword ptr [ebx + EhCrossType],NOT(CROSS_TYPE_MASK)
		mov dword ptr [ecx + EhCrossLink],edi
		and dword ptr [ecx + EhCrossType],NOT(CROSS_TYPE_MASK)
	.endif
	and eax,TYPE_MASK	
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
	add ebx,ENTRY_SIZE
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

	include GrpAtom.asm

OP_2T		equ 0FH
OP_INT		equ 0CDH
OP_SYSENTER	equ 34H
OP_RDTSC		equ 31H

xGpAtomIdentCallback:
	%GET_CURRENT_GRAPH_ENTRY
GpAtomIdentCallback proc uses ebx Gp:PVOID, GpBase:PVOID, GpLimit:PPVOID, Ip:PPVOID, Flags:DWORD
	mov ebx,Gp
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	jz Line
Next:
	xor eax,eax
Exit:
	ret
Line:
	invoke QueryPrefixLength, dword ptr [ebx + EhAddress]
	cmp al,MAX_INSTRUCTION_SIZE - 2
	ja Next
	add eax,dword ptr [ebx + EhAddress]
	movzx ecx,byte ptr [eax]
	cmp cl,OP_INT
	je xINT
	cmp byte ptr [eax],OP_2T
	jne Next
	movzx ecx,byte ptr [eax + 1]
	cmp cl,OP_SYSENTER
	je xSYSENTER
	cmp cl,OP_RDTSC
	jne Next
xRDTSC:
	test Flags,GCBE_BUILD_MORPH_RDTSC
	jz Next
	%GET_GRAPH_ENTRY xMI_RDTSC
	jmp Load
xSYSENTER:
	test Flags,GCBE_BUILD_MORPH_SYSENTER
	jz Next
	%GET_GRAPH_ENTRY xMI_SYSENTER
	jmp Load
xINT:
	movzx ecx,byte ptr [eax + 1]
	cmp cl,2AH
	jne @f
xINT2A:
	test Flags,GCBE_BUILD_MORPH_INT2A
	jz Next
	%GET_GRAPH_ENTRY xMI_INT2A
	jmp Load
@@:
	cmp cl,2EH
	jne Next
	test Flags,GCBE_BUILD_MORPH_INT2E
	jz Next
	%GET_GRAPH_ENTRY xMI_INT2E
Load:
	mov ecx,Ip
	mov dword ptr [ecx],eax
	mov eax,MIP_STATUS_HANDLED
	jmp Exit
GpAtomIdentCallback endp

; +
; Сборка графа.
;
GpBuildGraphInternal proc uses ebx esi GpBase:PVOID, GpLimit:PVOID, CsBase:PVOID, BuildBuffer:PVOID, Flags:DWORD
Local GraphLimit:PVOID
Local CsLimit:PVOID
Local CxBuffer[CX_REPLACE_TABLE_LENGTH + CX_REPLACE_GRAPH_LENGTH]:BYTE
	mov esi,CsBase
	mov ebx,GpBase
	%GET_GRAPH_ENTRY xGpAtomIdentCallback
	test Flags,GCBE_BUILD_LOCAL_DISPATCH
	lea ecx,GpLimit
	setnz dl
	push Flags
	movzx edx,dl
	push eax
	push edx
	push ecx
	push GpBase
	Call MIP_MORPH_ATOMIC
	test eax,eax
	mov ecx,GpLimit
	jnz Exit
	mov CsLimit,esi
	mov GraphLimit,ecx
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
	invoke CsBuild, Esi, CsLimit, BuildBuffer, Flags
Exit:
	ret
GpBuildGraphInternal endp