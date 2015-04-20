;
; (c) Indy, 2012
;
; - x16
; o UM, (MI).
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
	OPT_DBG_LOG		equ TRUE
	
.code
%DBG macro Msg$, ArgList:VARARG
	ifdef OPT_DBG_LOG
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

MAX_INSTRUCTION_SIZE	equ 15

; +
; Eax - число префиксов.
; Ecx - последний префикс.
; Edx - 0x67 Pfx.
;
QueryPrefixLength proc uses ebx esi edi Address:PVOID
Local PrefixesTable[12]:BYTE
Local IpLength:ULONG
comment '
PrefixesTable:
	BYTE PREFIX_LOCK
	BYTE PREFIX_REPNZ
	BYTE PREFIX_REP
	BYTE PREFIX_CS
	BYTE PREFIX_DS
	BYTE PREFIX_SS
	BYTE PREFIX_ES
	BYTE PREFIX_FS
	BYTE PREFIX_GS
	BYTE PREFIX_DATA_SIZE
	BYTE PREFIX_ADDR_SIZE
	'
	mov IpLength,MAX_INSTRUCTION_SIZE + 1
	mov dword ptr [PrefixesTable],02EF3F2F0H
	mov dword ptr [PrefixesTable + 4],06426363EH
	mov dword ptr [PrefixesTable + 8],000676665H
	mov esi,Address
	cld
	lea edx,PrefixesTable
	xor ebx,ebx
@@:
	dec IpLength
	.if Zero?
		xor eax,eax
		xor ecx,ecx
		jmp Exit
	.endif
	lodsb
	mov edi,edx
	cmp al,PREFIX_ADDR_SIZE
	mov ecx,11
	.if Zero?
		or bl,1
	.endif
	repne scasb
	jz @b
	dec esi
	xor eax,eax
	movzx ecx,byte ptr [esi - 1]
	sub esi,Address
	.if Zero?
		xor ecx,ecx
	.else
		mov eax,esi
	.endif
Exit:
	mov edx,ebx
	ret
QueryPrefixLength endp

MODRM_MOD		equ 11000000B
MODRM_REG		equ 00111000B
MODRM_RM		equ 00000111B

SIB_SCALE		equ 11000000B
SIB_INDEX		equ 00111000B
SIB_BASE		equ 00000111B

; +
;
; Раскодировка ModR/M.
;
; Eax: PTR
; Ecx: LDE
; Edx: Необходимо чтение(FALSE).
;
EncodeModRM proc uses ebx esi edi pModRM:PVOID, Context:PCONTEXT
	mov ebx,pModRM
	xor edi,edi	; Длина.
	movzx eax,byte ptr [ebx]	; ModRM
	mov esi,Context
	mov edx,eax
	and al,MODRM_RM	; R/M
	rol dl,2
	mov Context,FALSE
	and dl,(MODRM_MOD shr 6)	; MOD
	jnz Mod01
Mod00:
	cmp al,3
	ja Mod00A3
GetReg:
	neg eax
	mov eax,CONTEXT.rEax[esi][eax*4]
	jmp Exit
Mod00A3:
	cmp al,100B
	jne Mod00A4
	; SIB
	Call SIB
	inc edi	; +SIB
	jmp Exit
Mod00A4:
	cmp al,101B
	jne Mod00A5
	; DISP32
	mov eax,dword ptr [ebx + 1]
	add edi,4
	jmp Exit
Mod00A5:
	; [Esi]
	; [Edi]
	sub al,2
	jmp GetReg

Mod01:
	cmp dl,11B
	je Mod11
Mod01_10:
	cmp al,3
	ja Mod01_10A3
@@:
	neg eax
	mov eax,CONTEXT.rEax[esi][eax*4]
Mod01_10_Disp:
	.if dl == 01B
		movzx edx,byte ptr [ebx + edi + 1]	; Disp8
		inc edi
		btr edx,7	; Sign.
		.if Carry?
			sub eax,80H
		.endif
	.else	; 10B
		mov edx,dword ptr [ebx + edi + 1]	; Disp32
		add edi,4
	.endif
	add eax,edx
Exit:
	mov ecx,edi
	mov edx,Context
	ret
Mod01_10A3:
	cmp al,100B
	ja Mod01_10A4
	; SIB
	Call SIB
	inc edi
	jmp Mod01_10_Disp
Mod01_10A4:
	cmp al,101B
	jne Mod01_10A5
	; [Ebp + Disp8]
	sub eax,6
	jmp @b
Mod01_10A5:
	; [Esi + Disp8]
	; [Edi + Disp8]
	sub al,2
	jmp @b

Mod11:
	mov Context,TRUE
	; *** Без чтения памяти.
	cmp al,3
	jbe GetReg
Mod11A3:
	cmp al,100B
	ja Mod11A4
	sub eax,9
	jmp GetReg
Mod11A4:
	cmp al,101B
	jne Mod00A5
	sub eax,6
	jmp GetReg
	
SIB:
	movzx ecx,byte ptr [ebx + 1]	; SIB
	mov eax,ecx
	rol cl,2
	shr eax,3
	and al,(SIB_INDEX shr 3)	; Index
	and cl,(SIB_SCALE shr 6)	; Scale
	.if al == 101B
	; [Ebp]
		sub eax,6
	.elseif al == 100B
		xor eax,eax
		jmp @f
	.elseif al > 101B
	; [Esi]
	; [Edi]
		sub al,2
	.endif
	neg eax
	mov eax,CONTEXT.rEax[esi][eax*4]
	shl eax,cl	; Scale * Index
@@:
	movzx ecx,byte ptr [ebx + 1]	; SIB
	and cl,SIB_BASE
	.if cl == 100B
		add eax,CONTEXT.rEsp[esi]
	.elseif cl == 101B
		.if !dl	; MOD: 00
			add eax,dword ptr [ebx + 2]	; Disp32
			add edi,4
		.else
			add eax,CONTEXT.rEbp[esi]
		.endif
	.elseif cl <= 3
	@@:
		neg ecx
		add eax,CONTEXT.rEax[esi][ecx*4]
	.else
	; [Esi]
	; [Edi]
		sub cl,2
		jmp @b
	.endif
	retn 0
EncodeModRM endp

JCC_TYPE_MASK	equ 00001111B

; +
;
; !ZF: TRUE
;
IsCC proc JccType:DWORD, EFlags:DWORD
	and JccType,JCC_TYPE_MASK
	mov eax,JccType
	mov ecx,EFlags
	and JccType,1
	Call @f
	setc al
	xor JccType,eax
	ret
@@:
	shr eax,1
	and eax,JCC_TYPE_MASK/2
	jz CC_O
	dec al
	jz CC_C
	dec al
	jz CC_Z
	dec al
	jz CC_NA
	dec al
	jz CC_S
	dec al
	jz CC_P
	dec al
	jz CC_L
	dec al
CC_NG:
	bt ecx,6
	.if Carry?
		retn
	.endif
CC_L:
	test ecx,EFLAGS_SF
	bt ecx,11
	.if Zero?
		jc Set
	.else
		jnc Set
	.endif
	xor eax,eax
	retn
Set:
	stc
	retn
CC_O:
	bt ecx,11
	retn
CC_C:
	bt ecx,0
	retn
CC_Z:
	bt ecx,6
	retn
CC_S:
	bt ecx,7
	retn
CC_P:
	bt ecx,2
	retn
CC_NA:
	test ecx,EFLAGS_CF or EFLAGS_ZF
	jnz Set
	retn
IsCC endp

OP_ESC2B	equ 0FH

JCC_SHORT_OPCODE_BASE	equ 70H
JCC_NEAR_OPCODE_BASE	equ 80H

JCC_O	equ 0	; OF
JCC_NO	equ 1	; !OF
JCC_C	equ 2	; CF
JCC_B	equ 2	; CF
JCC_NAE	equ 2	; CF
JCC_NC	equ 3	; !CF
JCC_NB	equ 3	; !CF
JCC_AE	equ 3	; !CF
JCC_Z	equ 4	; ZF
JCC_E	equ 4	; ZF
JCC_NZ	equ 5	; !ZF
JCC_NE	equ 5	; !ZF
JCC_NA	equ 6	; CF | ZF
JCC_BE	equ 6	; CF | ZF
JCC_A	equ 7	; !CF & !ZF
JCC_NBE	equ 7	; !CF & !ZF
JCC_S	equ 8	; SF
JCC_NS	equ 9	; !SF
JCC_P	equ 0AH	; PF
JCC_PE	equ 0AH	; PF
JCC_NP	equ 0BH	; !PF
JCC_PO	equ 0BH	; !PF
JCC_L	equ 0CH	; SF != OF
JCC_NGE	equ 0CH	; SF != OF
JCC_NL	equ 0DH	; SF = OF
JCC_GE	equ 0DH	; SF = OF
JCC_NG	equ 0EH	; ZF | (SF != OF)
JCC_LE	equ 0EH	; ZF | (SF != OF)
JCC_G	equ 0FH	; !ZF & (SF = OF)
JCC_NLE	equ 0FH	; !ZF & (SF = OF)

; o Jump short: 0x70 + JCC_*
; o Jump near: 0x0F 0x80 + JCC_*

JCC_LOOPNE	equ 0E0H	; Ecx & !ZF
JCC_LOOPE		equ 0E1H	; Ecx & ZF
JCC_LOOP		equ 0E2H	; Ecx
JCC_ECXZ		equ 0E3H	; !Ecx

JCX_OPCODE_BASE	equ 0E0H

; +
;
; Определяет следующую инструкцию, после исполнения ветвления(Jcc/Jcx).
;
JccToCC proc uses ebx esi Ip:PVOID, Context:PCONTEXT
	mov ebx,Ip
	mov esi,Context
	assume esi:PCONTEXT
	movzx eax,byte ptr [ebx]	; Opcode
	cmp al,OP_ESC2B
	je IsNear
	cmp al,JCC_SHORT_OPCODE_BASE
	jb Error
	cmp al,JCC_SHORT_OPCODE_BASE + 15
	ja IsJcx
Jcx:
	invoke IsCC, Eax, [Esi].rEFlags
	movzx eax,byte ptr [ebx + 1]	; Disp.
	.if Zero?
		add ebx,2
	.else
		btr eax,7
		.if Carry?
			sub eax,80H
		.endif
		lea ebx,[eax + ebx + 2]
		.if Edx
			and ebx,0FFFFH
		.endif
	.endif
	jmp Exit	
IsNear:
	movzx eax,byte ptr [ebx + 1]
	cmp al,JCC_NEAR_OPCODE_BASE
	jb Error
	cmp al,JCC_NEAR_OPCODE_BASE + 15
	ja Error
	invoke IsCC, Eax, [Esi].rEFlags
	.if Zero?
		add ebx,6
	.else
		mov eax,dword ptr [ebx + 2]
		lea ebx,[eax + ebx + 6]
	.endif
	jmp Exit
IsJcx:
	sub al,JCX_OPCODE_BASE
	mov ecx,[Esi].rEcx
	jb Error
	cmp al,(JCC_ECXZ - JCX_OPCODE_BASE)
	ja Error
	.if Zero?	; JCC_ECXZ; !Ecx
		test ecx,ecx
		jz Jcx
	.else
		.if Ecx
			dec eax
			.if Zero?	; JCC_LOOPNE; Ecx & !ZF
				bt [Esi].rEFlags,6	; ZF
				jnc Jcx
			.else
				dec eax
				.if Zero?	; JCC_LOOPE; Ecx & ZF
					bt [Esi].rEFlags,6	; ZF
					jc Jcx
				.else	; JCC_LOOP; Ecx
					test ecx,ecx
					jnz Jcx
				.endif
			.endif
		.endif
	.endif
	add ebx,2
Exit:
	mov eax,ebx
@@:
	ret
Error:
	xor eax,eax
	jmp @b
JccToCC endp

OP_JMP_SHORT	equ 0EBH
OP_JMP_NEAR	equ 0E9H
OP_JMP_FAR	equ 0EAH

; +
;
JmpToCC proc uses ebx Ip:PVOID, Context:PCONTEXT
	mov ebx,Ip
	movzx eax,byte ptr [ebx]	; Opcode
	cmp al,OP_JMP_SHORT
	jne @f
	movzx eax,byte ptr [ebx + 1]
	btr eax,7
	.if Carry?
		sub eax,80H
	.endif
	lea eax,[eax + ebx + 2]
	jmp Exit
@@:
	cmp al,OP_JMP_NEAR
	jne @f
	mov eax,dword ptr [ebx + 1]
	lea eax,[eax + ebx + 5]
	jmp Exit
@@:
	cmp al,0FFH	; Grp. 5
	jne Error
	movzx eax,byte ptr [ebx + 1]	; ModR/M
	and al,MODRM_REG
	shr al,3
	.if al == 100B
		inc ebx
		invoke EncodeModRM, Ebx, Context
		.if Eax
			.if !Edx
				mov eax,dword ptr [eax]	; ИСПОЛЬЗУЕТСЯ СЕГМЕНТ ДАННЫХ, НЕОБХОДИМО ПЕРЕОПРЕДЕЛИТЬ!
			.endif
		.endif
	.else
Error:
		xor eax,eax
	.endif
Exit:
	ret
JmpToCC endp

OP_CALL_REL	equ 0E8H

; +
;
CallToCC proc uses ebx Ip:PVOID, Context:PCONTEXT
	mov ebx,Ip
	movzx ecx,byte ptr [ebx]	; Opcode
	cmp cl,OP_CALL_REL
	jne @f
	lea ecx,[eax + 5]
	mov edx,dword ptr [ebx + 1]
	lea eax,[edx + ebx + 5]
	jmp Exit
@@:
	cmp cl,0FFH	; Grp. 5
	jne Error
	movzx ecx,byte ptr [ebx + 1]	; ModR/M
	and cl,MODRM_REG
	shr cl,3
	.if cl == 010B
		push eax
		inc ebx
		invoke EncodeModRM, Ebx, Context
		.if Eax
			.if !Edx
				mov eax,dword ptr [eax]	; ИСПОЛЬЗУЕТСЯ СЕГМЕНТ ДАННЫХ, НЕОБХОДИМО ПЕРЕОПРЕДЕЛИТЬ!
			.endif
		.endif
		pop edx
		lea ecx,[ecx + edx + 2]
	.else
Error:
		xor eax,eax
	.endif
Exit:
	ret
CallToCC endp

; +
; 
RetToCC proc Ip:PVOID, Context:PCONTEXT
	mov edx,Ip
	movzx ecx,byte ptr [edx + eax]
	mov eax,Context
	.if (cl == 0C3H) || (cl == 0C2H)
		mov eax,CONTEXT.rEsp[eax]
		mov eax,dword ptr [eax]
	.else
		xor eax,eax
	.endif
	ret
RetToCC endp

.data
JccCount	ULONG ?
JmpCount	ULONG ?
CallCount	ULONG ?
RetCount	ULONG ?
SysCount	ULONG ?
LineCount	ULONG ?

.code
	assume fs:nothing
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

%DBGINC macro Count
	ifdef OPT_DBG_LOG
		inc Count
	endif
endm

EXCEPTION_REGISTRATION_RECORD struct
Next		PVOID ?	; PEXCEPTION_REGISTRATION_RECORD
Handler	PVOID ?
EXCEPTION_REGISTRATION_RECORD ends

TLS struct
Frame		EXCEPTION_REGISTRATION_RECORD <>
Break		PVOID ?
Sfc			PVOID ?
rEbx			DWORD ?
Ip			PVOID ?
Count		ULONG ?
union
	Line		BOOLEAN ?
	Magic	DWORD ?
ends
TLS ends
PTLS typedef ptr TLS

xScall:
	%GET_CURRENT_GRAPH_ENTRY
Scall proc C
	assume ebx:PTLS
	push [ebx].Ip
	push EFLAGS_TF or EFLAGS_MASK
	mov ebx,[ebx].rEbx
	%DBGINC RetCount
	%DBGINC SysCount
	; * Инструкции связаны(iret генерит трап после исполнения следующей инструкции)!
	popfd
	ret
Scall endp

OP_INT	equ 0CDH

MAGIC	equ EFLAGS_SF or EFLAGS_ZF or EFLAGS_MASK	; * Любое значение для расшифровки.

xXcptPredict:
	%GET_CURRENT_GRAPH_ENTRY
XcptPredict proc uses ebx esi edi ExceptionRecord:PEXCEPTION_RECORD, EstablisherFrame:PVOID, ContextRecord:PCONTEXT, DispatcherContext:PVOID
	mov esi,ExceptionRecord
	mov edi,ContextRecord
	assume esi:PEXCEPTION_RECORD
	assume edi:PCONTEXT
	mov ebx,[esi].ExceptionAddress
	.if [esi].ExceptionFlags || ([esi].ExceptionCode != STATUS_SINGLE_STEP)
Chain:
		mov eax,ExceptionContinueSearch
		jmp Exit
	.endif
	mov esi,EstablisherFrame
	assume esi:PTLS
	.if [Esi].Break != Ebx
		or [edi].rEFlags,EFLAGS_TF
	.else
		mov [esi].Magic,MAGIC
Fail:
		and [edi].rEFlags,NOT(EFLAGS_TF)
		jmp Load
	.endif
	mov eax,[esi].Ip
	.if Eax
		.if ![Esi].Line
			cmp ebx,eax
			jne Fail
		.else
			cmp ebx,eax
			jb Fail
			add eax,MAX_INSTRUCTION_SIZE
			cmp ebx,eax
			jnb Fail
		.endif
	.endif
	inc [esi].Count
	mov [esi].Line,FALSE
	invoke QueryPrefixLength, Ebx
	add ebx,eax
	invoke JmpToCC, Ebx, Edi
	.if Eax
		%DBGINC JmpCount
	.else
		invoke JccToCC, Ebx, Edi
		.if Eax
			%DBGINC JccCount
		.else
			invoke CallToCC, Ebx, Edi
			.if Eax
				%DBGINC CallCount
			.else
				invoke RetToCC, Ebx, Edi
				.if Eax
					%DBGINC RetCount
				.else
					.if (byte ptr [Ebx] == OP_ESC2B) && (byte ptr [Ebx + 1] == 34H) \	; Sysenter
						|| (byte ptr [Ebx] == OP_INT) && (byte ptr [Ebx + 1] == 2EH)	; Int 0x2e -> Ret
						; KiDebugService не обрабатываем, для блокировки можно взвести PEB.BeingDebugged
						%GET_GRAPH_ENTRY xScall
						mov ecx,[edi].rEsp
						mov edx,[edi].rEbx
						and [edi].rEFlags,NOT(EFLAGS_TF)
						xchg dword ptr [ecx],eax	; ~Zw
						mov [esi].rEbx,edx
						mov [edi].rEbx,esi
					.else
						%DBGINC LineCount
						mov ecx,ExceptionRecord
						mov [esi].Line,TRUE
						mov eax,EXCEPTION_RECORD.ExceptionAddress[ecx]
					.endif
				.endif
			.endif
		.endif
	.endif
	mov [esi].Ip,eax
Load:
	xor eax,eax	; ExceptionContinueExecution
Exit:
	ret
XcptPredict endp

$Jcc		CHAR "JCC's: 0x%X", 13, 10, 0
$Jmp		CHAR "JMP's: 0x%X", 13, 10, 0
$Call	CHAR "CALL's: 0x%X", 13, 10, 0
$Ret		CHAR "RET's: 0x%X", 13, 10, 0
$Line	CHAR "LINE's: 0x%X", 13, 10, 0
$Sys		CHAR "SYSCALL's: 0x%X", 13, 10, 0

.code
RtlComputeCrc32 proto PartialCrc:ULONG, Buffer:PVOID, _Length:ULONG

Ip proc
	push NULL	; Magic/Line
	push 0	; Count
	push NULL	; Ip
	push NULL	; rEbx
	%GET_GRAPH_ENTRY XBREAK	; ext.
	push ebp	; SFC
	push eax
	%GET_GRAPH_ENTRY xXcptPredict
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	push EFLAGS_TF or EFLAGS_MASK
	popfd
	invoke RtlComputeCrc32, 0, addr $Sys, sizeof $Sys
	xor eax,8CE0B5FCH
	jmp @f
XBREAK::
	%GET_CURRENT_GRAPH_ENTRY
@@:
	pop dword ptr fs:[0]
	pop ecx
	pop ecx
	pop ebp
	pop ecx
	pop ecx
	pop ecx
	pop edx
	.if !Eax
		.if (Edx != MAGIC) || (Ecx < 10H)
			Int 3	; VM
		.else
			%DBG $Jcc, JccCount
			%DBG $Jmp, JmpCount
			%DBG $Call, CallCount
			%DBG $Ret, RetCount
			%DBG $Sys, SysCount
			%DBG $Line, LineCount
		.endif
	.endif
	ret
Ip endp
end Ip