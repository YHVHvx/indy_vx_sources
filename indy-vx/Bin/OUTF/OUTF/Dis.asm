; OUTEFLAGS()
;
; o MI
; (c) Indy, 2011.

	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

OP_ESC_2B			equ 0FH

.code
; o Префиксы удалены.
; o Не учитывается EFLAGS_MASK(0x2).
; o RF при загрузке Ss не учитываем.
; o Валидность опкодов не проверяем.
;
OUTEFLAGS proc C
	mov edx,eax
	movzx eax,byte ptr [edx]
	cmp al,OP_ESC_2B
	je Esc2B	; 2-byte escape.
	cmp al,40H
	jnb T_40
	cmp al,20H
	jae f_o??szapc	; AND/DAA/SUB/DAS/XOR/AAA/CMP/AAS
	and al,111B
	sub al,110B
	jb f_o??szapc; ADD/ADC
; PUSH/POP
	xor eax,eax
	ret
f_???szapc:
	mov eax,EFLAGS_CF or EFLAGS_PF or EFLAGS_AF or EFLAGS_ZF or EFLAGS_SF
	ret
f_????z???:
	mov eax,EFLAGS_ZF
	ret
Nmod:
	xor eax,eax
	ret
Grp_2:
f_o??szapc:
	mov eax,EFLAGS_CF or EFLAGS_PF or EFLAGS_AF or EFLAGS_ZF or EFLAGS_SF or EFLAGS_OF
	ret
f_o??szap?:
	mov eax,EFLAGS_PF or EFLAGS_AF or EFLAGS_ZF or EFLAGS_SF or EFLAGS_OF
	ret
T_40:
	sub al,50H
	jb f_o??szap?	; INC/DEC
	sub al,(63H - 50H)
	jb Nmod	; PUSH/POP/PUSHA/POPA/BOUND
	je f_????z???	; ARPL
	sub al,(69H - 63H)
	jb Nmod	; SEG/PUSH
	je f_o??szapc	; IMUL
	dec al
	jz Nmod	; PUSH
	dec al	; IMUL
	jz f_o??szapc
	sub al,(80H - 6BH)
	jb Nmod	; INS/OUTS/Jcc
	sub al,(86H - 80H)
	jb f_o??szapc	; Grp_1, TEST
	sub al,(8FH - 86H)
	jbe Nmod	; XCHG/MOV/LEA/POP
	sub al,(9DH - 8FH)
	jb Nmod	; NOP/XCHG/CBW/CWD/CALLF/FWAIT
	jz Op_Popf	; POPF
	dec al
	jz f_???szapc	; SAH
	sub al,(0A6H - 9EH)
	jb Nmod	; LAHF/MOV/MOVS
	sub al,4
	jb f_o??szapc	; CMPS/TEST
	sub al,4
	jb Nmod	; STOS/LODS
	sub al,2
	jb f_o??szapc	; SCAS
	sub al,(0C0H - 0B0H)
	jb Nmod
	sub al,2
	jb Grp_2	; * ModR/M = 11 110 XXX(SAL)
	sub al,(0CDH - 0C2H)
	jb Nmod	; RETN/LES/LDS/ENTER/LEAVE/RETF/INT3
	jz Op_Int	; INT
	dec al
	jz Nmod	; INTO
	dec al
	jz Op_Iret
	sub al,(0D6H - 0CFH)
	jb f_o??szapc	; Grp_2 & AAM/AAD
	sub al,(0DBH - 0D6H)
	jb Nmod	; XLAT/ESC
	jz Esc_DB
	sub al,(0DFH - 0DBH)
	jb Nmod
	jz Esc_DF
	sub al,(0F5H - 0DFH)
	jb Nmod	; LOOPNE/LOOPE/LOOP/JCXZ/IN/OUT/CALL/JMP/IN/OUT/INT1/REPNE/REPE/HLT
	jz f_???????c	; CMC
	sub al,2
	jbe Grp_3
	sub al,2
	jbe f_???????c	; CLC/STC
	sub al,2
	jbe f_??i?????	; CLI/STI
	sub al,2
	jbe f_?d??????	; CLD/STD
	dec al
	jz Grp_4
Grp_5:
	mov al,byte ptr [edx + 1]
	test al,00110000B
	jz f_o??szap?	; INC/DEC
	jmp Nmod2
Op_Int:
	; INT stub..
	mov eax,EFLAGS_RF
	ret
Grp_3:
	mov al,byte ptr [edx + 1]
	and al,MODRM_REG_MASK
	xor al,010B
	jz Nmod2	; NOT
	jmp f_o??szapc
Grp_4:
	test byte ptr [edx + 1],00110000B
	jz f_o??szap?	; INC/DEC
	jmp Nmod2
Esc_DF:	
; FCOMIP/FUCOMIP
Esc_DB:
; FCOMI/FUCOMI
	mov al,byte ptr [edx + 1]
	sub al,0E8H
	jb Nmod2
	sub al,(0F8H - 0E8H)
	jb f_o???z?pc
Nmod2:
	xor eax,eax
	ret
Op_Popf:
	mov eax,EFLAGS_CF or EFLAGS_PF or EFLAGS_AF or EFLAGS_ZF or EFLAGS_SF or EFLAGS_OF \
	or EFLAGS_TF or EFLAGS_DF or EFLAGS_NT or EFLAGS_AC or EFLAGS_ID or EFLAGS_IOPL \
	or EFLAGS_VIF or EFLAGS_VIP	; Cleared.
	ret
Op_Iret:
	mov eax,EFLAGS_CF or EFLAGS_PF or EFLAGS_AF or EFLAGS_ZF or EFLAGS_SF or EFLAGS_OF \
	or EFLAGS_TF or EFLAGS_DF or EFLAGS_RF or EFLAGS_NT or EFLAGS_AC or EFLAGS_ID or EFLAGS_IOPL \
	or EFLAGS_VM or EFLAGS_VIF or EFLAGS_VIP
	ret
f_o???z?pc:
	mov eax,EFLAGS_CF or EFLAGS_PF or EFLAGS_ZF or EFLAGS_OF
	ret
f_???????c:
	mov eax,EFLAGS_CF
	ret
f_??i?????:
	mov eax,EFLAGS_IF
	ret
f_?d??????:
	mov eax,EFLAGS_DF
	ret
Esc2B:
	mov al,byte ptr [edx + 1]
	test al,al
	jz Grp_6
	dec al
	jz Nmod2	; Grp_7
	sub al,2
	jbe ff_????z???	; LAR/LSL
	sub al,(20H - 3)
	jb Nmod2	; CLTS/INVD/WBINVD/UD2/NOP/SSE
	sub al,4
	jb ff_o??szapc	; MOV Cr
	sub al,(34H - 24H)
	jb Nmod2
	jz Op_Sysenter	; SYSENTER
	sub al,(0A3H - 34H)
	jb Nmod2
	sub al,3
	jb ff_o??szapc	; BT/SHLD
	sub al,(0ABH - 0A6H)
	jb Nmod2
	sub al,3
	jb ff_o??szapc	; BTS/SHRD
	jz Nmod2	; Grp_15
	sub al,4
	jb ff_o??szapc	; IMUL/CMPXCHG
	jz Nmod2
	dec al
	jz ff_o??szapc	; BTR
	sub al,(0BAH - 0B3H)
	jb Nmod2
	jz ff_o??szapc	; Grp_8
	sub al,4
	jb ff_o??szapc	; BTC/BSF/BSR
	sub al,2
	jb Nmod3
	sub al,2
	jb ff_o??szapc	; XADD
	xor eax,eax
	ret
Grp_6:
	mov al,byte ptr [edx + 2]
	shr al,3
	and al,MODRM_REG_MASK shr 3
	cmp al,100B
	jb Nmod3	; SLDT/STR/LLDT/LTR
	cmp al,110B
	jb ff_????z???	; VERR/VERW
	jmp Nmod3
Op_Sysenter:
	; SYSENTER Stub..
Nmod3:
	xor eax,eax
	ret
ff_????z???:
	mov eax,EFLAGS_ZF
	ret
ff_o??szapc:
	mov eax,EFLAGS_CF or EFLAGS_PF or EFLAGS_AF or EFLAGS_ZF or EFLAGS_SF or EFLAGS_OF
	ret
OUTEFLAGS endp

TestIp:
	bts eax,1

Ip:
	lea eax,offset TestIp
	Call OUTEFLAGS
	ret
end Ip