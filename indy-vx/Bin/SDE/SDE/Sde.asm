; SDE
; o MI
; (c) Indy, 2010.

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

SIB_SCALE_MASK		equ 11000000B
SIB_INDEX_MASK		equ 00111000B
SIB_BASE_MASK		equ 00000111B

OP_ESC_2B	equ 0FH

OP_BOUND	equ 62H
OP_ARPL	equ 63H
OP_IMUL4	equ 69H
OP_IMUL1	equ 6BH
OP_INSB	equ 6CH
OP_INSD	equ 6DH
OP_OUTSB	equ 6EH
OP_OUTSD	equ 6FH
OP_INT	equ 0CDH
OP_XLAT	equ 0D7H

OP_LAR	equ 2
OP_LSL	equ 3
OP_CMOVcc	equ 40H
OP_SETcc	equ 90H
OP_BT	equ 0A3H
OP_BTS	equ 0ABH
OP_BTC	equ 0BBH

OVSEG_DS	equ 1
OVSEG_SS	equ 2
OVSEG_ES	equ 3
OVSEG_XY	equ 4	; MOVS, CMPS(Es:[Edi], Ds:[Esi])

QueryOverrideSegment proc Ip:PVOID, Pfx16:BOOLEAN
	mov edx,Ip
	movzx eax,byte ptr [edx]
;
; One-byte opcode map. E/O codes for ModRM field.
;   0123456789ABCDEF
; 0 1111000011110000
; 1 1111000011110000
; 2 1111000011110000
; 3 1111000011110000
; 4 0000000000000000
; 5 0000000000000000
; 6 0011000001010000
; 7 0000000000000000
; 8 1111111111111010
; 9 0000000000000000
; A 0000000000000000
; B 0000000000000000
; C 1100110000000000
; D 1111000000000000
; E 0000000000000000
; F 0000000000000000
;
	push 00000000000000000000000000000000B
	push 00000000000011110000000000110011B
	push 00000000000000000000000000000000B
	push 00000000000000000101111111111111B
	push 00000000000000000000101000001100B
	push 00000000000000000000000000000000B
	push 00001111000011110000111100001111B
	push 00001111000011110000111100001111B
	cmp al,OP_ESC_2B
;
; Two-byte opcode map. E code for ModRM field.
;   0123456789ABCDEF
; 0 0011000000000100
; 1 0000000000000001
; 2 0000000000000000
; 3 0000000000000000
; 4 1111111111111111
; 5 0000000000000000
; 6 0000000000000000
; 7 0000000000000000
; 8 0000000000000000
; 9 1111111111111111
; A 0001110000011101
; B 1111111100011111
; C 1100000000000000
; D 0000000000000000
; E 0000000000000000
; F 0000000000000000
;
	push 00000000000000000000000000000000B
	push 00000000000000000000000000000011B
	push 11111000111111111011100000111000B
	push 11111111111111110000000000000000B
	push 00000000000000000000000000000000B
	push 00000000000000001111111111111111B
	push 00000000000000000000000000000000B
	push 10000000000000000010000000001100B
	mov ecx,eax
	je Esc2B	; 2-byte escape.
	shr eax,5
	and cl,31
	bt dword ptr [esp + eax*4 + 8*4],ecx
	jc ModRM1
	mov al,byte ptr [edx]
	sub al,6CH
	jb NoSeg1
	sub al,2
	jbe SegEs1	; INS
	sub al,2
	jbe SegDs1	; OUTS
	sub al,(8FH - 6CH - 4)
	jb NoSeg1
	.if Zero?
ExtsGrp1A:
; Grp 1A
	   test byte ptr [edx + 1],MODRM_REG_MASK	; ModR/M
	   jnz NoSeg1
	   jmp ModRM1
	.endif
	sub al,(0A0H - 8FH)
	jb NoSeg1
	sub al,3
	jbe SegDs1	; MOV
	sub al,4
	jbe SegXY	; MOVS, CMPS
	sub al,2
	jbe NoSeg1
	sub al,2
	jbe SegEs1	; STOS
	sub al,2
	jbe SegDs1	; LODS
	sub al,2
	jbe SegEs1	; SCAS
	sub al,(0C6H - 0AFH)
	jb NoSeg1
	sub al,2
	jbe ExtsGrp1A	; Grp 11
	sub al,(OP_XLAT - 0C8H)
	jz SegDs1	; XLAT ???
	jb NoSeg1
	sub al,(0F6H - OP_XLAT)
	jb NoSeg1
	sub al,2
	ja @f
; Grp 3
	mov al,byte ptr [edx + 1]	; ModR/M
	and al,111000B
	cmp al,001000B
	jne ModRM1
NoSeg1:
	jmp NoSeg2
SegDs1:
	jmp SegDs2
SegEs1:
	jmp SegEs
ModRM1:
	jmp ModRM2
@@:
	sub al,(0FEH - 0F6H - 2)
	jb NoSeg2
	jnz @f
ExtsGrp4:
; Grp 4
	mov al,byte ptr [edx + 1]	; ModR/M
	and al,MODRM_REG_MASK
	cmp al,001000B
	jbe ModRM1	; INC, DEC
	jmp NoSeg1
@@:
; Grp 5
	mov al,byte ptr [edx + 1]	; ModR/M
	and al,MODRM_REG_MASK
	cmp al,111000B
	je NoSeg
	jmp ModRM1
Esc2B:
	movzx eax,byte ptr [edx + 1]
	mov ecx,eax
	inc edx
	shr eax,5
	and cl,31
	bt dword ptr [esp + eax*4],ecx
	jc ModRM1
	mov al,byte ptr [edx]
	.if !al
; Grp 6
	   mov al,byte ptr [edx + 1]	; ModR/M
 	   and al,MODRM_REG_MASK
	   cmp al,110000B
	   jb ModRM1
NoSeg2:
	   jmp NoSeg
SegDs2:
	jmp SegDs
	.endif
	dec al
	.if Zero?
; Grp 7
	   mov al,byte ptr [edx + 1]
	   and al,MODRM_REG_MASK
	   cmp al,101000B
	   je NoSeg
ModRM2:
	   jmp ModRM
	.endif
	sub al,(0AEH - 1)
; Grp 15 -> 4
	jz ExtsGrp4
	sub al,(0BAH - 0AEH)
	.if Zero?
; Grp 8
	   mov al,byte ptr [edx + 1]
	   and al,MODRM_REG_MASK
	   cmp al,100000B
	   jb NoSeg
	   jmp ModRM
	.endif
	sub al,(0C7H - 0BAH)
	jnz NoSeg
; Grp 9
	mov al,byte ptr [edx + 1]
	and al,MODRM_REG_MASK
	cmp al,001000B
	je ModRM	; CMPXCHG8B
NoSeg:
	xor eax,eax
	jmp Exit
SegDs:
	mov al,OVSEG_DS
	jmp Exit
SegSs:
	mov al,OVSEG_SS
	jmp Exit
SegEs:
	mov al,OVSEG_ES
	jmp Exit
SegXY:
	mov al,OVSEG_XY
Exit:
	movzx eax,al
	add esp,32*2
	ret
ModRM:
	mov al,byte ptr [edx + 1]	; ModR/M
	mov ah,byte ptr [edx + 1]
	and al,MODRM_MOD_MASK
	and ah,MODRM_RM_MASK	; R/M
	rol al,2	; MOD
	cmp al,11B
	je NoSeg
	.if !Pfx16
; x32
	   sub ah,3
	   jbe SegDs
	   dec ah
	   .if Zero?	; SIB
	      mov al,byte ptr [edx + 2]	; SIB
	      and al,SIB_BASE_MASK
	      sub al,100B	; Esp
	      jz SegSs
	      dec al
	      jz SegSs
	      jmp SegDs
	   .endif
	   dec ah
	   jnz SegDs	; Esi/Edi
	   test al,al
	   jz SegDs	; Disp32
	   jmp SegSs	; Ebp
	.else
; x16
	   sub ah,2
	   jbe SegDs
	   sub ah,2
	   jbe SegSs	; Bp
	   sub ah,2
	   jbe SegDs
	   dec ah
	   jnz SegDs	; Bx
	   test al,al
	   jz SegDs	; Disp16
	   jmp SegSs	; Bp
	.endif
QueryOverrideSegment endp