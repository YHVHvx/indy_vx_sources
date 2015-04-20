.code
	assume ebx:nothing, edi:nothing
	include VirXasm32b.asm
	
MAX_INSTRUCTION_SIZE	equ 15

comment '
; +
; Eax - число префиксов.
;
LPFXP proc uses ebx esi edi Ip:PVOID
Local PfxTable[12]:BYTE
	mov ebx,MAX_INSTRUCTION_SIZE + 1
	mov dword ptr [PfxTable],02EF3F2F0H
	mov dword ptr [PfxTable + 4],06426363EH
	mov dword ptr [PfxTable + 8],000676665H
	mov esi,Ip
	cld
	lea edx,PfxTable
@@:
	dec ebx
	jz @f
	.if Zero?
		xor eax,eax
		jmp Exit
	.endif
	lodsb
	mov edi,edx
	mov ecx,11
	repne scasb
	jz @b
@@:
	dec esi
	sub esi,Ip
	mov eax,esi
Exit:
	ret
LPFXP endp'

MODRM_MOD		equ 11000000B
MODRM_REG		equ 00111000B
MODRM_RM		equ 00000111B

OP_ESC2B	equ 0FH

JCC_SHORT_OPCODE_BASE	equ 70H
JCC_NEAR_OPCODE_BASE	equ 80H

JCC_LOOPNE	equ 0E0H	; Ecx & !ZF
JCC_LOOPE		equ 0E1H	; Ecx & ZF
JCC_LOOP		equ 0E2H	; Ecx
JCC_ECXZ		equ 0E3H	; !Ecx

JCX_OPCODE_BASE	equ 0E0H

OP_JMP_SHORT	equ 0EBH
OP_JMP_NEAR	equ 0E9H
OP_JMP_FAR	equ 0EAH

OP_CALL_REL	equ 0E8H

FLOW_ENTRY struct
Ip		PVOID ?
_Size	ULONG ?
FLOW_ENTRY ends
PFLOW_ENTRY typedef ptr FLOW_ENTRY

; +
;
Snapshot proc uses ebx esi edi Ip:PVOID, G:PVOID, S:PVOID, Fdyn:BOOLEAN
Local Ip0:PVOID
Local G0:PVOID
Local Scount:ULONG
	push NULL
	mov eax,G
	mov Scount,0
; Ebx: LEN
; Esi: Ip
; Edi: LDE()
	mov esi,Ip
	mov G0,eax
Flow:
	xor ebx,ebx
	mov Ip0,esi
	jmp Step
Next:
	add ebx,edi
	add esi,edi
Step:
	mov ecx,G0
	mov edx,G
	.repeat
		mov eax,FLOW_ENTRY.Ip[ecx]
		.if Eax < Esi
			add eax,FLOW_ENTRY._Size[ecx]
			cmp eax,esi
			ja Load	; Ip ~ G{}
		.endif
		add ecx,sizeof(FLOW_ENTRY)
	.until Ecx >= Edx
Scan:
	Call VirXasm32
	mov edi,eax
	invoke LPFX, Esi
	cmp al,MAX_INSTRUCTION_SIZE
	jnb Load
	movzx ecx,byte ptr [esi + eax]	; Opcode
	cmp cl,OP_ESC2B
	je @f
	cmp cl,JCC_SHORT_OPCODE_BASE
	jb IsCall
	cmp cl,JCC_SHORT_OPCODE_BASE + 15
	ja IsJcx
Jcx:
	movzx eax,byte ptr [esi + eax + 1]	; Disp.
	btr eax,7
	.if Carry?
		sub eax,80H
	.endif
	lea eax,[eax + esi + 2]
	push eax
	jmp Next
@@:
	movzx ecx,byte ptr [esi + eax + 1]
	cmp cl,JCC_NEAR_OPCODE_BASE
	jb IsCall
	cmp cl,JCC_NEAR_OPCODE_BASE + 15
	ja IsCall
	mov eax,dword ptr [esi + eax + 2]
	lea eax,[eax + esi + 6]
	push eax
	jmp Next
IsJcx:
	cmp cl,JCX_OPCODE_BASE
	jb IsCall
	cmp cl,JCC_ECXZ
	jbe Jcx
IsCall:
	cmp cl,OP_CALL_REL
	je @f
	cmp cl,0FFH	; Grp. 5
	jne IsJmp
	movzx ecx,byte ptr [esi + eax + 1]	; ModR/M
	and cl,MODRM_REG
	shr cl,3
	cmp cl,010B
	jne IsJmp
@@:
	mov ecx,S
	add esi,edi
	add ebx,edi
	mov dword ptr [ecx],esi
	inc Scount
	add S,sizeof(PVOID)
	jmp Step
IsJmp:
	cmp cl,OP_JMP_SHORT
	jne @f
	movzx eax,byte ptr [esi + eax + 1]
	btr eax,7
	.if Carry?
		sub eax,80H
	.endif
	lea eax,[eax + esi + 2]
Tjmp:
	push eax
	jmp Cont
@@:
	cmp cl,OP_JMP_NEAR
	jne @f
	mov eax,dword ptr [esi + eax + 1]
	lea eax,[eax + esi + 5]
	jmp Tjmp
@@:
	cmp cl,0FFH
	jne IsRet
	cmp byte ptr [esi + eax + 1],25H	; Grp. 5
	jne IsRet
	mov eax,dword ptr [esi + eax + 2]
	.if Fdyn == FALSE
		add ebx,edi
		jmp Load
	.endif
	mov eax,dword ptr [eax]	; DS
	push eax
	jmp Cont
IsRet:
	cmp cl,0C3H
	je Cont
	cmp cl,0C2H
	jne Next
Cont:
	add ebx,edi
Load:
	assume ecx:PFLOW_ENTRY
	mov ecx,G
	mov eax,Ip0
	mov [ecx]._Size,ebx
	mov [ecx].Ip,eax
	add G,sizeof(FLOW_ENTRY)
xPop:
	pop esi
	test esi,esi
	jz Exit
	mov ecx,G0
	mov edx,G
	.repeat
		mov eax,FLOW_ENTRY.Ip[ecx]
		.if Eax < Esi
			add eax,FLOW_ENTRY._Size[ecx]
			cmp eax,esi
			ja xPop	; Ip ~ G{}
		.endif
		add ecx,sizeof(FLOW_ENTRY)
	.until Ecx >= Edx
	xor ebx,ebx
	mov Ip0,esi
	jmp Scan
Exit:
	mov eax,Scount
	ret
Snapshot endp