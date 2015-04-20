; Определение баланса стека.
;
; o MI, KM/UM.
;
; (c) Indy, 2011.
;

MAX_INSTRUCTION_SIZE	equ 15

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

STK_TYPE_PUSHX		equ 1
STK_TYPE_NCALL		equ 2
STK_TYPE_FCALL		equ 3
STK_TYPE_PUSHA		equ 4

STK_TYPE_POPX		equ 5
STK_TYPE_POPA		equ 6
STK_TYPE_RET		equ 7
STK_TYPE_RETF		equ 8

; +
;
QueryStackSize proc uses ebx esi edi Address:PVOID
Local Buffer[2]:DWORD
	mov esi,Address
	xor ebx,ebx
	invoke QueryPrefixLength, Esi
	test eax,eax	; * opt.
	jz @f
	cmp cl,PREFIX_DATA_SIZE
	sete bl
	mov ecx,eax
	je @f
	push eax
	mov edi,Address
	mov eax,PREFIX_DATA_SIZE
	cld
	repne scasb
	sete bl
	pop eax
@@:
	add esi,eax
	mov al,byte ptr [esi]
	cmp al,50H	; push r32
	jb @f
	cmp al,57H
	jbe PushX
	cmp al,58H	; pop r32
	jb @f
	cmp al,5FH
	jbe PopX
@@:
	cmp al,0E8H	; Call rel 32
	mov ecx,STK_TYPE_NCALL
	je Push32
	cmp al,09AH	; Call far 16:32
	je fCall
	cmp al,60H	; pusha
	jne @f
	mov ecx,STK_TYPE_PUSHA
	mov eax,-8*4
	jmp Pfx0x66
@@:
	cmp al,61H	; popa
	jne @f
	mov ecx,STK_TYPE_POPA
	mov eax,8*4
	jmp Pfx0x66
@@:
	cmp al,0FH
	jne @f
	cmp byte ptr [esi + 1],0A0H	; push fs
	je PushX
	cmp byte ptr [esi + 1],0A8H	; push gs
	je PushX
	cmp byte ptr [esi + 1],0A1H	; pop fs
	je PopX
	cmp byte ptr [esi + 1],0A9H	; pop gs
	je PopX
@@:
	cmp al,0FFH
	jne @f
	mov al,byte ptr [esi + 1]
	and al,MODRM_REG_MASK
	shr al,3
	cmp al,6
	je PushX
; 0xFF
	cmp al,2	; call near r/m32
	mov ecx,STK_TYPE_NCALL
	je Push32
	dec al	; call far m16:32
	jnz @f
fCall:
	mov ecx,STK_TYPE_FCALL
	mov eax,-2*4
	jmp Pfx0x66
@@:
	cmp al,0C3H	; ret
	mov ecx,STK_TYPE_RET
	je Pop32
	cmp al,0C2H	; ret imm16
	jne @f
	movzx eax,word ptr [esi + 1]
	test ebx,ebx
	lea eax,[eax + 2]
	jnz Exit
	add eax,2
	jmp Exit
@@:
	cmp al,0CBH	;  retf
	jne @f
	mov ecx,STK_TYPE_RETF
	mov eax,2*4
	jmp Pfx0x66
@@:
	lea edi,Buffer
	mov ecx,7
	mov Buffer[0],1E160E9CH	; pushf/push cs/push ss/push ds
	mov Buffer[4],00686A06H	; push es/push imm8/push imm32/
	repne scasb
	je PushX
	lea edi,Buffer
	mov ecx,5
	mov Buffer[0],17071F9DH	; popf/pop ds/pop es/pop es
	mov Buffer[4],8FH	; pop mem32
	repne scasb
	je PopX
	xor eax,eax
	xor ecx,ecx
Exit:
	mov edx,esi
	ret
PushX:
	mov ecx,STK_TYPE_PUSHX
Push32:
	mov eax,-4
	jmp Pfx0x66
PopX:
	mov ecx,STK_TYPE_POPX
Pop32:
	mov eax,4
Pfx0x66:
	.if Ebx
		shr eax,1
	.endif
	jmp Exit
QueryStackSize endp

; +
; * inc, dec, add, sub, lea.
; * add sp,imm2 etc. не обрабатываем(с префиксом 0x66).
;
QueryStackSizeForEspMod proc uses ebx Address:PVOID
	mov ebx,Address
	invoke QueryPrefixLength, Ebx
	add ebx,eax
	mov al,byte ptr [ebx]
	cmp al,44H	; inc esp
	jne @f
	mov eax,1
	jmp Exit
@@:
	cmp al,4CH	; dec esp
	jne @f
	mov eax,-1
	jmp Exit
@@:
	cmp al,81H
	jne x1
	cmp byte ptr [ebx + 1],0C4H	; add esp,imm4
	jne @f
	mov eax,dword ptr [ebx + 2]
	jmp Exit
@@:
	cmp byte ptr [ebx + 1],0ECH	; sub esp,imm4
	jne x1
	mov eax,dword ptr [ebx + 2]
	jmp xsub
x1:
	cmp al,83H
	jne x2
	cmp byte ptr [ebx + 1],0C4H	; add esp,imm1
	jne @f
	movzx eax,byte ptr [ebx + 2]
	jmp Exit
@@:
	cmp byte ptr [ebx + 1],0ECH	; sub esp,imm1
	jne x1
	movzx eax,byte ptr [ebx + 2]
xsub:
	not eax
	inc eax
	jmp Exit
x2:
	cmp al,8DH
	je @f
	xor eax,eax
	jmp Exit
@@:
	cmp word ptr [ebx + 1],2464H	; lea esp,[esp + imm1]
	jne @f
	movzx eax,byte ptr [ebx + 3]
	jmp Exit
@@:
	xor eax,eax
	cmp word ptr [ebx + 1],24A4H	; lea esp,[esp + imm4]
	jne Exit
	mov eax,dword ptr [ebx + 3]
Exit:
	ret
QueryStackSizeForEspMod endp