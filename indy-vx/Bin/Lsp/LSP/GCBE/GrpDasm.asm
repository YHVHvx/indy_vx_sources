; o GCBE
; o (c) Indy, 2011.
;
OP_LOOPNE	equ 0E0H
OP_LOOPE	equ 0E1H
OP_LOOP	equ 0E2H
OP_JCXZ	equ 0E3H

MAX_INSTRUCTION_SIZE	equ 15

.code
; +
; Eax - число префиксов.
; Ecx - последний префикс.
; Edx - 0x67 Pfx.
;
; o Размер инструкции не ограничен.
;
QueryPrefixLength proc uses ebx esi edi Address:PVOID
Local PrefixesTable[12]:BYTE
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
	mov dword ptr [PrefixesTable],02EF3F2F0H
	mov dword ptr [PrefixesTable + 4],06426363EH
	mov dword ptr [PrefixesTable + 8],000676665H
	mov esi,Address
	cld
	lea edx,PrefixesTable
	xor ebx,ebx
@@:
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
	mov edx,ebx
	ret
QueryPrefixLength endp

; +
; Eax - размер инструкции.
;
IsRetOpcode proc Address:PVOID
	invoke QueryPrefixLength, Address
	mov edx,Address
	movzx ecx,byte ptr [edx + eax]
	inc eax
	cmp cl,0CFh	; iretd
	je @f
	cmp cl,0C3h	; retn
	je @f
	cmp cl,0CBh	; retf
	je @f
	add eax,2
	cmp cl,0C2h
	je @f
	cmp cl,0CAh	; retf
	je @f
	xor eax,eax
@@:
	ret
IsRetOpcode endp

; +
; Eax - определяет инструкцию Jcc.
; Ecx - размер инструкции.
; Edx - адрес ветвления.
;
IsJccOpcode proc Address:PVOID
	invoke QueryPrefixLength, Address
	mov ecx,eax
	add eax,Address
	cmp byte ptr [eax],0Fh
	je TypeNear
	cmp byte ptr [eax],70h
	jb Error
	cmp byte ptr [eax],7Fh
	jna Load
	cmp byte ptr [eax],0E0h	; jecxz
	jb Error
	cmp byte ptr [eax],0E3h	; jecxz
	ja Error
Load:
	movzx edx,byte ptr [eax + 1]
	btr edx,7
	.if Carry?
	   sub eax,80h
	.endif
	lea edx,[eax + edx + 2]
	add ecx,2
	jmp Valid
TypeNear:
	cmp byte ptr [eax + 1],80h
	jb Error
	cmp byte ptr [eax + 1],8Fh
	ja Error
	cmp ecx,PREFIX_DATA_SIZE
	.if Zero?
	   movzx edx,word ptr [eax + 2]
	   lea edx,[eax + edx + 4]
	   add ecx,4
	.else
	   mov edx,dword ptr [eax + 2]
	   lea edx,[eax + edx + 6]
	   add ecx,6
	.endif
Valid:
	mov eax,TRUE
Exit:
	ret
Error:
	xor eax,eax
	xor ecx,ecx
	xor edx,edx
	jmp Exit
IsJccOpcode endp

; +
; Определяет тип Jcc.
; Возвращает JCC_* + 1.
;
QueryJccType proc Ip:PVOID
	invoke QueryPrefixLength, Ip
	add eax,Ip
	.if byte ptr [eax] == 0FH
	   movzx eax,byte ptr [eax + 1]
	   sub eax,80H
	.else
	   movzx eax,byte ptr [eax]
	   sub eax,70H
	.endif
	jb Error
	cmp eax,10H
	jnb Error
	inc eax
Exit:
	ret
Error:
	xor eax,eax
	jmp Exit
QueryJccType endp

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

; +
; Eax - определяет инструкцию Jmp.
; Ecx - определяет относительное ветвление.
; Edx - адрес ветвления.
;
IsJmpOpcode proc Address:PVOID
	invoke QueryPrefixLength, Address
	add eax,Address
	cmp byte ptr [eax],0EBh	; Jump short.
	jne @f
	movzx edx,byte ptr [eax + 1]
	btr edx,7
	.if Carry?
	   sub eax,80h
	.endif
	lea edx,[eax + edx + 2]
	mov ecx,TRUE
	jmp Valid
@@:
	cmp byte ptr [eax],0E9h	; Jump near relative.
	jne @f
	.if Ecx == PREFIX_DATA_SIZE
	   movzx edx,word ptr [eax + 1]
	   lea edx,[eax + edx + 3]
	.else
	   mov edx,dword ptr [eax + 1]
	   lea edx,[eax + edx + 5]
	.endif
	mov ecx,TRUE
	jmp Valid
@@:
	cmp byte ptr [eax],0EAh	; Jump far absolute.
	je Clear
	cmp byte ptr [eax],0FFh
	jne Error
	movzx edx,byte ptr [eax + 1]
	and edx,MODRM_REG_MASK
	shr edx,3
	sub edx,4
	je Clear
	dec edx
	jnz Error
Clear:
	xor ecx,ecx
	xor edx,edx
Valid:
	mov eax,TRUE
Exit:
	ret
Error:
	xor ecx,ecx
	xor edx,edx
	xor eax,eax
	jmp Exit	
IsJmpOpcode endp

; +
; Eax - определяет инструкцию Call.
; Ecx - определяет относительное ветвление.
; Edx - адрес ветвления.
;
IsCallOpcode proc Address:PVOID
	invoke QueryPrefixLength, Address
	add eax,Address
	cmp byte ptr [eax],0E8h	; Call near relative.
	jne @f
	.if Ecx == PREFIX_DATA_SIZE
	   movzx edx,word ptr [eax + 1]
	   lea edx,[eax + edx + 3]
	.else
	   mov edx,dword ptr [eax + 1]
	   lea edx,[eax + edx + 5]
	.endif
	mov ecx,TRUE
	jmp Valid
@@:
	cmp byte ptr [eax],09Ah
	je Clear
	cmp byte ptr [eax],0FFh
	jne Error
	movzx edx,byte ptr [eax + 1]
	and edx,MODRM_REG_MASK
	shr edx,3
	sub edx,2
	je Clear
	dec edx
	jnz Error
Clear:
	xor ecx,ecx
	xor edx,edx
Valid:
	mov eax,TRUE
Exit:
	ret
Error:
	xor ecx,ecx
	xor edx,edx
	xor eax,eax
	jmp Exit	
IsCallOpcode endp

; +
; Определяет тип инструкции.
;
QueryOpcodeType proc uses ebx Address:PVOID
	mov ebx,HEADER_TYPE_JCC
	invoke IsJccOpcode, Address	; -> Ecx - адрес ветвления.
	test eax,eax
	jnz @f
	dec ebx
	invoke IsJmpOpcode, Address	; -> Ecx - адрес ветвления.
	test eax,eax
	jnz @f
	dec ebx
	invoke IsCallOpcode, Address
	test eax,eax
	jnz @f
	dec ebx
@@:
	mov eax,ebx
	ret
QueryOpcodeType endp

; +
; Определяет размер инструкции.
;
QueryOpcodeSize proc uses esi Opcode:PVOID
	mov esi,Opcode
	Call VirXasm32
	ret
QueryOpcodeSize endp