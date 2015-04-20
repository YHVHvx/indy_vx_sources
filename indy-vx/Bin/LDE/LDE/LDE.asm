; LDE
; UM, MI
; (c) Indy, 2011.
;
.code
MAX_INSTRUCTION_LENGTH	equ 15

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

OP_INTN		equ 0CDH
OP_POPSS		equ 017H
OP_IRET		equ 0CFH
OP_RET		equ 0C3H
OP_RETN		equ 0C2H
OP_RETF		equ 0CBH
OP_ENTER		equ 0C8H
OP_LEAVE		equ 0C9H
OP_POPESP		equ 05CH
OP_XCHGESP	equ 094H

ESCAPE_0F		equ 0FH

OP_LSS		equ 0B2H
OP_BSWAPESP	equ 0CCH
OP_SYSENTER	equ 034H
OP_XCHG		equ 087H
OP_CMPXCHG	equ 0B1H
OP_PEXTRW		equ 0C5H

NPX_STATE_LENGTH	equ 512

EXCEPTION_CHAIN_END	equ -1

; +
; Buffer - регион размером MAX_INSTRUCTION_LENGTH с доступом RWE, после которого лежит страница NOACCESS.
; 
	assume fs:nothing
LDE proc uses ebx esi edi Buffer:PVOID, Address:PVOID
Local Ip:PVOID	; Ссылка на исходную инструкцию.
Local Instruction[(MAX_INSTRUCTION_LENGTH + 11B) and NOT(11B)]:BYTE	; Текущая инструкция для копирования в буфер.
Local Prefixes:ULONG	; Число префиксов.
Local PfxMask:DWORD	; Маска для префиксов 0x66, 0x67.
Local Ips:ULONG	; Накапливаемая длина инструкции.
Local SpTable[4]:DWORD
Local KiTrap:PVOID, BpInit:BOOLEAN
Local pNpxState:PVOID
Local NpxState[NPX_STATE_LENGTH + 16]:BYTE
; Сохраняем состояние NPX.
	lea eax,NpxState
	xor ecx,ecx
	add eax,15
	mov KiTrap,ecx
	and eax,NOT(15)
	mov BpInit,ecx
	fxsave [eax]	; Буфер выравнен на 16 байт, иначе #GP.
	mov PfxMask,ecx
	mov pNpxState,eax
; Определяем наличие префиксов 66, 67 и число всех префиксов.
	cld
	xor edx,edx
	mov dword ptr [SpTable],02EF3F2F0H	; LOCK, REPNZ, REP, CS
	mov dword ptr [SpTable + 4],06426363EH	; DS, SS, ES, FS
	mov esi,Address
NextIp:
	lodsb
	cmp al,PREFIX_GS	; GS
	mov ecx,8
	je NextPfx
	lea edi,SpTable
	.if al == 66H
		bts PfxMask,0
		jmp NextPfx
	.elseif al == 67H
		bts PfxMask,1
		jmp NextPfx
	.endif
	repne scasb
	jne @f
NextPfx:
	inc edx
	cmp dl,MAX_INSTRUCTION_LENGTH
	jb NextIp
	xor eax,eax
	jmp Exit
@@:
	mov ax,word ptr [esi]	; AH
	dec esi
	mov Prefixes,edx
	mov Ips,2	
; Esi - ссылка на опкод.
	lea edi,Instruction
; o Для Ev используем префикс переопределения сегмента Ds.
	mov al,PREFIX_DS	; DS
	stosb
	mov al,66H
	bt PfxMask,0
	.if Carry?
		inc Ips
		stosb
	.endif
	inc al
	bt PfxMask,1
	.if Carry?
		inc Ips
		stosb
	.endif
	not edx
	mov ebx,edi
	lea ecx,[edx + MAX_INSTRUCTION_LENGTH + 1]	; Оставшаяся часть инструкции.
	push ebp
	rep movsb
	Call @f
Safe:
	pop dword ptr fs:[0]
	lea esp,[esp + 2*4]
	pop ebp
Exit:
	mov ecx,pNpxState
	fxrstor [ecx]
	ret
@@:
	Call @f
; SEH()
	push ebp
	mov edx,dword ptr [esp + 2*4]
	assume edx:PEXCEPTION_RECORD
	mov esi,dword ptr [esp + 3*4]	; EstablisherFrame
	mov ebp,dword ptr [esi + 3*4]	; Ebp
	mov eax,Buffer
	mov ecx,[edx].ExceptionAddress
	add eax,MAX_INSTRUCTION_LENGTH
	.if [Edx].ExceptionCode == STATUS_ACCESS_VIOLATION
		.if [Edx].ExceptionInformation[4] == Eax
			sub eax,Ips
			.if Eax == Ecx
				inc Ips
				mov esp,esi
				xor eax,eax
				cmp Ips,MAX_INSTRUCTION_LENGTH
				jnb Safe
				mov dword ptr fs:[TEB.Tib.ExceptionList],esp
				jmp Iter
			.endif
		.endif
	.elseif [Edx].ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION
		xor eax,eax
		cmpxchg BpInit,ecx
		.if Zero?
			mov eax,dword ptr [esp + 4*4]	; PCONTEXT
			inc CONTEXT.regEip[eax]
			jmp Reset
		.endif
	.elseif [Edx].ExceptionCode == STATUS_SINGLE_STEP
		xor eax,eax
		cmpxchg KiTrap,ecx
		.if Zero? || (Eax == Ecx)
			mov eax,dword ptr [esp + 4*4]
	Reset:
			and CONTEXT.regEFlags[eax],NOT(EFLAGS_TF)	; Сбрасывает ядро.
			pop ebp
			mov eax,EXCEPTION_CONTINUE_SEARCH
			retn 4*4
		.endif
	.endif
	mov esp,esi
Load:
	mov eax,Ips
	bt PfxMask,0
	.if Carry?
		dec eax
	.endif
	bt PfxMask,1
	.if Carry?
		dec eax
	.endif
	dec eax	; !Ds
	add eax,Prefixes
	jmp Safe
@@:
	push dword ptr fs:[TEB.Tib.ExceptionList]
	mov dword ptr fs:[TEB.Tib.ExceptionList],esp
; Пропускаем инструкции изменяющие Ss/Esp и прерывания.
	lea edi,SpTable[0]
	movzx eax,word ptr [ebx]	; Опкод и ModR/M.
	mov ecx,4
	mov SpTable[0],(OP_RETF shl 24) or (OP_IRET shl 16) or (OP_RET shl 8) or OP_POPSS
	mov SpTable[4],(OP_POPESP shl 24) or (OP_RETN shl 16) or (OP_INTN shl 8) or OP_LEAVE	; 00011000B
	repne scasb
	jz Load
	mov ecx,4
	mov edx,00011000B
	repne scasb
	jnz @f
	shl ecx,1
	ror dl,cl
	and dl,11B
	add Ips,edx
	jmp Load
@@:
	cmp al,OP_ENTER
	jne @f
	add Ips,3
	jmp Load
@@:
	cmp al,OP_XCHGESP
	je Load
	cmp al,ESCAPE_0F
	lea edi,SpTable[0]
	jne Op_1
; ~~~ T-A3 ~~~
	inc ebx
	mov al,ah
	.if (ah == OP_BSWAPESP) || (ah == OP_SYSENTER)
; 0F CC		BSWAP	ESP
		inc Ips
		jmp Load
	.elseif al == OP_LSS
		add byte ptr [ebx],2	; LFS
		jmp Gen
	.elseif (ah >= 40H) && (ah <= 4FH)
; 0F [40%4F]	CMOVcc	Gv, Ev
Gv_Reg:
; Заменяем регистр Esp/Sp на Eax/Ax.
		and byte ptr [ebx + 1],NOT(MODRM_REG_MASK)	; Esp/Sp -> Eax/Ax
		jmp Gen
	.endif
; 0F 20		MOV		Rd, Cd
	cmp al,20H
	je R_Mod_Eax
; 0F 21		MOV		Rd, Dd
	cmp al,21H
	je R_Mod_Eax
; 0F 02		LAR		Gw, Ev
; 0F 03		LSL		Gw, Ev
; 0F AF		IMUL		Gv, Ew
; 0F B4		LFS		Gv, Mp
; 0F B5		LGS		Gv, Mp
; 0F B6		MOVZX	Gv, Eb
; 0F B7		MOVZX	Gv, Ew
; 0F BC		BSF		Gv, Ew
; 0F BD		BSR		Gv, Ew
; 0F BE		MOVSX	Gv, Eb
; 0F BF		MOVSX	Gv, Ew
; 0F 50		MOVMSKPS	Gd/q, Ups
	mov cl,12
	mov SpTable[0],0B4AF0302H	; LAR, LSL, IMUL, LFS
	mov SpTable[4],0BCB7B6B5H	; LGS, MOVZX, BSF
	mov SpTable[2*4],050BFBEBDH	; BSR, MOVSX, MOVMSKPS
	and ah,MODRM_MOD_MASK
	repne scasb
	jz Gv_Reg
; o CVTSS2SI не обрабатываем.
	cmp al,OP_PEXTRW
; 0F C5		PEXTRW	Gd, Nq, Lb
	je Gv_Reg
; 0F A4		SHLD		Ev, Gv, Lb
; 0F A5		SHLD		Ev, Gv, CL
; 0F AB		BTS		Ev, Gv
; 0F AC		SHRD		Ev, Gv, Lb
; 0F AD		SHRD		Ev, Gv, CL
; 0F B3		BTR		Ev, Gv
; 0F C1		XADD		Ev, Gv
; 0F BB		BTC		Ev, Gv
	lea edi,SpTable[0]
	mov cl,8
	mov SpTable[0],0ACABA5A4H	; SHRD, BTS, SHLD
	mov SpTable[4],0BBC1B3ADH	; BTC, XADD, BTR, SHRD
	repne scasb
	jz Ev_Mod_11
	.if al == OP_CMPXCHG
; B1 	CMPXCHG	Ev, Gv
EvGv:
		and byte ptr [ebx + 1],NOT(MODRM_REG_MASK)	; 000B = Eax/Ax
		jmp Ev_Mod_11
	.endif
	cmp al,0BAH	; Grp 8(Ev, Lb)
; BT, BTS, BTR, BTC
	je Ev_Mod_11
	jmp Gen
; ~~~ T-A2 ~~~
Op_1:
	and ah,MODRM_MOD_MASK
	cmp al,OP_XCHG
; 87		XCHG		Ev, Gv
	je EvGv
; 03		ADD		Gv, Ev
; 13		ADC		Gv, Ev
; 23		AND		Gv, Ev
; 33		XOR		Gv, Ev
; 0B		OR		Gv, Ev
; 1B		SBB		Gv, Ev
; 2B		SUB		Gv, Ev
; 62		BOUND	Gv, Ma
; 69		IMUL		Gv, Ev, Lz
; 6B		IMUL		Gv, Ev, Lb
; 8B		MOV		Gv, Ev
; 8D		LEA		Gv, M
; C4		LES		Gz, Mp
; C5		LDS		Gz, Mp
	mov cl,14
	mov SpTable[0],33231303H	; ADD, ADC, AND, XOR
	mov SpTable[4],8D2B1B0BH	; OR, SBB, SUB, LEA
	mov SpTable[2*4],62C5C48BH	; MOV, LES, LDS, BOUND
	mov SpTable[3*4],6B69H	; IMUL
	repne scasb
	jz Gv_Reg	; Esp/Sp -> Eax/Ax.
	.if al == 0BCH	; mov Esp,imm32
		sub byte ptr [ebx],(0BCH - 0B8H)	; Eax
		jmp Gen
	.endif
	cmp al,8EH	; mov Sreg,r/m16
	je Gv_Reg		; Ss -> Es
; o Поле REG не раскодируем(T-A6).
; o Smsw esp не обрабатываем.
;
; 81 Ev, Lz	(Grp 1)
; 83 Ev, Lb	(Grp 1)
; 8F Ev		(Grp 1A)	; C4 - pop esp
; C1 Ev, Lb	(Grp 2)
; D1 Ev, 1	(Grp 2)
; D3 Ev, CL	(Grp 2)
; C7 Ev, Lz	(Grp 11)
; F7 Ev 		(Grp 3)
	lea edi,SpTable
	mov cl,8
	mov SpTable[0],0C18F8381H
	mov SpTable[4],0F7C7D3D1H
	and ah,MODRM_MOD_MASK
	repne scasb
	jz Ev_Mod_11
; 01		ADD		Ev, Gv
; 11		ADC		Ev, Gv
; 21		AND		Ev, Gv
; 31		XOR		Ev, Gv
; 63		ARPL		Ew, Gw
; 09		OR		Ev, Gv
; 19		SBB		Ev, Gv
; 29		SUB		Ev, Gv
; 89		MOV		Ev, Gv
; 8C		MOV		Ev, Sw
	lea edi,SpTable
	mov cl,8
	mov SpTable[0],31211101H		; XOR, AND, ADC, ADD
	mov SpTable[4],29190963H		; SUB, SBB, OR, ARPL
	repne scasb
	jz Ev_Mod_11
	.if (al == 89H) || (al == 8CH)		
Ev_Mod_11:
		.if ah == MODRM_MOD_MASK
R_Mod_Eax:
			and byte ptr [ebx + 1],NOT(MODRM_RM_MASK)
		.endif
	.endif
Gen:
; Генерим трап в диспетчере исключений.
	mov eax,Buffer
; Связка Popf - Cli не должна быть разорвана, формируем код в буфере.
	mov dword ptr [eax],00030268H
	mov dword ptr [eax + 4],0C3FA9D00H
;	push EFLAGS_TF or EFLAGS_IF or EFLAGS_MASK
;	popfd
;	cli
;	ret
	Call eax
Iter:
	sub esp,8*8	; Пространство для pop/popa/popf.

	xor eax,eax
	mov edi,Buffer
	lea esi,Instruction
	add edi,MAX_INSTRUCTION_LENGTH
; IRET-фрейм.
	push EFLAGS_TF or EFLAGS_IF or EFLAGS_MASK	; EFlags
	sub edi,Ips
	push Cs	; KGDT_R3_CODE or RPL_MASK
	mov ecx,Ips
	push edi	; Ip
	
	xor eax,eax
	xor ebx,ebx
	xor edx,edx
	xor ebp,ebp

	rep movsb
	
	mov es,eax
	mov ds,eax
	mov gs,eax
	mov fs,eax
	
	xor ecx,ecx
	xor esi,esi
	xor edi,edi
	
; Трап возникнет после исполнения инструкции в буфере.
	BYTE OP_IRET	; Iretd
LDE endp