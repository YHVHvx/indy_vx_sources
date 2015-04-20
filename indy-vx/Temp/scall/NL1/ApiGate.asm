; o Защита стека.
;
; o MI, UM
;
; (с) Indy, 2011
;
.code

OP_PUSH32	equ 68H
OP_RETN	equ 0C2H	; ret #

SYSSTUB struct
; typedef NTSTATUS (NTAPI *PCSR_SERVER_API_ROUTINE)(IN PPORT_MESSAGE Request, IN PPORT_MESSAGE Reply);
Gate		PVOID ?	; Call [CsrServerApiRoutine]
; PCSR_SERVER_API_ROUTINE CsrServerApiRoutine
Link		PVOID ?	; CsrServerApiRoutine
Back		PVOID ?	; Ip'
pFlag	PVOID ?	; CsrServerProcess
Flag		ULONG ?	; BYTE [CsrServerProcess]
Cookie	PVOID ?	;
Chain	PVOID ?	; [CsrServerApiRoutine]
SYSSTUB ends
PSYSSTUB typedef ptr SYSSTUB

OP_ESC_2B	equ 0FH

JCC_SHORT_OPCODE_BASE	equ 70H
JCC_NEAR_OPCODE_BASE	equ 80H

; o Jcc short: 0x70 + JCC_*
; o Jcc near: 0x0F 0x80 + JCC_*

JCC_E	equ 4	; ZF
JCC_NE	equ 5	; !ZF

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

; +
;
; Поиск стаба.
;
; o Перед загрузкой CsrServerProcess должна быть загружена и инициализирована User32.dll
;   Иначе коннект к подсистеме в CsrClientConnectToServer() завершится с ошибкой.
; 
CsrQueryGate proc uses ebx esi edi NtBase:PVOID, Info:PSYSSTUB
Local Entries[2]:PVOID
	%SEHPROLOG
	xor ecx,ecx
	mov Entries[0],07B07D433H	; HASH("CsrClientCallServer")
	mov Entries[4],ecx
	invoke LdrEncodeEntriesList, NtBase, addr Entries
	test eax,eax
	mov esi,Entries[0]	; @CsrClientCallServer()
	jnz Exit
	lea ebx,[esi + 0C0H]
Next:
	xor edi,edi
	.if byte ptr [esi] == OP_ESC_2B
; Jcc near.
		cmp byte ptr [esi + 1],JCC_NEAR_OPCODE_BASE + JCC_E
		je @f
		cmp byte ptr [esi + 1],JCC_NEAR_OPCODE_BASE + JCC_NE
		jne Step
		inc edi
	@@:
		mov eax,dword ptr [esi + 2]
		lea eax,[eax + esi + 6]
	.else
; Jcc short.
		cmp byte ptr [esi],JCC_SHORT_OPCODE_BASE + JCC_E
		je @f
		cmp byte ptr [esi],JCC_SHORT_OPCODE_BASE + JCC_NE
		jne Step
		inc edi
	@@:
		movzx eax,byte ptr [esi + 1]
		btr eax,7
		.if Carry?
	   		sub eax,80H
		.endif
		lea eax,[eax + esi + 2]
	.endif
; ** ** 18 00 00 00 8B ** 20 89 ** 08 8B ** 24 56 56 89 46 0C FF 15
	cmp dword ptr [eax + 2],18H
	jne Step
	cmp dword ptr [eax + 14],89565624H
	jne Step
	cmp dword ptr [eax + 18],15FF0C46H
	jne Step
	cmp word ptr [eax + 11],8B08H
	jne Step
	cmp word ptr [eax + 8],8920H
	mov ecx,Entries[0]
	jne Step
	mov esi,ecx
	.if word ptr [Ecx] == 3D80H
; 80 3D XXXXXXXX 00		cmp byte ptr [CsrServerProcess],0
		.if byte ptr [Ecx + 6] == 1
			xor dl,1
		.endif
		inc ecx
	.elseif byte ptr [Ecx] == 38H
; 38 1D XXXXXXXX	cmp byte ptr ds:[_CsrServerProcess],reg8
; 38 CMP Eb, Gb
		mov dl,byte ptr [ecx + 1]
		and dl,NOT(MODRM_REG_MASK)
		cmp dl,00000101B
		jne Step
	.endif
	mov edx,dword ptr [esi + 2]	; CsrServerProcess
	add eax,14H
	mov ebx,Info
	assume ebx:PSYSSTUB
	add ecx,6
	mov [ebx].Gate,eax
	mov [ebx].Flag,edi
	mov eax,dword ptr [eax + 2]
	mov [ebx].pFlag,edx
	mov esi,ecx
	mov [ebx].Link,eax
	Call VirXasm32
	add esi,eax
	mov [ebx].Back,esi
	xor eax,eax
	mov [ebx].Chain,eax
	jmp Exit
Step:
	mov Entries[0],esi	; Ip'
	Call VirXasm32
	add esi,eax
	cmp ebx,esi
	ja Next
	mov eax,STATUS_NOT_FOUND
	%SEHEPILOG
	ret
CsrQueryGate endp

EXCEPTION_CHAIN_END	equ -1

; -
; o Только тест, следует хранить в другом месте!
;
%ENVPTR macro Reg32
	mov Reg32,fs:[TEB.Peb]
	add Reg32,X86_PAGE_SIZE - sizeof(SYSSTUB)
endm

API_FRAME struct
Args		ULONG ?
Sfc		PSTACK_FRAME ?	; SFC head.
Ip		PVOID ?	; API ret ptr.
API_FRAME ends

API_GATE_ERROR	equ 2

ifdef OPT_ENABLE_DBG_LOG
	$API_STUB_CALLED		CHAR "API_STUB ( @Api = 0x%X", CRLF
	$API_STUB_GETENVPTR		CHAR "API_STUB.GETENVPTR: 0x%X", CRLF
	$API_STUB_LOCKREAD		CHAR "API_STUB.LOCKREAD(Gate): 0x%X", CRLF
	$API_STUB_ENCRYPT		CHAR "API_STUB.ENCRYPT: @Frame = 0x%X", CRLF
	$API_STUB_RETURNED		CHAR "API_STUB ) Ip = 0x%X", CRLF
	$API_STUB_CsrQueryGate	CHAR "API_STUB.CsrQueryGate: Status = 0x%X", CRLF
	$API_STUB_GETENVPTR2	CHAR "API_STUB.GETENVPTR2: 0x%X", CRLF
	$API_STUB_LdrLoadUser32	CHAR "API_STUB.LdrLoadUser32 (", CRLF
	$API_STUB_LdrLoadUser32x	CHAR "API_STUB.LdrLoadUser32 ) Status = 0x%X, Base = 0x%X", CRLF
endif

; +
;
; [esp]		Ip
; [esp + 4]	Arg's
; [esp + 2*4]	@Api
;
API_STUB proc C
	%OUT "WARNING: STPT(KM NOT SUPPORTED)"
	%DBG $API_STUB_CALLED, dword ptr [esp + 2*4 + 9*4]
	push ebx
	%GETENVPTR
	%DBG $API_STUB_GETENVPTR, Eax
	jz Error
	mov ebx,eax
	assume ebx:PUENV
	%SPINLOCK [ebx].LockApi, Init, Error
	mov eax,[ebx].ApiStub.Gate
	%DBG $API_STUB_LOCKREAD, Eax
Gate:
	pop ebx
	pop eax	; Ip
	pop ecx	; Arg's
	mov edx,dword ptr fs:[TEB.Tib.StackBase]
	xchg dword ptr [esp],eax	; @Api
	push ebp
	push ecx
	xor API_FRAME.Ip[esp],edx
	assume ebp:PSTACK_FRAME
	.if (Ebp) && (Ebp != EXCEPTION_CHAIN_END)
	   push eax
	   xor API_FRAME.Sfc[esp + 4],edx
@@:
	   mov eax,[ebp].Next
	   .if Eax && (Eax != EXCEPTION_CHAIN_END)
	      %DBG $API_STUB_ENCRYPT, Eax
	      xor [ebp].Next,edx
	      xor [ebp].Ip,edx
	      mov ebp,eax
	      jmp @b
	   .endif
	   pop eax
	.endif
	test ecx,ecx
	lea edx,[ecx*4 + sizeof(API_FRAME) - 4]
	jz CallApi
@@:
	push dword ptr [esp + edx]
	dec ecx
	jnz @b
CallApi:
	push eax
	%GETENVPTR
	%DBG $API_STUB_GETENVPTR2, Eax
	mov eax,UENV.ApiStub.Gate[eax]
	mov ebp,EXCEPTION_CHAIN_END
	xchg dword ptr [esp],eax
	%DBG $API_STUB_RETURNED, Eax
	Jmp Eax
Init:
	lea eax,[ebx].ApiStub
	invoke CsrQueryGate, NULL, Eax
	%DBG $API_STUB_CsrQueryGate, Eax
	test eax,eax
	jnz ErrGate
	%DBG $API_STUB_LdrLoadUser32
	push eax
	invoke LdrLoadUser32, Esp
	test eax,eax
	pop ecx
	%DBG $API_STUB_LdrLoadUser32x, Ecx, Eax
	jnz ErrGate
	mov ecx,[ebx].ApiStub.Link
	%GET_GRAPH_ENTRY xCsrStub
	xchg dword ptr [ecx],eax
	mov [ebx].ApiStub.Chain,eax
	mov ecx,[ebx].ApiStub.pFlag
	mov edx,[ebx].ApiStub.Flag
	mov byte ptr [ecx],dl
	%UNLOCK [ebx].LockApi,LOCK_INIT
	jmp Gate
ErrGate:
	%UNLOCK [ebx].LockApi,LOCK_FAIL
Error:
	pop ebx
	pop eax	; Ip
	pop ecx	; Arg's
	xchg dword ptr [esp],eax
	%DBG $API_STUB_RETURNED, Eax
	Jmp Eax
API_STUB endp

%APICALL macro Routine, ArgNumber
	push Routine
	push ArgNumber
	Call API_STUB
endm

ifdef OPT_ENABLE_DBG_LOG
	$CsrStub_CALLED		CHAR "CsrStub (", CRLF
	$CsrStub_RETURNED		CHAR "CsrStub ) Ip = 0x%X", CRLF
	$CsrStub_GETENVPTR		CHAR "CsrStub.GETENVPTR: 0x%X", CRLF
	$CsrStub_DECRYPT		CHAR "CsrStub.DECRYPT: @Frame = 0x%X", CRLF
	$CsrStub_RETURNED_SYS	CHAR "CsrStub.RETURNED_SYS: Ip = 0x%X", CRLF
	$CsrStub_RETURNED_BACK	CHAR "CsrStub.RETURNED_BACK: Ip = 0x%X", CRLF
	$CsrStub_APIGATE		CHAR "CsrStub.APIGATE", CRLF
	$CsrStub_XCPTGATE		CHAR "CsrStub.XCPTGATE: 0x%X", CRLF
endif
		
; +
;
; CSR:
; rEax: TID
; rEcx: PID
; rEsi: PPORT_MESSAGE
;
; API:
; [esp]		XXXX
; [esp + 4]	API_FRAME
;
; VEH:
; [esp]		XXXX
; [esp + 4]	UENV.XcptIp
;
; SEH:
; rEdx		UENV.XcptCookie
;
; o Перед вызовом API-стаба из VEH должна быть завершена SFC!
;
xCsrStub:
	%GET_CURRENT_GRAPH_ENTRY
CsrStub proc C
	%DBG $CsrStub_CALLED
	push eax
	%GETENVPTR
	%DBG $CsrStub_GETENVPTR, Eax
ifdef OPT_NX_SEHGATE
	.if Edx
		.if UENV.XcptCookie[Eax] == Edx
			pop eax
			add esp,4	; Ip
			jmp SEHP
		.endif
	.endif
endif
	mov edx,eax
	%SPINWAIT UENV.LockApi[edx]	; Ожидаем окончание инициализации.
	pop eax
	assume edx:PUENV
	.if (fs:[TEB.Cid.UniqueThread] == Eax) && (fs:[TEB.Cid.UniqueProcess] == Ecx)
	; Вызов из CsrClientCallServer().
		.if [edx].ApiStub.Chain
			%DBG $CsrStub_RETURNED_SYS, [edx].ApiStub.Chain
	      	jmp [edx].ApiStub.Chain
		.else
			add esp,3*4
			%DBG $CsrStub_RETURNED_BACK, [edx].ApiStub.Back
			jmp [edx].ApiStub.Back
		.endif
	.endif
	pop ecx	; Ip
	cmp [edx].XcptSnap.RwSnap.GpBase,NULL
	mov ecx,[edx].XcptIp
	je Api
	test ecx,ecx
	jz IsXcpt
	push eax
	mov eax,ebp
@@:
	%IS_VALID_FRAME Eax, Api2
	cmp STACK_FRAME.Ip[eax],ecx
	je @f
	mov eax,STACK_FRAME.Next[eax]
	jmp @b
@@:
	pop eax
	jmp NxVEH
Api2:
	pop eax
Api:
	%DBG $CsrStub_APIGATE
	mov ecx,API_FRAME.Sfc[esp]
	mov edx,dword ptr fs:[TEB.Tib.StackBase]
	.if (!Ecx) || (Ecx == EXCEPTION_CHAIN_END)
	   mov ebp,ecx
	.else
	   xor ecx,edx	; SFC
	   mov ebp,ecx
	   assume ecx:PSTACK_FRAME
	   .while ([ecx].Next) && ([ecx].Next != EXCEPTION_CHAIN_END)
	      %DBG $CsrStub_DECRYPT, Ecx
	      xor [ecx].Next,edx
	      xor [ecx].Ip,edx
	      mov ecx,[ecx].Next
	   .endw
	.endif
	mov ecx,API_FRAME.Ip[esp]
	xor ecx,edx
	mov edx,API_FRAME.Args[esp]
	lea esp,[esp + edx*4 + sizeof(API_FRAME)]
	%DBG $CsrStub_RETURNED, Ecx
	Jmp Ecx
IsXcpt:
	push ebx
	push eax
	mov ebx,edx
	assume ebx:PUENV
	sub esp,sizeof(GP_FRAME)
	push esp
	push NULL
	push [ebx].XcptSnap.RwSnap.GpBase
	Call RwIsValidCaller
	test eax,eax
	jnz NoXcpt
	mov ecx,GP_FRAME.First[esp]
	mov edx,GP_FRAME.Last[esp]
; PROTOTYPE
	mov eax,dword ptr [ecx + sizeof(STACK_FRAME)]	; PEXCEPTION_RECORD
	mov ecx,dword ptr [ecx + sizeof(STACK_FRAME) + 4]	; PCONTEXT
	%IS_VALID_FRAME Eax, NoXcpt
	%IS_VALID_FRAME Ecx, NoXcpt
	cmp dword ptr [edx + sizeof(STACK_FRAME)],eax
	jne NoXcpt
	cmp dword ptr [edx + sizeof(STACK_FRAME) + 4],ecx
	jne NoXcpt
	pop ecx	; GP_FRAME.First
	pop edx
	mov ecx,STACK_FRAME.Ip[ecx]
	xor eax,eax
	lock cmpxchg [ebx].XcptIp,ecx
	%DBG $CsrStub_XCPTGATE, Ecx
	pop eax
	pop ebx
	jmp NxVEH
NoXcpt:
	add esp,sizeof(GP_FRAME)
	pop eax
	pop ebx
	jmp Api
CsrStub endp