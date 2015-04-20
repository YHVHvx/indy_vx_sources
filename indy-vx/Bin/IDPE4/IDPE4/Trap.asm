; o IDPE 4.1
;
; o MI, UM
;
; (с) Indy, 2012
;
; +
; 
; G - гранулярность.
;
MAX_INSTRUCTION_LENGTH	equ 15

; +
; Eax - число префиксов.
; Edx - SEG.
;
LPFX proc uses ebx esi edi Ip:PVOID
Local Prefixes[12]:BYTE
Local Ips:ULONG
comment '
Prefixes:
	BYTE PREFIX_LOCK
	BYTE PREFIX_REP
	BYTE PREFIX_REPNZ
	BYTE PREFIX_DATA_SIZE
	BYTE PREFIX_ADDR_SIZE
	BYTE PREFIX_CS
	BYTE PREFIX_SS
	-
	BYTE PREFIX_DS
	BYTE PREFIX_ES
	BYTE PREFIX_FS
	BYTE PREFIX_GS
	'

	mov Ips,MAX_INSTRUCTION_LENGTH + 1
	mov dword ptr [Prefixes],2EF3F2F0H
	mov dword ptr [Prefixes + 4],3E676636H
	mov dword ptr [Prefixes + 2*4],656426H
	mov esi,Ip
	cld
	xor ebx,ebx
@@:
	dec Ips
	jz @f
	lodsb
	lea edi,Prefixes
	mov ecx,11
	repne scasb
	jnz @f
	cmp ecx,4
	jnb @b
	movzx ebx,al
	jmp @b
@@:
	mov eax,MAX_INSTRUCTION_LENGTH
	mov edx,ebx
	sub eax,Ips
	ret
LPFX endp

PcStackBase	equ 4
PcStackLimit	equ 8

ACCESS_TYPE_READ	equ 0
ACCESS_TYPE_WRITE	equ 1

OP_MOVSB		equ 0A4H

.code
; +
; 
xVEH:
	%GET_CURRENT_GRAPH_ENTRY
VEH proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local Env:PUENV
	%GETENVPTR
	mov ecx,ExceptionPointers
	mov ebx,eax
	%DBG "VEH.GETENVPTR: 0x%X", Eax
	jz Chain
	mov Env,ebx
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[ecx]
	mov edi,EXCEPTION_POINTERS.ContextRecord[ecx]
	assume ebx:PUENV
	assume esi:PEXCEPTION_RECORD
	assume edi:PCONTEXT
	%DBG "VEH.XCPT: Ip = 0x%X, Code: 0x%X", [Esi].ExceptionCode, [Esi].ExceptionAddress
	cmp [esi].ExceptionFlags,0
	jne Chain
	cmp [esi].ExceptionCode,STATUS_ACCESS_VIOLATION
	jne IsDB
	%DBG "VEH.AV: Type = 0x%X, Cr2 = 0x%X", [Esi].ExceptionInformation + 4, [Esi].ExceptionInformation
; [ExceptionInformation]:
; +0 Access(0:R, 1:W).
; +4 Cr2
	cmp [esi].NumberParameters,2
	jne Chain
	cmp [esi].ExceptionInformation + 4,10000H
	jnb Chain
	%RLOCK [Ebx].IdpLock
	mov ecx,[ebx].SegCount
	lea edx,[ebx].SegList
	test ecx,ecx
	mov eax,[esi].ExceptionInformation + 4
	jz CLock
	assume edx:PSEGMENT_ENTRY
	.repeat
		.if [Edx].Base <= Eax
			cmp [edx].Limit,eax
			ja @f
		.endif
		add edx,sizeof(SEGMENT_ENTRY)
		dec ecx
	.until Zero?
CLock:
	%RUNLOCK [Ebx].IdpLock
Chain:
	xor eax,eax
Exit:
	%DBG "VEH ) 0x%X", Eax
	ret
@@:
	%RUNLOCK [Ebx].IdpLock
	inc [ebx].IdpCount
	invoke TlsAdd, Ebx
	%DBG "VEH.TlsAdd(): 0x%X", Eax
	jz Chain
	assume eax:PTLS_ENTRY
	push [edi].rEFlags
	push [edi].rDs
	push [edi].rEs
	push [edi].rFs
	push [edi].rGs
	%TLS_START_IDP Eax
	or [edi].rEFlags,EFLAGS_TF
	pop [eax].Idp.rGs
	pop [eax].Idp.rFs
	pop [eax].Idp.rEs
	pop [eax].Idp.rDs
	pop [eax].Idp.rEFlags
	mov [eax].Idp.pSegment,edx
	mov ebx,edx
	push eax
	invoke LPFX, [Esi].ExceptionAddress
	mov ecx,[Esi].ExceptionAddress
	movzx ecx,byte ptr [eax + ecx]
	sub cl,OP_MOVSB
	pop eax
	jz @f
	dec ecx
	jnz Idp
; movs
@@:
	%DBG "VEH.MOVS DETECTED"
	assume ebx:PSEGMENT_ENTRY
	mov ecx,[ebx].Selector
	.if [Esi].ExceptionInformation != ACCESS_TYPE_READ
	; WR
		mov [edi].rEs,ecx
	.else
	; RD
		.if !Edx
			mov [edi].rDs,ecx
		.elseif dl == PREFIX_ES
			mov [edi].rEs,ecx
		.else
			mov [edi].rDs,ecx
			mov [edi].rFs,ecx
			mov [edi].rGs,ecx
		.endif
	.endif
@@:
	mov ecx,SEGMENT_ENTRY.SegBase[ebx]
	ifndef OPT_DISABLE_TEB
		%TLSSET Eax
	endif
	add [esi].ExceptionInformation + 4,ecx
	mov ebx,Env
	mov [esi].ExceptionRecord,eax
	mov [esi].ExceptionCode,IDP_BREAKPOINT
	jmp CLock
Idp:
	mov ecx,SEGMENT_ENTRY.Selector[ebx]
	mov [edi].rDs,ecx
	mov [edi].rEs,ecx
	mov [edi].rFs,ecx
	mov [edi].rGs,ecx
	jmp @b
IsDB:
	assume ebx:PUENV
	mov ecx,[esi].ExceptionAddress
	cmp [esi].ExceptionCode,STATUS_SINGLE_STEP
	jne IsBreak
	%ISWLOCK [ebx].IdpLock.Mux
	jnc @f
	cmp [ebx].BugEvent,XCPT_TRAP
	jne @f
	mov [ebx].BugIp,ecx
	inc [ebx].BugEvent	; XCPT_SKIP
	%DBG "VEH.XCPT_SKIP"
	jmp Load	
@@:
	.if ([ebx].BugEvent == XCPT_END) && ([Ebx].BugIp == Ecx)
		%DBG "VEH.BUG HANDLED"
Load:
		mov eax,EXCEPTION_CONTINUE_EXECUTION
		jmp Exit
	.endif
	mov eax,[ebx].pKiUserExceptionDispatcher
	cmp eax,ecx
	ja @f
	add eax,MAX_INSTRUCTION_LENGTH
	cmp eax,ecx
	ja Load
@@:
	ifdef OPT_DISABLE_TEB
		invoke TlsGet, Ebx
		%DBG "VEH.TlsGet(): 0x%X", Eax
	else
		%TLSGET Eax
		%DBG "VEH.TLSGET(): 0x%X", Eax
		test eax,eax
	endif
	jz Chain	; Не маршрутизация, событие IDP_BREAKPOINT не наступало.
	%TLS_STOP_IDP Eax
	jnc Chain
	assume eax:PTLS_ENTRY
	mov ecx,[eax].Idp.rEFlags
	push [eax].Idp.rDs
	push [eax].Idp.rEs
	and [edi].rEFlags,NOT(EFLAGS_TF)
	push [eax].Idp.rFs
	push [eax].Idp.rGs
	and ecx,EFLAGS_TF
	pop [edi].rGs
	pop [edi].rFs
	or [edi].rEFlags,ecx
	pop [edi].rEs
	pop [edi].rDs
	mov [esi].ExceptionRecord,eax
	mov [esi].ExceptionCode,IDP_SINGLE_STEP
	jmp Chain
IsBreak:
	cmp [esi].ExceptionCode,STATUS_BREAKPOINT
	jne Chain
	%ISWLOCK [ebx].IdpLock.Mux
	jnc Chain
	cmp [ebx].BugEvent,XCPT_BREAK
	jne @f
	cmp [ebx].pDbgBreakPoint,ecx
	jne Chain
	%DBG "VEH.XCPT_TRAP"
	or [edi].rEFlags,EFLAGS_TF
	inc [ebx].BugEvent	; XCPT_TRAP
	jmp Load
@@:
	cmp [ebx].BugEvent,XCPT_SKIP
	jne Chain
	inc [edi].rEip
	%DBG "VEH.XCPT_END"
	inc [ebx].BugEvent	; XCPT_END
	and [edi].rEFlags,NOT(EFLAGS_TF)
	jmp Load
VEH endp