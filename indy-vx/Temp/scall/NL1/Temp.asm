(W8):
KiUserExceptionDispatcher
	RtlDispatchException
		RtlIsValidHandler
			RtlCaptureImageExceptionValues
		RtlLookupFunctionTable
			RtlpxLookupFunctionTable
				RtlCaptureImageExceptionValues
	
	
	
	
	
	mov ecx,dword ptr [esp + 3*4]
	assume ecx:PEXCEPTION_POINTERS
; - PEXCEPTION_POINTERS принадлежит стеку.
	cmp fs:[PcStackBase],ecx
	jna NoXcpt
	cmp fs:[PcStackLimit],ecx
	ja NoXcpt
	mov eax,[ecx].ExceptionRecord
; - PEXCEPTION_RECORD принадлежит стеку.
	cmp fs:[PcStackBase],eax
	jna NoXcpt
	cmp fs:[PcStackLimit],eax
	ja NoXcpt
	cmp EXCEPTION_RECORD.NumberParameters[eax],EXCEPTION_MAXIMUM_PARAMETERS
	mov edx,[ecx].ContextRecord
	ja NoXcpt
; - PCONTEXT принадлежит стеку.
	cmp fs:[PcStackBase],edx
	jna NoXcpt
	cmp fs:[PcStackLimit],edx
	ja NoXcpt
	assume edx:PCONTEXT
	mov eax,[edx].ContextFlags
	and eax,CONTEXT_CONTROL or CONTEXT_INTEGER or CONTEXT_SEGMENTS or CONTEXT_DEBUG_REGISTERS
	cmp eax,CONTEXT_CONTROL or CONTEXT_INTEGER or CONTEXT_SEGMENTS or CONTEXT_DEBUG_REGISTERS
	mov ecx,[edx].regEsp
	jne NoXcpt
; - Context.rEsp принадлежит стеку.
	cmp fs:[PcStackBase],ecx
	jna NoXcpt
	cmp fs:[PcStackLimit],ecx
	ja NoXcpt
	test [edx].regEFlags,EFLAGS_IF
	jz NoXcpt
	push eax
	lea ecx,[ebx].XcptSnap.RwSnap
	push esp
	push dword ptr [esp + 4*4]
	push GCBE_PARSE_NL_UNLIMITED
	push ecx
	Call RwCheckIpBelongToSnapshot
	pop ecx
	test eax,eax
	jnz NoXcpt
	sub esp,sizeof(GP_CALLER)
	lea eax,[ebx].XcptSnap.RwSnap
	invoke GpFindCallerBelongToSnapshot, Eax, TRUE, GCBE_PARSE_NL_PRIMARY, NULL, UserMode, Esp
	add esp,sizeof(GP_CALLER)
	test eax,eax
	mov edx,dword ptr [esp + 2*4]
	jnz NoXcpt
	lock cmpxchg [ebx].XcptIp,edx
	%DBG $CsrStub_XCPTGATE, Edx
	pop edx
	pop ebx
	jmp NxVEH
		

ifdef OPT_NXSEH_DIRECT_ANALYZE

$NxDirectVEH_GETENVPTR		CHAR "NxDirectVEH.GETENVPTR: 0x%X", CRLF
$NxDirectVEH_EvAreTheSame	CHAR "NxDirectVEH.EvAreTheSame(NT = 0x%X, FRAME.Ip = 0x%X): 0x%X", CRLF
$NxDirectVEH_XcptIp			CHAR "NxDirectVEH.XcptIp: 0x%X", CRLF

xNxDirectVEH:
	%GET_CURRENT_GRAPH_ENTRY
NxDirectVEH proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
	mov eax,ExceptionPointers
	mov eax,EXCEPTION_POINTERS.ExceptionRecord
	cmp EXCEPTION_RECORD.ExceptionCode[eax],STATUS_BREAKPOINT	; Ip' = Ip + 1, KiTrap03()
	jne Chain
	%GETENVPTR
	mov ebx,eax
	%DBG $NxVEHXcptIp_GETENVPTR, Eax
	assume ebx:PUENV
	jz Chain
	mov ecx,[ebx].InitThread
	mov esi,ebp
	cmp fs:[TEB.Cid.UniqueThread],ecx
	jne Chain
	assume esi:PSTACK_FRAME
	invoke LdrGetNtImageBaseU
	mov edi,eax
	jmp First
Next:
	mov esi,[esi].Next
First:
	cmp fs:[PcStackBase],esi
	jna Chain
	cmp fs:[PcStackLimit],esi
	ja Chain
	invoke EvAreTheSame, Ebx, Edi, [Esi].Ip
	%DBG $NxVEHXcptIp_EvAreTheSame, [Esi].Ip, Edi
	test eax,eax
	mov ecx,[Esi].Ip
	jne Next
	mov [ebx].XcptIp,ecx
	%DBG $NxVEHXcptIp_XcptIp, Ecx
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	ret
Chain:
	xor eax,eax
	jmp Exit
NxDirectVEH endp
endif

OP_INT3	equ 0CCH

NxXcptGenInternal proc C
	assume ebx:PUENV
	TSEHOPT equ FLG_ENABLE_SEH
	FLG_ENABLE_SEH	equ TRUE
	%SEHPROLOG
	rdtsc	; %TSC
	mov [ebx].Rand,eax
	BYTE OP_INT3
	%SEHEPILOG
	FLG_ENABLE_SEH equ TSEHOPT
	ret
NxXcptGen endp
