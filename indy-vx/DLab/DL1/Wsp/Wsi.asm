	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	
.code
; IDP
	include Idp.inc
; LDASM
	include VirXasm32b.asm
	
GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm

SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	assume fs:nothing
	push dword ptr fs:[TEB.Tib.ExceptionList]
	mov dword ptr fs:[TEB.Tib.ExceptionList],esp
	jmp ecx
SEH_Prolog endp

; o Не восстанавливаются Ebx, Esi и Edi.
;
SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[TEB.Tib.ExceptionList]
	lea esp,[esp + 3*4]
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

_$_GetCallbackReference::
	pop eax
	ret

; +
; Поиск ws2_32!sm_context_table
;
WspQueryContextTable proc uses ebx esi edi pWahContextTable:PVOID, pWahCreateHandleContextTable:PVOID
Local $Buffer[16]:CHAR, DllName:UNICODE_STRING
Local WsHandle:PVOID, HlHandle:HANDLE
Local Entries[6]:PVOID, WahEntries[3]:PVOID
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
	lea ecx,WsHandle
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
	push WsHandle
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
	lea ecx,HlHandle
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
	lea ecx,WahEntries
	jnz Unload
	mov WahEntries[0],03E2D73A7H 	; CRC32("WahReferenceContextByHandle")
	mov WahEntries[4],0F646DDDDH 	; CRC32("WahCreateHandleContextTable")
	mov WahEntries[2*4],eax
	push ecx
	push ecx
	push eax
	push HlHandle
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
	cmp WahEntries[0],ecx
	mov edx,dword ptr [esi - 4]	; @sm_context_table
	jne Step2
	mov ecx,pWahContextTable
	mov esi,WahEntries[4]
	mov edi,pWahCreateHandleContextTable
	xor eax,eax
	mov dword ptr [ecx],edx
	mov dword ptr [edi],esi
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
	push WsHandle
	Call Entries[3*4]
	pop eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
WspQueryContextTable endp

VEH proc uses esi edi ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov eax,ExceptionPointers
	mov ecx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume ecx:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [ecx].ExceptionFlags,NULL
	jnz Chain
	cmp [ecx].ExceptionCode,IDP_BREAKPOINT
	je Load
	cmp [ecx].ExceptionCode,IDP_SINGLE_STEP
	jne Chain
;	[...]
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	ret
Chain:
	xor eax,eax
	ret
VEH endp

NTERR macro
	.if Eax
	Int 3
	.endif
endm

APIERR macro
	.if !Eax
	Int 3
	.endif
endm

Entry proc
Local pWahContextTable:PVOID
Local pWahCreateHandleContextTable:PVOID
	invoke WspQueryContextTable, addr pWahContextTable, addr pWahCreateHandleContextTable
	NTERR
	mov ebx,pWahContextTable
	mov eax,IDP_INITIALIZE_ENGINE
	Call IDP
	NTERR
	.if dword ptr [Ebx] == Eax
	push ebx
	Call pWahCreateHandleContextTable	; .. WSAStartup()
	NTERR
	.endif
	push offset VEH
	push 0
	mov eax,IDP_ADD_VEH
	Call IDP
	APIERR
	push 3000H
	push pWahContextTable
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	NTERR
;	[...]
	ret
Entry endp
end Entry