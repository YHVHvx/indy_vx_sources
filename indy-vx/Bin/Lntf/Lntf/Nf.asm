; o Регистрация загрузочной нотифи.
; o MI, UM
;
; (с) Indy, 2011
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib


.code
	assume fs:nothing
%GET_NT_BASE macro Reg32
	mov Reg32,fs:[TEB.Peb]
	mov Reg32,PEB.Ldr[Reg32]
	mov Reg32,PEB_LDR_DATA.InLoadOrderModuleList.Flink[Reg32]
	mov Reg32,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[Reg32]
	mov Reg32,LDR_DATA_TABLE_ENTRY.DllBase[Reg32]	; ntdll.dll
endm

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

	%GET_GRAPH_REFERENCE

	assume fs:nothing
SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	push ecx
	ret
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 2*4]
	pop ebp
	push ecx
	ret
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
	push dword ptr [esp + 2*4]
	ret
SEH_GetRef endp

FLG_ENABLE_SEH	equ TRUE

%SEHPROLOG macro EpilogLabel
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog_Reference
		Call SEH_Prolog
	endif
endm

%SEHEPILOG macro ExitLabel
	ifdef FLG_ENABLE_SEH
		jmp Exit
  	SEH_Epilog_Reference:
		%GET_CURRENT_GRAPH_ENTRY
	endif
	ifndef ExitLabel
  Exit:
  	else
  ExitLabel:
  	endif
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog
	endif
endm

LdrGetNtBase proc C
	%GET_NT_BASE Eax
	ret
LdrGetNtBase endp

	include Img.asm
	include VirXasm32b.asm

; +
; Перечисление фиксапов для ссылки.
;
; typedef VOID (*LDR_FIXUP_ENUMERATION_CALLBACK)(
;	IN PVOID ImageBase OPTIONAL,
;	IN PVOID Fixup,
;	IN PVOID Context,
;	IN OUT BOOLEAN *StopEnumeration
;	);
;
LdrEnumerateFixups proc uses ebx esi edi ImageBase:PVOID, Section:PIMAGE_SECTION_HEADER, Ip:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
Local ExitFlag:BOOLEAN
Local SectionBaseVA:ULONG, SectionLimitVA:ULONG
	%SEHPROLOG
	.if !ImageBase
		invoke LdrGetNtBase
		mov ImageBase,eax
	.endif
	invoke LdrImageNtHeader, ImageBase, addr ExitFlag
	test eax,eax
	mov ecx,ExitFlag
	mov edx,Section
	jnz Exit
	test edx,edx
	mov esi,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress[ecx + IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof(IMAGE_DATA_DIRECTORY)]
	mov edi,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory._Size[ecx + IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof(IMAGE_DATA_DIRECTORY)]
	.if !Zero?
		mov eax,IMAGE_SECTION_HEADER.VirtualAddress[edx]
		mov SectionBaseVA,eax
		add eax,IMAGE_SECTION_HEADER.VirtualSize[edx]
		mov SectionLimitVA,eax
	.endif
	test esi,esi
	mov edx,Ip
	jz Error
	test edx,edx
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage[ecx]
	jz @f
	sub edx,ImageBase
	jbe Error
	cmp edx,ecx
	jnb Error
@@:
	test edi,edi
	jz Error
	add esi,ImageBase
	add edi,esi	; Limit
	assume esi:PIMAGE_BASE_RELOCATION
Scan:
	mov ebx,[esi].SizeOfBlock
	sub ebx,sizeof(IMAGE_BASE_RELOCATION)
	jbe Error		; ..
	shr ebx,1
	cmp Section,NULL
	mov eax,[esi].VirtualAddress
	jz @f
	cmp SectionBaseVA,eax
	mov edx,SectionLimitVA
	ja Block
	cmp SectionLimitVA,eax
	jbe Block
@@:
	movzx eax,word ptr [esi + ebx*2 + sizeof(IMAGE_BASE_RELOCATION) - 2]
	mov edx,eax
	and edx,NOT(0FFFH)
	and eax,0FFFH
	cmp edx,(IMAGE_REL_BASED_HIGHLOW shl 12)
	jne Next
	add eax,[esi].VirtualAddress
	mov ecx,Ip
	add eax,ImageBase
	.if !Ecx || dword ptr [Eax] == Ecx
		lea edx,ExitFlag
		mov ExitFlag,FALSE
		push edx
		push CallbackParameter
		push eax
		push ImageBase
		Call CallbackRoutine
		cmp ExitFlag,FALSE
		jne Exit
	.endif
Next:
	dec ebx
	jnz @b
Block:
	add esi,[esi].SizeOfBlock
	cmp esi,edi
	jb Scan
	xor eax,eax
	%SEHEPILOG
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
LdrEnumerateFixups endp

OP_PUSH32	equ 68H
OP_RETN	equ 0C2H	; ret #

LDR_CALLBACK_DATA struct
Routine	PVOID ?
Context	PVOID ?
LDR_CALLBACK_DATA ends
PLDR_CALLBACK_DATA typedef ptr LDR_CALLBACK_DATA

xLdrSearchFixup:
	%GET_CURRENT_GRAPH_ENTRY
LdrSearchFixupCallbackInternal proc ImageBase:PVOID, Fixup:PVOID, CallbackData:PLDR_CALLBACK_DATA, Stop:PBOOLEAN
	mov eax,Fixup
	mov ecx,CallbackData
	dec eax
	.if byte ptr [Eax] == OP_PUSH32
		push Stop
		push LDR_CALLBACK_DATA.Context[ecx]
		push eax
		push ImageBase
		Call LDR_CALLBACK_DATA.Routine[ecx]
	.endif
	xor eax,eax
	ret
LdrSearchFixupCallbackInternal endp

xLdrSearchReferenceInRelocationTable proc ImageBase:PVOID, Section:PIMAGE_SECTION_HEADER, Ip:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
	lea ecx,CallbackRoutine
	%GET_GRAPH_ENTRY xLdrSearchFixup
	invoke LdrEnumerateFixups, ImageBase, Section, Ip, Eax, CallbackParameter
	ret
xLdrSearchReferenceInRelocationTable endp

xLdrSearchFixupForLdrpShutdownInProgress:
	%GET_CURRENT_GRAPH_ENTRY
LdrSearchFixupForLdrpShutdownInProgressCallbackInternal proc ImageBase:PVOID, Fixup:PVOID, Reference:PVOID, Stop:PBOOLEAN
	mov eax,Fixup
	mov ecx,Reference
	cmp dword ptr [eax + 4],50C0950FH	; setne al/push eax
	jne @f
	cmp dword ptr [eax - 4],0538C033H	; xor eax,eax/cmp byte ptr ds:[LdrpShutdownInProgress],al
	jne @f
	add eax,8
	mov edx,Stop
	mov dword ptr [ecx],eax
	mov dword ptr [edx],TRUE
@@:
	xor eax,eax
	ret
LdrSearchFixupForLdrpShutdownInProgressCallbackInternal endp

; +
; Поиск переменной LdrpDllNotificationList.
;
LdrQueryLdrpDllNotificationList proc uses ebx esi edi NtBase:PVOID, pLdrpDllNotificationList:PVOID
Local Reference:PVOID
Local Entries[2]:PVOID
	%SEHPROLOG
	xor ecx,ecx
	mov Entries[0],06254D76CH	; HASH("RtlDllShutdownInProgress")
	mov Entries[4],ecx
	invoke LdrEncodeEntriesList, NtBase, Ecx, addr Entries
	test eax,eax
	mov ecx,Entries[0]
	jnz Exit
	.if dword ptr [ecx] == 0538C033H	; xor eax,eax/cmp byte ptr ds:[LdrpShutdownInProgress],al
		mov ecx,dword ptr [ecx + 4]	; @LdrpShutdownInProgress
	.elseif word ptr [ecx] == 3D80H	; cmp byte ptr ds:[LdrpShutdownInProgress],0
		mov ecx,dword ptr [ecx + 2]
	.else
Error:
		mov eax,STATUS_NOT_FOUND
		jmp Exit
	.endif
	lea edx,Reference
	%GET_GRAPH_ENTRY xLdrSearchFixupForLdrpShutdownInProgress
	invoke LdrEnumerateFixups, NtBase, NULL, Ecx, Eax, Edx
	mov edx,0E856H		; push esi/call LdrpSendDllNotifications
	test eax,eax
	mov esi,Reference
	jnz Exit
	cmp word ptr [esi],dx
	je @f
	cmp word ptr [esi + 2],dx
	jne Error
	inc esi	; push 2
	inc esi
@@:
	add esi,dword ptr [esi + 2]
	add esi,6		; @LdrpSendDllUnloadedNotifications/LdrpSendDllUnloadedNotifications
	lea ebx,[esi + 40H]
Scan:
	Call VirXasm32
	cmp al,6
	je Check
	cmp al,3
	jne @f
	cmp byte ptr [esi],OP_RETN
	je Error
@@:
	add esi,eax
	cmp esi,ebx
	jb Scan
	jmp Error
Check:
	cmp word ptr [esi],358BH	; mov esi,dword ptr ds:[LdrpDllNotificationList]
	jne @b
	mov ebx,dword ptr [esi + 2]
	mov ecx,pLdrpDllNotificationList
	xor eax,eax
	mov dword ptr [ecx],ebx
	%SEHEPILOG
	ret
LdrQueryLdrpDllNotificationList endp

LDR_DLL_NOTIFICATION_DATA struct
ShutdownInProgress	BOOLEAN ?		; LDR_DLL_UNLOADED_FLAG_PROCESS_TERMINATION
FullDllName   		PUNICODE_STRING ?
BaseDllName   		PUNICODE_STRING ?
DllBase			PVOID ?
SizeOfImage		ULONG ?
LDR_DLL_NOTIFICATION_DATA ends
PLDR_DLL_NOTIFICATION_DATA typedef ptr LDR_DLL_NOTIFICATION_DATA

LDR_DLL_NOTIFICATION_RECORD struct
Entry		LIST_ENTRY <>
Handler		PVOID ?
Context		PVOID ?
LDR_DLL_NOTIFICATION_RECORD ends
PLDR_DLL_NOTIFICATION_RECORD typedef ptr LDR_DLL_NOTIFICATION_RECORD

LDR_DLL_NOTIFICATION_REASON_LOADED		equ 1
LDR_DLL_NOTIFICATION_REASON_UNLOADED	equ 2

LDR_DLL_LOADED_NOTIFICATION_DATA		equ 1
LDR_DLL_UNLOADED_NOTIFICATION_DATA	equ 2

LDR_DLL_UNLOADED_FLAG_PROCESS_TERMINATION	equ 1	; def. ntldr.h

; +
; Регистрация нотификатора в LdrpDllNotificationList.
;
; o ListHead:PLDR_DLL_NOTIFICATION_RECORD начало списка(@LdrpDllNotificationList).
; o LdrpLoaderLock/LdrpDllNotificationLock захвачена.
;
LdrRegisterNotification proc ListHead:PLDR_DLL_NOTIFICATION_RECORD, ListRecord:PLDR_DLL_NOTIFICATION_RECORD, Handler:PVOID, Context:PVOID, First:BOOLEAN
	push Handler
	mov ecx,ListHead
	push Context	
	cmp First,FALSE
	mov edx,ListRecord
	.if Zero?
		assume eax:PLDR_DLL_NOTIFICATION_RECORD
		assume ecx:PLDR_DLL_NOTIFICATION_RECORD
		assume edx:PLDR_DLL_NOTIFICATION_RECORD
		mov eax,[ecx].Entry.Flink
		mov [edx].Entry.Blink,ecx
		mov [ecx].Entry.Flink,edx
		mov [edx].Entry.Flink,eax
		mov [eax].Entry.Blink,edx
	.else
		mov eax,[ecx].Entry.Blink
		mov [edx].Entry.Flink,ecx
		mov [ecx].Entry.Blink,edx
		mov [edx].Entry.Blink,eax
		mov [eax].Entry.Flink,edx
	.endif
	pop [edx].Context
	pop [edx].Handler
	ret
LdrRegisterNotification endp

; +
; Регистрация нотификатора в LdrpDllNotificationList.
;
LdrRegisterNotificationEx proc uses ebx esi edi NtBase:PVOID, Handler:PVOID, Context:PVOID, First:BOOLEAN, Cookie:PVOID
Local Entries[5]:PVOID
Local LockCookie:ULONG
Local pLdrpDllNotificationList:PVOID
	%SEHPROLOG
	xor ecx,ecx
	mov Entries[0],095DB37F4H	; HASH("LdrRegisterDllNotification")
	mov Entries[4],ecx
	invoke LdrEncodeEntriesList, NtBase, Ecx, addr Entries
	test eax,eax
	lea ecx,Entries
	jz Api
	cmp eax,STATUS_PROCEDURE_NOT_FOUND
	mov Entries[0],0C84D4FC9H	; HASH("LdrLockLoaderLock")
	mov Entries[4],0684E8EDEH	; HASH("LdrUnlockLoaderLock")
	jne Exit
	xor eax,eax
	mov Entries[2*4],0086E5953H	; HASH("RtlAllocateHeap")
	mov Entries[3*4],04C040550H	; HASH("RtlGetLastNtStatus")
	mov Entries[4*4],eax
	invoke LdrEncodeEntriesList, NtBase, Eax, Ecx
	test eax,eax
	jnz Exit
	invoke LdrQueryLdrpDllNotificationList, NtBase, addr pLdrpDllNotificationList
	test eax,eax
	lea ecx,LockCookie
	jnz Exit
	push ecx
	push eax
	push LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED
	Call Entries[0]	; LdrLockLoaderLock()
	test eax,eax
	mov ecx,fs:[TEB.Peb]
	jnz Exit
	push sizeof(LDR_DLL_NOTIFICATION_RECORD)
	push eax
	push PEB.ProcessHeap[ecx]
	Call Entries[2*4]	; RtlAllocateHeap()
	test eax,eax
	mov ecx,Cookie
	jnz @f
	Call Entries[3*4]	; RtlGetLastNtStatus()
	jmp Unlock
@@:
	mov dword ptr [ecx],eax
	invoke LdrRegisterNotification, pLdrpDllNotificationList, Eax, Handler, Context, First
	xor eax,eax
Unlock:
	push eax
	push LockCookie
	push LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED
	Call Entries[4]	; LdrUnlockLoaderLock()
	pop eax
	%SEHEPILOG
	ret
Api:
	push Cookie
	push Context
	push Handler
	push eax
	Call Entries[0]	; LdrRegisterDllNotification()
	jmp Exit
LdrRegisterNotificationEx endp

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
	invoke LdrEncodeEntriesList, NtBase, Ecx, addr Entries
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
	mov edx,dword ptr [ecx + 2]	; CsrServerProcess
	add eax,14H
	mov ebx,Info
	assume ebx:PSYSSTUB
	add ecx,6
	mov [ebx].Gate,eax
	mov [ebx].Flag,edi
	mov eax,dword ptr [eax + 2]	; CsrServerApiRoutine
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

STACK_FRAME struct
Link		PVOID ?	; PSTACK_FRAME
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

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

; +
;
; [esp]		Ip
; [esp + 4]	Arg's
; [esp + 2*4]	@Api
;
API_STUB proc C
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
	   mov eax,[ebp].Link
	   .if Eax && (Eax != EXCEPTION_CHAIN_END)
	      xor [ebp].Link,edx
	      xor [ebp].Ip,edx
	      mov ebp,eax
	      jmp @b
	   .endif
	   pop eax
	.endif
	lea edx,[ecx*4 + sizeof(API_FRAME) - 4]
	jecxz CallApi
@@:
	push dword ptr [esp + edx]
	loop @b
CallApi:
	%ENVPTR Ecx
	mov ebp,EXCEPTION_CHAIN_END
	push SYSSTUB.Gate[ecx]
	jmp eax
API_STUB endp

%APICALL macro Routine, ArgNumber
	push Routine
	push ArgNumber
	Call API_STUB
endm

; +
;
; CSR:
; Eax: TID
; Ecx: PID
; Esi: PPORT_MESSAGE
;
; API:
; [esp]		XXXX
; [esp + 4]	API_FRAME
;
; LDR:
; Esi: PLDR_DLL_NOTIFICATION_RECORD
;
xCsrStub:
	%GET_CURRENT_GRAPH_ENTRY
CsrStub proc C
	%ENVPTR Edx
	assume edx:PSYSSTUB
	.if (fs:[TEB.Cid.UniqueThread] == Eax) && (fs:[TEB.Cid.UniqueProcess] == Ecx)
	; Вызов из CsrClientCallServer().
		.if [edx].Chain
	      	jmp [edx].Chain
		.else
			add esp,3*4
			jmp [edx].Back
		.endif
	.endif
	add esp,4
	cmp [edx].Cookie,esi
	je LdrNotify
Api:
	mov ecx,API_FRAME.Sfc[esp]
	mov edx,dword ptr fs:[TEB.Tib.StackBase]
	.if (!Ecx) || (Ecx == EXCEPTION_CHAIN_END)
	   mov ebp,ecx
	.else
	   xor ecx,edx	; SFC
	   mov ebp,ecx
	   assume ecx:PSTACK_FRAME
	   .while ([ecx].Link) && ([ecx].Link != EXCEPTION_CHAIN_END)
	      xor [ecx].Link,edx
	      xor [ecx].Ip,edx
	      mov ecx,[ecx].Link
	   .endw
	.endif
	mov ecx,API_FRAME.Ip[esp]
	xor ecx,edx
	mov edx,API_FRAME.Args[esp]
	lea esp,[esp + edx*4 + sizeof(API_FRAME)]
	jmp ecx
CsrStub endp

; +
;
CsrInitGate proc uses ebx
	%ENVPTR Ebx
	assume ebx:PSYSSTUB
; Загружаем шлюз.
	%GET_GRAPH_ENTRY xCsrStub
	mov ecx,[ebx].Link
	xchg dword ptr [ecx],eax
	mov [ebx].Chain,eax
; Разрешаем использование шлюза.
	mov ecx,[ebx].pFlag
	mov edx,[ebx].Flag
	mov byte ptr [ecx],dl
	ret
CsrInitGate endp

LdrNotify proc NotificationReason:ULONG, NotificationData:PLDR_DLL_NOTIFICATION_DATA, Context:PVOID
; Тут можно выполнить маршрутизацию или любые другие действия.
	ret
LdrNotify endp

$User32	CHAR "user32.dll", 0
$Test	CHAR "psapi.dll", 0

_imp__LoadLibraryA proto :PSTR

Entry proc
	invoke LoadLibrary, addr $User32
	
	%ENVPTR Ebx
	invoke CsrQueryGate, NULL, Ebx
	invoke LdrRegisterNotificationEx, NULL, SYSSTUB.Gate[ebx], 123H, TRUE, addr SYSSTUB.Cookie[ebx]
	invoke CsrInitGate
	
; CSR api.
	invoke AllocConsole
	
; API & LDR stub's.
	push offset $Test
	%APICALL dword ptr [_imp__LoadLibraryA], 1
	
	ret
Entry endp
end Entry