; Защита стека.
;  Indy, 2011.
; -
; o Необходимо сформировать локальный фрейм, в котором будет сохранён адрес возврата 
;   и RGP для восстановления(если используются стабом). Так как этот фрейм должен на
;   ходится в стеке выше чем аргументы апи, то формирование можно выполнить двумя сп
;   особами: формировать фрейм до загрузки аргументов с стек, либо после загрузки и 
;   копировать аргументы.
; o Посли криптования стека и вызова апи ни в коем случае не должен быть уменьшен NL 
;   без вызова декриптора. Тоесть из апи не должна быть выполнена развёртка исключен
;   ия, либо вызов апи должен быть защищён сех. Иначе случае изза инвалидной ссылки 
;   в Ebp будет разрушен стек.
; o Вызывающий апи стаб должен поддерживать рекурсивные вызовы. Это например вызов а
;   пи из калбэков. Так как предыдущий вызов апи завершает FSC, то выполняется крипт
;   ование части стека. Эта изоляция позволит избежать коллизий при декриптовке SFC. 
; o Для C конвенции вызова необходимо очистить стек из стаба. Но так как в стеке не 
;   определённое количество аргументов, не известно смещение до структуры содержащей 
;   число аргументов. Поэтому необходимо связать структуру с сех фреймом.
;
	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

.code
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

EXCEPTION_CHAIN_END	equ -1

SEH_FRAME struct
Link			PVOID ?	; PSEH_FRAME
Stub			PVOID ?
XcptHandler	PVOID ?
SafePlace		PVOID ?
Sfc			PVOID ?	; rEbp
SEH_FRAME ends
PSEH_FRAME typedef ptr SEH_FRAME

STACK_FRAME struct
Link		PVOID ?	; PSTACK_FRAME
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

API_FRAME struct
; Opt.
;rEbx	DWORD ?
;rEsi	DWORD ?
;rEdi	DWORD ?
Args		ULONG ?
Sfc		PSTACK_FRAME ?	; SFC head.
Ip		PVOID ?	; API ret ptr.
API_FRAME ends

SYSENV struct
Gate		PVOID ?	; (Call [CsrServerApiRoutine])
Chain	PVOID ?	; Предыдущее значение [CsrServerApiRoutine] = csrsrv!CsrCallServerFromServer, только в контексте csrss.
SYSENV ends
PSYSENV typedef ptr SYSENV

; *************************************************************************************
SYSENV_OFFSET	equ (X86_PAGE_SIZE - sizeof(SYSENV))	; in PEB.

; + 
; Данный макрос возвращает ссылку на глобальную переменную, содержащую структуру SYSENV.
; Смещение структуры SYSENV в переменной постоянно и задано константой SYSENV_OFFSET, 
; тоесть (%ENVPTR + SYSENV_OFFSET):PSYSENV.
;
%ENVPTR macro Reg32
	mov Reg32,fs:[TEB.Peb]
endm
; *************************************************************************************
	%GET_GRAPH_REFERENCE

	assume fs:nothing
SEH_Prolog proc C
	mov edx,dword ptr fs:[TEB.Tib.StackBase]
	pop ecx
	xor eax,edx
	push ebp	; SFC
	push eax	; Safe place
	%GET_GRAPH_ENTRY SEH_Internal
	xor eax,edx
	push eax
	%ENVPTR Edx
	push SYSENV.Gate[edx + SYSENV_OFFSET]
	push dword ptr fs:[TEB.Tib.ExceptionList]	; Link
	mov dword ptr fs:[TEB.Tib.ExceptionList],esp
	jmp ecx
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[TEB.Tib.ExceptionList]
	lea esp,[esp + 3*4]
	pop ebp
	jmp ecx
SEH_Epilog endp

SEH_Internal proc C
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
	mov ebp,SEH_FRAME.Sfc[esp]
	jmp SEH_FRAME.SafePlace[esp]
SEH_Internal endp

%SEH_PROLOG macro
	%GET_GRAPH_ENTRY Safe
	Call SEH_Prolog
endm

%SEH_EPILOG macro
	jmp @f
Safe:
	%GET_CURRENT_GRAPH_ENTRY
@@:
	Call SEH_Epilog
endm

; +
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
	push SYSENV.Gate[ecx + SYSENV_OFFSET]
	jmp eax
API_STUB endp

; +
; Стаб для API и SEH. Вызывается через шлюз(Call [CsrServerApiRoutine]).
;
; API:
; [esp]		XXXX
; [esp + 4]	API_FRAME
;
; SEH:
; Ecx: @GATE
; [esp]		XXXX
; [esp + 4]	XXXX	
; [esp + 2*4]	PEXCEPTION_RECORD ExceptionRecord
; [esp + 3*4]	PSEH_FRAME EstablisherFrame
; [esp + 4*4]	PCONTEXT ContextRecord
; [esp + 5*4]	PVOID DispatcherContext
;
; CSR:
; Eax: PID
; Ecx: TID
; Esi: PPORT_MESSAGE
;
SYS_STUB proc C
	%GET_CURRENT_GRAPH_ENTRY
	%ENVPTR Edx
	.if (fs:[TEB.Cid.UniqueProcess] == Eax) && (fs:[TEB.Cid.UniqueThread] == Ecx)
	   .if SYSENV.Chain[edx + SYSENV_OFFSET]
	      jmp SYSENV.Chain[edx + SYSENV_OFFSET]
	   .endif
	.endif
	cmp [edx + SYSENV_OFFSET].Gate,ecx
	lea esp,[esp + 4]
	mov edx,dword ptr fs:[TEB.Tib.StackBase]
	je Xcpt
	mov ecx,API_FRAME.Sfc[esp]
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
Xcpt:
	mov ecx,dword ptr [esp + 2*4]	; EstablisherFrame
	assume ecx:PSEH_FRAME
	mov eax,[ecx].Sfc
	assume eax:PSTACK_FRAME
	xor [ecx].XcptHandler,edx
	xor [ecx].SafePlace,edx
	.if (Eax) && (Eax != EXCEPTION_CHAIN_END)
	   .while ([eax].Link) && ([eax].Link != EXCEPTION_CHAIN_END)
	      xor [eax].Link,edx
	      xor [eax].Ip,edx
	      mov eax,[eax].Link
	   .endw
	.endif
	jmp [ecx].XcptHandler
SYS_STUB endp

%APICALL macro Routine, ArgNumber
	push Routine
	push ArgNumber
	Call API_STUB
endm

	include Cfg.asm
; +
;
Initialize proc pZwProtectVirtualMemory:PVOID
	invoke QueryGate
;	test eax,eax
	jz Error
	%ENVPTR Edx
	push pZwProtectVirtualMemory
	push eax
	add edx,SYSENV_OFFSET
	assume edx:PSYSENV
	mov [edx].Gate,eax
	%GET_GRAPH_ENTRY SYS_STUB
	xchg dword ptr [ecx],eax
	mov [edx].Chain,ecx
	Call ConfigureConfigDirectory
Exit:
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
Initialize endp
; ~~~~~~~~~~~~~~~~~~~~~~~~ TEST ~~~~~~~~~~~~~~~~~~~~~~~~
$Msg	CHAR "Test",0
$Dll	CHAR "psapi.dll",0

_imp__DbgPrint proto C :DWORD, :VARARG
_imp__LdrSetDllManifestProber proto :PVOID
_imp__LoadLibraryA proto :PSTR
_imp__ZwProtectVirtualMemory proto :HANDLE, :PVOID, :PULONG, :ULONG, :PULONG

Print proc
	invoke DbgPrint, addr $Dll
	Int 3
	ret
Print endp

LdrpManifestProberRoutine proc DllBase:PVOID, FullDllPath:PCWSTR, ActivationContext:PVOID
	%SEH_PROLOG
	   %APICALL offset Print, 0
	%SEH_EPILOG
	xor eax,eax
	ret
LdrpManifestProberRoutine endp

Entry proc
	invoke Initialize, dword ptr [_imp__ZwProtectVirtualMemory]
	push offset LdrpManifestProberRoutine
	%APICALL dword ptr [_imp__LdrSetDllManifestProber], 1
	push offset $Dll
	%APICALL dword ptr [_imp__LoadLibraryA], 1
	ret
Entry endp
end Entry