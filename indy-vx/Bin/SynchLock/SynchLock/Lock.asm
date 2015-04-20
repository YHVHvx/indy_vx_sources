; Мониторинг критических секций.
;
; (c) Indy, 2011.
;
comment '
Initialize:
   SectionCopy = CS	; Копия кс.
   ; Инвалидный описатель, отличный от нуля. Нулевой описатель приведёт к созданию евента и апдейту этого по
   ; ля. При ожидании на этом описателе будет сгенерирован #STATUS_INVALID_HANDLE в RtlpWaitForCriticalSecti
   ; on().
   CS.LockSemaphore = MAGIC
   !CS.LockCount	; Захватываем кс. Тред входит в ожидание если LockCount & !CurrentThread.
   CS.RecursionCount = 1	; Для RtlLeaveCriticalSection().
   CS.OwningThread = NULL
   ; В RtlEnterCriticalSection() нет проверки на ноль, это поле обнуляется до вызова RtlpUnWaitCriticalSecti
   ; on() -> ZwSetEventBoostPriority()/ZwReleaseKeyedEvent().
   ...

XcptHandler:
   if XCPT_CODE = #STATUS_INVALID_HANDLE
      if (Ip ~ RtlpWaitForCriticalSection()) or (Ip ~ RtlpUnWaitCriticalSection())
         ; Откатываем функцию и повторно вызываем её с валидной кс.
         Leave(NL = 2)	; Эмулируем возврат из RtlEnterCriticalSection()/RtlLeaveCriticalSection().
         PUSH(@SectionCopy) 
         CONTEXT.rEip = @RtlEnterCriticalSection()
         !CS.LockCount
         CS.RecursionCount = 1
         Continue()
      fi
   fi
   '
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

_imp__RtlEnterCriticalSection proto :dword

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

STACK_FRAME struct
Next		PVOID ?
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

.code
	assume fs:nothing

%IS_VALID_SFC_ENTRY macro pEntry, $Invalid
	cmp fs:[TEB.Tib.StackBase],pEntry
	jna $Invalid
	cmp fs:[TEB.Tib.StackLimit],pEntry
	ja $Invalid
endm

%TLS_GET_VALUE macro Reg32
	mov Reg32,fs:[TEB.Tib.StackBase]
	mov Reg32,dword ptr [Reg32 - 4]
endm

%TLS_SET_VALUE macro Value
	mov eax,fs:[TEB.Tib.StackBase]
	mov dword ptr [eax - 4],Value
endm

CONFIGURATION_FRAME struct
Magic	ULONG ?	; PTEB xor PCONFIGURATION_FRAME.
Result	BOOLEAN ?	; Null - ошибка.
Disp		ULONG ?	; Смещение до аргумента.
CONFIGURATION_FRAME ends
PCONFIGURATION_FRAME typedef ptr CONFIGURATION_FRAME

PROTO_BP_BASED	equ 1	
PROTO_SP_BASED	equ 2

; Пользовательские макро для загрузки значений из глобальных переменных.
;
%GET_GLOBAL_CFG macro
	mov ecx,gType
	mov edx,gDisp
endm

%GET_2ND_DISPATCH macro
	lea eax,Cs2ndDispatch
endm

QueryPrototype proc uses ebx esi edi pRtlEnterCriticalSection:PVOID, pCS:PRTL_CRITICAL_SECTION, Result:PULONG, Disp:PULONG
Local Config:CONFIGURATION_FRAME
	mov eax,ebp
	xor ecx,ecx
	xor eax,fs:[TEB.Tib.Self]
	mov Config.Result,ecx
	lea edx,Config
	mov Config.Disp,ecx
	mov Config.Magic,eax
	%TLS_SET_VALUE Ebp
	push pCS
	Call pRtlEnterCriticalSection
	mov eax,Config.Result
	mov ecx,Config.Disp
	mov edx,Result
	mov ebx,Disp
	mov dword ptr [edx],eax
	mov dword ptr [ebx],ecx
	ret
QueryPrototype endp

; +
; o NL = 2(Const).
;
VEH proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
	mov eax,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,EXCEPTION_NONCONTINUABLE
	jne Chain
; В зависимости от типа синхрообьекта генерируется:
; o STATUS_OBJECT_TYPE_MISMATCH для KeyedEvent в ZwWaitForKeyedEvent().
; o STATUS_OBJECT_INVALID_HANDLE для Event в ZwWaitForSingleObject().
	cmp [esi].ExceptionCode,STATUS_INVALID_HANDLE
	je @f
	cmp [esi].ExceptionCode,STATUS_OBJECT_TYPE_MISMATCH
	jne Chain
@@:
	mov eax,[edi].regEbp	; ~RtlRaiseStatus()
	assume eax:PSTACK_FRAME
	%IS_VALID_SFC_ENTRY Eax, Chain
	
	mov eax,[eax].Next	; ~RtlpWaitForCriticalSection()
	%IS_VALID_SFC_ENTRY Eax, Chain
	
	%TLS_GET_VALUE Ecx
	%IS_VALID_SFC_ENTRY Ecx, Route	; PCONFIGURATION_FRAME
	
	mov ebx,[eax].Next	; ~RtlEnterCriticalSection()
	%IS_VALID_SFC_ENTRY Ebx, Route
	assume ebx:PSTACK_FRAME
	
	mov edx,fs:[TEB.Tib.Self]
	xor edx,ecx
	cmp ebx,ecx
	je SpBased
	cmp [ebx].Next,ecx
	jne Route
	cmp CONFIGURATION_FRAME.Magic[ecx - sizeof(CONFIGURATION_FRAME)],edx
	jne Route
	mov CONFIGURATION_FRAME.Result[ecx - sizeof(CONFIGURATION_FRAME)],PROTO_BP_BASED
BpRoute:
; Leave & Ret.
	mov [edi].regEbp,ecx
	lea eax,[ebx + 4]
	jmp Load
SpBased:
	cmp CONFIGURATION_FRAME.Magic[ebx - sizeof(CONFIGURATION_FRAME)],edx
	jne Route
	mov CONFIGURATION_FRAME.Result[ebx - sizeof(CONFIGURATION_FRAME)],PROTO_SP_BASED
	sub ecx,eax
	sub ecx,sizeof(CONFIGURATION_FRAME) + 5*4 + sizeof(STACK_FRAME)	; Local's.
	mov CONFIGURATION_FRAME.Disp[ebx - sizeof(CONFIGURATION_FRAME)],ecx
SpRoute:
; Leave & Ret.
	mov ebx,[eax].Next
	lea eax,[eax + ecx + sizeof(STACK_FRAME)]
	mov [edi].regEbp,ebx
Load:
	mov [edi].regEsp,eax
	%GET_2ND_DISPATCH
	mov [edi].regEax,STATUS_SUCCESS
	mov [edi].regEip,eax
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	ret
Chain:
	xor eax,eax
	jmp Exit
Route:
	%GET_GLOBAL_CFG
	dec ecx
	jnz IsSpBased
; PROTO_BP_BASED
	mov ebx,[eax].Next
	%IS_VALID_SFC_ENTRY Ebx, Chain
	mov ecx,[ebx].Next
	jmp BpRoute
IsSpBased:
; PROTO_SP_BASED
	dec ecx
	jnz Chain
	mov ecx,edx
	jmp SpRoute
VEH endp

.data
gType	ULONG ?
gDisp	ULONG ?
CritSect	RTL_CRITICAL_SECTION <>

.code
$Msg	CHAR "CS: [Ip: 0x%p, @Lock: 0x%p]", 13, 10, 0

; На этот стаб управление передаётся при возврате из RtlEnterCriticalSection().
; [Esp]:
;	Ip
;	Arg
;
Cs2ndDispatch proc C
	pushad
	invoke DbgPrint, addr $Msg, dword ptr [esp + 8*4 + 4], dword ptr [esp + 8*4 + 4]
	popad
	retn 4
Cs2ndDispatch endp

Ip proc
	invoke RtlInitializeCriticalSection, addr CritSect
	%NTERR
	invoke RtlAddVectoredExceptionHandler, 1, addr VEH
	%APIERR
	mov CritSect.LockSemaphore,-3 and NOT(1)	; !Keyed event, !NtCurrentProcess, !NtCurrentThread.
	mov CritSect.LockCount,0
	mov CritSect.OwningThread,0
	mov CritSect.RecursionCount,1
	invoke QueryPrototype, dword ptr [_imp__RtlEnterCriticalSection], addr CritSect, addr gType, addr gDisp
	invoke RtlEnterCriticalSection, addr CritSect
	invoke RtlLeaveCriticalSection, addr CritSect
	ret
Ip endp
end Ip

