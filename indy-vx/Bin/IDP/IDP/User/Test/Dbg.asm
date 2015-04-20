; Захват DbgPrint().
; Если имеется отладочный порт(PEB.BeingDebugged = TRUE), 
; то для доставки на него сообщения генерируется исключен
; ие DBG_PRINTEXCEPTION_C, которое можно обработать в VEH.
; Решение ниже заключается в захвате отладочных сообщений 
; техникой IDP(разрушение указателя, бактрейс и трассиров
; ка). Этот пример показывает насколько мощная техника.
;
; \IDP\Public\User\Test\Dbg.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

	includelib \masm32\lib\masm32.lib

	include vars.inc

StdOut proto :PSTR
			
BREAKERR macro
	.if Eax
	int 3
	.endif
endm

.code	; ERW

	include ..\Engine\mi\idp.inc

ENTRIES_LIST struct
_isdigit			PVOID ?
_isupper			PVOID ?
_DbgPrint			PVOID ?
_RtlRaiseException	PVOID ?
ENTRIES_LIST ends
PENTRIES_LIST typedef ptr ENTRIES_LIST

Gl_pctype				PVOID ?
Gl_DbgPrint			PVOID ?
Gl_RtlRaiseException	PVOID ?
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Определяет адрес DbgPrint() и _pctype.
;
Initialize proc uses ebx esi edi
Local EntriesList:ENTRIES_LIST
	lea ecx,EntriesList
	xor edx,edx
	push ecx
	$PUSH_CRC32 08AA7784DH, \	; isdigit
			  0A68981A6H, \	; isupper
			  0D318D52FH, \	; DbgPrint
			  0B09C37BEH		; RtlRaiseException
	push edx
	push edx
	mov eax,IDP_QUERY_ENTRIES
	Call IDP
	test eax,eax
	jnz exit_
	mov eax,EntriesList._isdigit
	Call ParseEntry
	jnz @f
	mov eax,EntriesList._isupper
	Call ParseEntry
	jz error_
@@:
	Call dt_
dt_:
	mov ecx,EntriesList._DbgPrint
	mov ebx,EntriesList._RtlRaiseException
	pop edx
	mov dword ptr [edx + (offset Gl_pctype - offset dt_)],eax
	mov dword ptr [edx + (offset Gl_DbgPrint - offset dt_)],ecx
	mov dword ptr [edx + (offset Gl_RtlRaiseException - offset dt_)],ebx
	xor eax,eax
exit_:
	ret
error_:
	mov eax,STATUS_UNSUCCESSFUL
	jmp exit_
; Не используем дизассемблер длин.
; isdigit:
;	[...]
;	8B45 08			mov eax,dword ptr ss:[ebp + 8]
;	8B0D D0E3977C		mov ecx,dword ptr ds:[_pctype]
;	0FB60441			movzx eax,byte ptr ds:[ecx + eax*2]
;
ParseEntry:
	lea edx,[eax + 2EH]
check_:
	cmp word ptr [eax],0D8BH	; mov ecx,dword ptr ds:[XXXX]
	jne @f
	cmp dword ptr [eax + 6],4104B60FH	; movzx eax,byte ptr ds:[ecx + eax*2]
	jne @f
	mov eax,dword ptr [eax + 2]	; _pctype
	test eax,eax
	db 0C3H	; Ret
@@:
	inc eax
	cmp eax,edx
	jb check_
	xor eax,eax
	db 0C3H	; Ret
Initialize endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
STACK_FRAME struct
rEbp		PVOID ?	; Next frame, PSTACK_FRAME
rEip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

BREAKPOINT_PRINT		equ 1

DBG_PRINTEXCEPTION_C	equ 40010006H

TbLastEip	equ (PAGE_SIZE - 3*4)

; +
; VEH
;
ExceptionDispatcher proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov ecx,ExceptionPointers
	mov edx,EXCEPTION_POINTERS.ExceptionRecord[ecx]
	assume edx:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[ecx]
	assume edi:PCONTEXT
	cmp [edx].ExceptionFlags,NULL
	jnz chain_
; Останов по доступу к целевой области памяти.
	cmp [edx].ExceptionCode,IDP_BREAKPOINT
	je break_
	cmp [edx].ExceptionCode,IDP_SINGLE_STEP
	je trap_
	cmp [edx].ExceptionCode,STATUS_BREAKPOINT
	je int3_
	cmp [edx].ExceptionCode,STATUS_SINGLE_STEP
	jne chain_
	mov eax,[edi].regEip
; Тип вывода определяет флажёк PEB.BeingDebugged:
; 0 - Вывод посредством KiDebugService(Int 0x2D).
; 1 - Вывод посредством генерации сепшена DBG_PRINTEXCEPTION_C(0x40010006).
	cmp word ptr [eax],2DCDH	; Int 0x2D
	jne @f
; Останов в DebugService().
; Eax = BREAKPOINT_PRINT
; Ecx = @String
; Edx = Length
	cmp [edi].regEax,BREAKPOINT_PRINT
	jne trap_
	invoke StdOut, [edi].regEcx
	jmp trap_
@@:
	$LOAD Eax, Gl_RtlRaiseException
	cmp [edi].regEip, Eax
	jne trap_
; ExceptionRecord.ExceptionCode = DBG_PRINTEXCEPTION_C
; ExceptionRecord.NumberParameters = 2
; ExceptionRecord.ExceptionFlags = 0
; ExceptionRecord.ExceptionInformation[ 0 ] = Length + 1
; ExceptionRecord.ExceptionInformation[ 1 ] = @String
	mov eax,[edi].regEsp
	mov eax,dword ptr [eax + 4]	; ExceptionRecord:PEXCEPTION_RECORD
	assume eax:PEXCEPTION_RECORD
	cmp [eax].ExceptionCode,DBG_PRINTEXCEPTION_C
	jne trap_
	cmp [eax].NumberParameters,2
	jne trap_
	push dword ptr [eax].ExceptionInformation + 4
	Call StdOut
trap_:
	or [edi].regEFlags,EFLAGS_TF
	jmp continue_
int3_:
	cmp dword ptr fs:[TbLastEip],NULL
	je chain_
	$GET_REF Eax, Breaker
	xor ecx,ecx
	cmp [edi].regEip,eax
	jne chain_
	xchg dword ptr fs:[TbLastEip],ecx
	mov [edi].regEip,ecx
	jmp clear_tf_
break_:
; Флаг взведён если выполняется вывод.
	cmp fs:[TEB.InDbgPrint],0
	je continue_
	cmp dword ptr fs:[TbLastEip],NULL
	jne continue_
; Начинаем бактрейс для поиска адреса возврата в DbgPrint().
	$LOAD Esi, Gl_DbgPrint
	mov ecx,[edi].regEbp
	lea edx,[esi + 1EH]	; Длину задаём статически.
	assume ecx:PSTACK_FRAME
next_:
	jecxz continue_
	mov eax,[ecx].rEip
	cmp eax,esi
	jb @f
	cmp eax,edx
	jb load_
@@:
	mov ecx,[ecx].rEbp
	jmp next_
load_:
	mov ecx,[ecx].rEbp
	jecxz continue_
; Текущий фрейм содержит адрес возврата в пользовательский код из DbgPrint().
; Первый параметр, указатель на выводимую строку(Format), параметры выше.
; D[ecx + sizeof(STACK_FRAME)] = @Format.
; Если по какойто причине вывод не будет выполнен и трассировка не прекращена, 
; необходимо прекратить её при возврате из DbgPrint(). Для этого заменяем адрес 
; возврата в STACK_FRAME. Прекратить трассировку можно посредством сервиса 
; NtContinue, который вызывается в конце обработки исключения для загрузки 
; контекста в процессор(инструкция Popfd не сбрасывает TF). Сохраним адрес 
; возврата в TEB и загрузим указатель на инструкцию Int3. При останове на 
; этой инструкции восстановим Eip, сбросим TF и вернём управление на код.
	$GET_REF Eax, Breaker
	xchg [ecx].rEip,eax
	mov dword ptr fs:[TbLastEip],eax
	jmp trap_
clear_tf_:
	and [edi].regEFlags,NOT(EFLAGS_TF)
continue_:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp exit_
chain_:
	xor eax,eax
exit_:
	ret
Breaker::
	int 3	; x1
ExceptionDispatcher endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$DbgOut	CHAR "Value: %p", 13, 10, 0

Entry proc
; Инициализация движка.
	mov eax,IDP_INITIALIZE_ENGINE
	Call IDP
	BREAKERR
	invoke Initialize
	BREAKERR
; Устанавливаем VEH последним в цепочке.
	$PUSH_REF ExceptionDispatcher
	push 0
	mov eax,IDP_ADD_VEH
	Call IDP
	.if !Eax
	int 3
	.endif
; Ставим останов на область памяти по ссылке.
; [Gl_pctype] - указатель на переменную pctype, 
; которая содержит ссылку на массив размером 0x200.
	push 200H
	$PUSH Gl_pctype
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	assume ebx:PPEB
	
	invoke AllocConsole

	mov [ebx].BeingDebugged,0
	invoke DbgPrint, addr $DbgOut, 123456H
 
	mov [ebx].BeingDebugged,1
	invoke DbgPrint, addr $DbgOut, 987654H
	
	invoke Sleep, INFINITE

	ret
Entry endp
end Entry