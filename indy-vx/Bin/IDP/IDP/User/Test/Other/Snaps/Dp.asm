; \IDP\Public\User\Test\Other\Snaps\Dp.asm
;
; Если переменная ShowSnaps в ntdll содержит значение отличное 
; от нуля, то выполняется логирование событий в загрузчике. В 
; эту переменную загружается значение флага FLG_SHOW_LDR_SNAPS
; (0x2) на этапе инициализации процесса из PEB.NtGlobalFlag ес
; ли процесс отлаживается(PEB.BeingDebugged). В свою очередь ф
; лажки загружаются из реестра(\Image File Execution Options, 
; "GlobalFlag").
;
; Перенаправление вывода в файл, если OptionalHeadr.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI(3).
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

	includelib \masm32\lib\masm32.lib

StdOut proto :PSTR

.code
	include ShowSnaps.asm

DBG_PRINTEXCEPTION_C	equ 40010006H

	ASSUME FS:NOTHING
	
ExceptionDispatcher proc uses ebx ExceptionPointers:PEXCEPTION_POINTERS
	mov ebx,ExceptionPointers
	xor eax,eax
	mov ebx,EXCEPTION_POINTERS.ExceptionRecord[ebx]
	assume ebx:PEXCEPTION_RECORD
	.if [Ebx].ExceptionCode == DBG_PRINTEXCEPTION_C
	invoke StdOut, dword ptr [Ebx].ExceptionInformation + 4
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	.elseif [Ebx].ExceptionCode == STATUS_BREAKPOINT
	mov ebx,ExceptionPointers
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	mov ebx,EXCEPTION_POINTERS.ContextRecord[ebx]
	inc CONTEXT.regEip[ebx]
	.endif
	ret
ExceptionDispatcher endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$DbgOut	CHAR "Value: %p", 13, 10, 0
$DllName	CHAR "User32.dll",0
$MsgBox	CHAR "MessageBoxA",0

BREAKNTERR macro
	.if Eax
	int 3
	.endif
endm

BREAKWINERR macro
	.if !Eax
	int 3
	.endif
endm

Entry proc
Local ShowSnaps:PVOID
	invoke AllocConsole
	BREAKWINERR
	invoke QueryShowSnaps, addr ShowSnaps
	BREAKNTERR
	invoke RtlAddVectoredExceptionHandler, 1, addr ExceptionDispatcher
	BREAKWINERR
	mov ecx,ShowSnaps
	mov eax,fs:[TEB.Peb]
	mov byte ptr [ecx],1
	mov PEB.BeingDebugged[eax],1
	invoke LoadLibrary, addr $DllName
	BREAKWINERR
	invoke GetProcAddress, Eax, addr $MsgBox
	BREAKWINERR
	push MB_OK
	push offset $MsgBox
	push offset $MsgBox
	push 0
	Call Eax
	ret
Entry endp
end Entry