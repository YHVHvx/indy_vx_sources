; S-маршрутизация.
;
; (c) Indy, 2011.
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib

%APIERR macro
	.if !Eax || (Eax == INVALID_HANDLE_VALUE)
		Int 3
	.endif
endm

%NTERR macro
	.if Eax
	   Int 3
	.endif
endm

%BREAK macro
	Int 3
endm

.code
	include idp.inc	; IDPE
	include Relocate.asm
	
PcStackBase	equ 4
PcStackLimit	equ 8

STACK_FRAME struct
Next		PVOID ?	; PSTACK_FRAME
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

	assume fs:nothing
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
	jne Chain
	mov ebx,[edi].regEbp
	assume ebx:PSTACK_FRAME
@@:
	cmp fs:[PcStackBase],ebx
	jna Load
	cmp fs:[PcStackLimit],ebx
	ja Load
	cmp [ebx].Ip,offset L1
	je Route
	mov ebx,[ebx].Next
	jmp @b
Route:
; S-маршрутизация.
	mov eax,PL1
	mov [ebx].Ip,eax
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	ret
Chain:
	xor eax,eax
	jmp Exit
VEH endp

IdpInitialize proc
Local Temp:PVOID
	%CALLIDP IDP_INITIALIZE_ENGINE
	%NTERR
	push offset VEH
	push 0
	%CALLIDP IDP_ADD_VEH
	.if !Eax
		mov eax,STATUS_INTERNAL_ERROR
		%BREAK
	.endif
; Первый регион в нуле, возможны проверки указателя. Резервируем его.
	lea ecx,Temp
	mov edx,esp
	push sizeof(PVOID)
	and edx,NOT(X86_PAGE_SIZE - 1)
	push ecx
	mov Temp,edx
	%CALLIDP IDP_ADD_REFERENCE
	%NTERR
; Захват PEB.ProcessParameters
	mov ecx,fs:[TEB.Peb]
	push sizeof(RTL_USER_PROCESS_PARAMETERS)
	add ecx,PEB.ProcessParameters
	push ecx
	%CALLIDP IDP_ADD_REFERENCE
	%NTERR
	ret
IdpInitialize endp

$Msg	CHAR "Test message..", 13, 10, 0

.data
PL1	PVOID L1
PL2	PVOID L2
PL3	PVOID L3

.code
$BTitle	CHAR "..", 0
	
Stub proc C
	invoke MessageBox, NULL, addr $Msg, addr $BTitle, MB_OK
	mov eax,TRUE
	jmp PL3
Stub endp

Entry proc
Local ResultLength:ULONG
	invoke LdrInitialize
	invoke IdpInitialize
; Патчим вызов WriteConsole() в буфере.
	invoke GetModuleHandle, NULL
	%APIERR
	mov ecx,DllHandle2
	sub PL1,eax
	sub PL2,eax
	sub PL3,eax
	add PL1,ecx
	add PL2,ecx
	add PL3,ecx
	
	mov eax,PL2
	mov byte ptr [eax],0EAH	; Jmp far
	mov dword ptr [eax + 1],offset Stub
	mov word ptr [eax + 5],cs
	
	invoke AllocConsole
L1::
	%APIERR
	invoke GetStdHandle, STD_OUTPUT_HANDLE
	%APIERR
	mov ebx,eax
L2::
	invoke WriteConsole, Ebx, addr $Msg, sizeof $Msg, addr ResultLength, NULL
	%APIERR
L3::
	invoke CloseHandle, Ebx
	ret
Entry endp
end Entry