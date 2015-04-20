	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib
.code
CLIENTLOADLIBRARY	equ 42H

; Defined in user.h
CAPTUREBUF struct
cbCallback		DWORD ?
cbCapture			DWORD ?
cCapturedPointers	DWORD ?
pbFree			PBYTE ?
offPointers		DWORD ?
pvVirtualAddress	PVOID ?
CAPTUREBUF ends
PCAPTUREBUF typedef ptr CAPTUREBUF

CLIENTLOADLIBRARYMSG struct
CaptureBuf	CAPTUREBUF <>
strLib		UNICODE_STRING <>
InitApiRva	ULONG ?
CallInitApi	BOOLEAN ?	; Vista, W7
CLIENTLOADLIBRARYMSG ends
PCLIENTLOADLIBRARYMSG typedef ptr CLIENTLOADLIBRARYMSG

; Callback return status
CALLBACKSTATUS struct
retval	NTSTATUS ?
cbOutput	DWORD ?
pOutput	PVOID ?
CALLBACKSTATUS ends
PCALLBACKSTATUS typedef ptr CALLBACKSTATUS

LoadDll proc uses ebx DllName:PUNICODE_STRING
Local Message:CLIENTLOADLIBRARYMSG
	xor eax,eax
	mov edx,DllName
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	mov Message.CaptureBuf.cCapturedPointers,eax
	push dword ptr [edx]
	push dword ptr [edx + 4]
	mov Message.InitApiRva,eax
	mov Message.CallInitApi,eax
	lea edx,Message
	pop dword ptr [Message.strLib + 4]
	mov eax,CLIENTLOADLIBRARY
	pop dword ptr [Message.strLib]
	assume ebx:PPEB
	.if ([ebx].NtMajorVersion == 6) && ([ebx].NtMinorVersion == 1)
		dec eax
	.endif
	mov ecx,[ebx].KernelCallbackTable
	push edx
	.if Zero?
		mov eax,STATUS_UNSUCCESSFUL
		xor edx,edx
	.else
		Call dword ptr [ecx + eax*4]
		xor edx,edx
		.if Eax == STATUS_NO_CALLBACK_ACTIVE
			.if [ebx].NtMajorVersion == 6
				mov edx,dword ptr [esp - (3*4 + 114H)]
			.else
				mov edx,dword ptr [esp - (3*4 + 0CH)]
			.endif
			xor eax,eax
		.endif
	.endif
	mov fs:[TEB.LastStatusValue],eax
	ret
; Eax:NTSTATUS
; Edx:PVOID
LoadDll endp

$DllName	CHAR "dbghelp.dll",0

Entry proc
Local DllNameW:UNICODE_STRING
	invoke RtlCreateUnicodeStringFromAsciiz, addr DllNameW, addr $DllName
	invoke LoadDll, addr DllNameW
	ret
	Call MessageBox
Entry endp
end Entry