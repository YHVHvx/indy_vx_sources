; Защита от GUI-хуков.
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib
	include \masm32\include\masm32.inc
	includelib \masm32\lib\masm32.lib	
.data
SfcRoutine			PVOID ?
FirstClientLoadLibrary	PVOID ?
apfnDispatchBuffer		PVOID 100H DUP (?)

.code
CLIENTLOADLIBRARY	equ 42h

; Defined in user.h    
; Capture buffer definition for callbacks
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

; Defined in crecv.h
ClientLoadLibrary proc C
; Сохраняем все регистры для сокрытия.
	pushfd
	pushad	; 8x4
	push dword ptr [esp + 10*4]	; PCLIENTLOADLIBRARYMSG
	Call ClientLoadLibraryInternal
	test eax,eax
	jnz @f
	xor eax,eax
; CALLBACKSTATUS
	push eax
	push eax
	push eax	; NTSTATUS
	mov edx,3*4
	mov ecx,esp
	Int 2Bh	; KiCallbackReturn
	add esp,3*4
@@:
	popad
	push KGDT_R3_CODE or RPL_MASK
	push FirstClientLoadLibrary
	iretd
ClientLoadLibrary endp

$CRLF	CHAR 13, 10, 0

ClientLoadLibraryInternal proc uses ebx Message:PCLIENTLOADLIBRARYMSG
Local DllHandle:HANDLE
Local DllName:UNICODE_STRING
Local MessageString:UNICODE_STRING
	mov ebx,Message
	assume ebx:PCLIENTLOADLIBRARYMSG
; ~ User32!FixupCallbackPointers()
	cmp [ebx].CaptureBuf.cCapturedPointers,1
	jne Chain
	cmp [ebx].CaptureBuf.pvVirtualAddress,NULL
	jne Chain
; Строка одна, цикл корректировки не нужен.
	mov eax,[ebx].CaptureBuf.offPointers
	mov edx,dword ptr [ebx].strLib
	mov eax,dword ptr [ebx + eax]
	add ebx,dword ptr [ebx + eax]
	mov dword ptr [DllName],edx
	mov DllName.Buffer,ebx
	invoke LdrGetDllHandle, NULL, 0, addr DllName, addr DllHandle
	cmp eax,STATUS_DLL_NOT_FOUND
	jne Chain
	push ebx
	push NULL
	Call SfcRoutine	; SfcIsFileProtected()
	test eax,eax
	jnz Chain
	invoke RtlUnicodeStringToAnsiString, addr MessageString, addr DllName, TRUE
	test eax,eax
	jnz Chain
	invoke StdOut, MessageString.Buffer
	invoke StdOut, addr $CRLF
	invoke RtlFreeUnicodeString, addr MessageString
	  jmp Chain
Back:
	xor eax,eax
@@:
	ret
Chain:
	mov eax,TRUE
	jmp @b
ClientLoadLibraryInternal endp

; Получение размера KernelCallbackTable.
IMAGE_MASK equ 0FF000000h
	
QueryKernelCallbackTable proc uses ebx esi edi CallbackTable:PVOID, SizeOfCallbackTable:PULONG
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	mov edx,CallbackTable
	mov ebx,PEB.KernelCallbackTable[ebx]
	mov eax,STATUS_UNSUCCESSFUL	
	test ebx,ebx
	mov esi,ebx
	jz Exit
	mov dword ptr [edx],ebx
	cld
	and ebx,IMAGE_MASK
	mov edi,esi
@@:
	lodsd
	and eax,IMAGE_MASK
	cmp eax,ebx
	je @b
	sub esi,edi	;Размер таблицы в байтах.
	mov eax,STATUS_UNSUCCESSFUL
	sub esi,4
	mov edx,SizeOfCallbackTable
	jz Exit
	mov dword ptr [edx],esi
	xor eax,eax
Exit:
	ret
QueryKernelCallbackTable endp

$SfcLibrary	CHAR "sfc_os.dll",0
$SfcRoutine	CHAR "SfcIsFileProtected",0

Entry proc
Local CallbackTable:PVOID, SizeOfCallbackTable:ULONG
	invoke QueryKernelCallbackTable, addr CallbackTable, addr SizeOfCallbackTable
	.if !Zero?
	int 3
	.endif
	
	mov esi,CallbackTable
	mov ecx,SizeOfCallbackTable
	lea edi,apfnDispatchBuffer
	shr ecx,2
	push edi
	rep movsd
	assume fs:nothing

	lea eax,offset ClientLoadLibrary
	mov edx,CLIENTLOADLIBRARY
	mov ebx,fs:[TEB.Peb]
	assume ebx:PPEB
	.if ([ebx].NtMajorVersion == 6) && ([ebx].NtMinorVersion[ecx] == 1)
	dec edx
	.endif
	xchg dword ptr [apfnDispatchBuffer + edx * 4],eax
	pop [ebx].KernelCallbackTable
	mov FirstClientLoadLibrary,eax

	invoke LoadLibrary, addr $SfcLibrary
	mov ebx,eax
	invoke GetProcAddress, ebx, addr $SfcRoutine
	mov SfcRoutine,eax
	
	invoke AllocConsole
	
	invoke MessageBox, NULL, addr $SfcLibrary, addr $SfcLibrary, MB_OK
	ret
Entry endp
end Entry