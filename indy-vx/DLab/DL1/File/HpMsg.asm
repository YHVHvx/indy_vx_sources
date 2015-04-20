	include ldrexts.asm
	
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

.data
gFpCreateFileW		PVOID ?
gFpCreateFileA		PVOID ?
gEnv				DBG_HEAP_DISPATCH_INFORMATION <>
gTls				PVOID ?
gFileHandle		HANDLE ?
.code

_imp__CreateFileA proto :dword, :dword, :dword, :dword, :dword, :dword, :dword
_imp__CreateFileW proto :dword, :dword, :dword, :dword, :dword, :dword, :dword

; Определяет адрес возврата из CreateFileW() в CreateFileA().
;
QueryFpCreateFileW proc uses ebx esi edi
	mov esi,dword ptr [_imp__CreateFileA]
	mov edi,dword ptr [_imp__CreateFileW]
	lea ebx,[esi + 70H]
@@:
	Call VirXasm32
	cmp al,5
	je IsCall
	cmp al,3
	jne Next
	cmp byte ptr [esi],0C2H	; ret
	je Error
Next:
	add esi,eax
	cmp esi,ebx
	jb @b
Error:
	xor eax,eax
Exit:
	ret
IsCall:
	cmp byte ptr [esi],OP_CALL_NEAR
	jne Next
	mov ecx,dword ptr [esi + 1]
	lea ecx,[ecx + esi + 5]
	cmp ecx,edi
	jne Next
	add eax,esi
	jmp Exit
QueryFpCreateFileW endp

IH_MAGIC	equ 0ABCDE0H

; Вызывается при возврате из CreateFileW().
; Выполняем инвалидацию описателя.
;
gFpCreateFileA_Dispatch proc C
	mov gFileHandle,eax
	mov eax,IH_MAGIC
	jmp gFpCreateFileW
gFpCreateFileA_Dispatch endp

; Вызывается при возврате из RtlpCheckHeapSignature().
; Если вызывается из CreateFileW(), то захватываем адрес возврата.
;
gContinueHandler proc C
	mov ecx,ebp
	assume ecx:PSTACK_FRAME
@@:
	mov eax,[ecx].rEip
	cmp gFpCreateFileW,eax
	je xBreak
	mov ecx,[ecx].rEbp
	test ecx,ecx
	jnz @b
@@:
	mov eax,TRUE
	jmp gTls
xBreak:
	mov [ecx].rEip,gFpCreateFileA_Dispatch
	jmp @b
gContinueHandler endp

UsSystemCall	equ 7FFE0300H

$NtReadFile	CHAR "LG: NtReadFile", 13, 10, 0
$NtQueryInfo	CHAR "LG: NtQueryInformationFile", 13, 10, 0
$NtClose		CHAR "LG: NtClose", 13, 10, 0

_imp__ZwReadFile proto :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword
_imp__ZwQueryInformationFile proto :dword, :dword, :dword, :dword, :dword
_imp__ZwClose proto :dword

; Вызывается при возврате из сервиса.
; Восстанавливаем описатель и перезапускаем сервис.
;
gDispatchService proc C
	mov ecx,dword ptr [esp]	; Ip
	.if dword ptr [esp + 2*4] != IH_MAGIC
	ret
	.endif
; Стаб.
	.if byte ptr [ecx - 12] != 0B8H	; mov eax,#
	ret
	.endif
	.if byte ptr [ecx - 7] != 0BAH	; mov edx,#
	ret
	.endif
	.if dword ptr [ecx - 6] != UsSystemCall
	ret
	.endif
	mov eax,gFileHandle
	sub dword ptr [esp],12
	sub ecx,12
	mov dword ptr [esp + 2*4],eax
	pushad
	.if dword ptr [_imp__ZwReadFile] == Ecx
	invoke DbgPrint, addr $NtReadFile
	.elseif dword ptr [_imp__ZwQueryInformationFile] == Ecx
	invoke DbgPrint, addr $NtQueryInfo
	.elseif dword ptr [_imp__ZwClose] == Ecx
	invoke DbgPrint, addr $NtClose
	.endif
	popad
	ret
gDispatchService endp

gExceptionDispatcher proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
	invoke xHmgrDispatchException, addr gEnv, ExceptionPointers, addr gContinueHandler, addr gTls
	cmp eax,EXCEPTION_CONTINUE_EXECUTION
	je Exit
	mov ebx,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[ebx]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[ebx]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jne Chain
	cmp [esi].ExceptionCode,STATUS_INVALID_HANDLE
	jne Chain
; (leave/ret)
	mov eax,[edi].regEbp
	mov ecx,dword ptr [eax]
	add eax,2*4
	mov [edi].regEbp,ecx
	mov [edi].regEsp,eax
	mov [edi].regEip,gDispatchService
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	ret
Chain:
	xor eax,eax
	jmp Exit
gExceptionDispatcher endp

$MZ	CHAR "LG: %s", 13, 10, 0

Entry proc
Local Buffer[MAX_PATH]:BYTE
Local Count:ULONG
	invoke QueryFpCreateFileW
	APIERR
	mov gFpCreateFileW,eax
	invoke xLdrParseRtlpCheckHeapSignature, addr gEnv
	NTERR
	invoke RtlAddVectoredExceptionHandler, 1, addr gExceptionDispatcher
	APIERR
	invoke xEnableHandleTracing
	NTERR
	ENABLE_DEBUG_EXCEPTIONS
	ENABLE_HEAP_VALIDATION
	INVALIDATE_HEAP_SIGNATURE	; * После установки VEH!
; Test.
	invoke GetModuleFileName, NULL, addr Buffer, MAX_PATH
	APIERR
	invoke CreateFile, addr Buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
	mov ebx,eax
	.if Eax == INVALID_HANDLE_VALUE
	int 3
	.endif
	invoke GetFileSize, Ebx, NULL
	APIERR
	mov dword ptr [Buffer],0
	invoke ReadFile, Ebx, addr Buffer, 2, addr Count, NULL
	APIERR
	invoke CloseHandle, Ebx
	APIERR
	invoke DbgPrint, addr $MZ, addr Buffer
	ret
Entry endp
end Entry