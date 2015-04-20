; Захват загрузчика.
;
; \IDP\Public\User\Test\Other\LdrLock\LdrLock.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

.code
	include ..\..\..\Bin\Graph\Mm\Img.asm

;$DllName	CHAR "psapi.dll",0
	
ThreadStartThunk proc UserParameter:PVOID
; Поток попытается захватить критическую секцию из LdrpInitialize().
;	invoke LoadLibrary, addr $DllName
	invoke Beep, 2000, 140
	invoke RtlExitUserThread, STATUS_SUCCESS
	int 3
ThreadStartThunk endp

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

; +
; Поиск переменной LdrpLoaderLockAcquisitionCount.
;
; LdrLockLoaderLock:
; ...
; B9 XXXX		mov ecx,offset ntdll._LdrpLoaderLockAcquisitionCount
; F00FC119	lock xadd dword ptr ds:[ecx],ebx
;
QueryLdrpLoaderLockAcquisitionCountReference proc uses edi AcquisitionCountReference:PVOID
Local Buffer[2]:PVOID
	mov dword ptr [Buffer],95DB37F4H	; CRC32("LdrLockLoaderLock")
	mov dword ptr [Buffer + 4],0
	invoke NtEncodeEntriesList, NULL, 0, addr Buffer, addr Buffer
	cld
	test eax,eax
	mov edi,dword ptr [Buffer]
	jnz exit_
	mov ecx,0A4H
	mov al,0B9H
scan_:
	repne scasb
	jne @f
	cmp dword ptr [edi + 4],19C10FF0H
	jne @f
	mov ecx,dword ptr [edi]
	mov edx,AcquisitionCountReference
	xor eax,eax
	mov dword ptr [edx],ecx
	jmp exit_
@@:
	test ecx,ecx
	jnz scan_
	mov eax,STATUS_NOT_FOUND
exit_:
	ret
QueryLdrpLoaderLockAcquisitionCountReference endp

Entry proc
Local ThreadHandle:HANDLE, ClientId:CLIENT_ID
Local Cookie:DWORD, AcquisitionCountReference:PVOID
Local Context:CONTEXT
	invoke QueryLdrpLoaderLockAcquisitionCountReference, addr AcquisitionCountReference
	BREAKERR
; Захватываем лоадер.
	invoke LdrLockLoaderLock, 0, NULL, addr Cookie
	BREAKERR
	invoke RtlCreateUserThread, NtCurrentProcess, NULL, FALSE, 0, 0, 0, addr ThreadStartThunk, 0, addr ThreadHandle, addr ClientId
	BREAKERR
; При каждом захвате лоадера выполняется инкремент переменной LdrpLoaderLockAcquisitionCount.
	mov ebx,AcquisitionCountReference
	mov eax,dword ptr [ebx]
; Ожидаем вход потока в критическую секцию LdrpLoaderLock(). Ссылка в PEB.LoaderLock.
@@:
	invoke Sleep, 30
	cmp dword ptr [ebx],eax
	je @b
; Далее можно получить контекст ждущего потока, выполнить бактрейс и заменить адрес возврата.
	mov Context.ContextFlags,CONTEXT_ALL
	invoke ZwGetContextThread, ThreadHandle, addr Context
	BREAKERR
;	...
; Первый фрейм содержит адрес возврата в RtlEnterCriticalSection() из RtlpWaitForCriticalSection().
; -	
	invoke Sleep, 3000
; Освобождаем критическую секцию(разлочиваем лоадер), поток выйдет из ожидания и захватит её.
	invoke LdrUnlockLoaderLock, 0, Cookie
	BREAKERR
	invoke WaitForSingleObject, ThreadHandle, INFINITE
	ret
Entry endp
end Entry