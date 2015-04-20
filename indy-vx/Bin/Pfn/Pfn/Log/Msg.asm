; Захват pfnClient.
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	include \masm32\include\kernel32.inc
	include \masm32\include\user32.inc
	
	includelib \masm32\lib\ntdll.lib
	includelib \masm32\lib\kernel32.lib
	includelib \masm32\lib\user32.lib
	
PWND	typedef PVOID

BREAKZ macro
	.if !Eax
	int 3
	.endif
endm

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

$CRLF	equ CHAR 13, 10, 0	

.code
	include Img.asm

; Индекс в apfnDispatch[].
APFNDWORD	equ 2

; Индекс в pfnClientA[].
PFNDISPATCHMESSAGE	equ 20	; XP
; PFNDISPATCHMESSAGE	equ 21	; Vista, W7

CALLBACKSTATUS struct
retval	NTSTATUS ?
cbOutput	DWORD ?
pOutput	PVOID ?
CALLBACKSTATUS ends
PCALLBACKSTATUS typedef ptr CALLBACKSTATUS

FNDWORDMSG struct
pwnd		PVOID ?
Msg		UINT ?
wParam	WPARAM ?
lParam	LPARAM ?
xParam	ULONG_PTR ?
xpfnProc	PVOID ?
FNDWORDMSG ends
PFNDWORDMSG typedef ptr FNDWORDMSG

CLIENT_MESSAGE struct
pWnd		PWND ?
Message	ULONG ?
wParam	WPARAM ?
lParam	LPARAM ?
pFn		PVOID ?
CLIENT_MESSAGE ends
PCLIENT_MESSAGE typedef ptr CLIENT_MESSAGE

MessageNumber	ULONG 0

DbgStr:
	CHAR "Message #%x(pWnd: %p, Msg: %p, wParam: %p, lParam: %p, pFn: %p)", 0AH, 0
	
; Обращение к переменным из хэндлеров напрямую(только для теста!)
GL_FnDWORD			PVOID ?
GL_PfnDispatchMessage	PVOID ?
_apfnDispatchBuffer		PVOID 100H DUP (?)

; +
; Обработчик pfnDispatchMessage. Сохраняем
; флажки и RGP для оригинального обработчика.
;
_$_DispatchClientMessageReference:
	GET_CURRENT_GRAPH_ENTRY
DispatchClientMessage proc C
	pushfd
	pushfd
	pushad
	mov ebx, GL_PfnDispatchMessage
	lea edx,[esp + 4*11]
	assume edx:PCLIENT_MESSAGE
	inc MessageNumber
	invoke DbgPrint, addr DbgStr, MessageNumber, [edx].pWnd, [edx].Message, [edx].wParam, [edx].lParam, [edx].pFn
; Возврат на оригинальный обработчик.
	mov dword ptr [esp + 4*9],ebx
	popad
	popfd
; Возврат в ядро выполняется после возврата  
; в fnDWORD, посредством XyCallbackReturn().
; Возможен возврат вручную(KiCallbackReturn 
; или NtCallbackReturn).
	ret
DispatchClientMessage endp

; +
; Обработчик fnDWORD. Проверяет причину вызова.
; Если вызов для доставки сообщения, то перехват 
; исполняется заменой указателя FNDWORDMSG(либо 
; заменой указателя на структуру).
; После чего выполняется возврат на оригинальный 
; обработчик fnDWORD, в котором происходит переход 
; на новый обработчик pfnDispatchMessage.
; 
fnDWORD proc C
; Сохраняем флажки, формируем фрейм для возврата.
	pushfd
	push cs
	sub esp,4	; Eip
; Сохраняем RGP для сокрытия.
	pushad	; 8x4
	mov ecx, GL_FnDWORD
; Проверяем обработчик.
	mov edx, GL_PfnDispatchMessage
	mov ebx,dword ptr [esp + 12*4]
	assume ebx:PFNDWORDMSG
	mov dword ptr [esp + 8*4],ecx	; Eip
	cmp [ebx].xpfnProc,edx
	assume ebx:PFNDWORDMSG
	jne @f
	Call _$_DispatchClientMessageReference
	mov [ebx].xpfnProc,eax
@@:	
; Возврат на оригинальный обработчик fnDWORD.
	popad
	iretd
fnDWORD endp

; +
; Определение размера KernelCallbackTable.
;
QueryKernelCallbackTable proc uses ebx esi edi CallbackTable:PVOID, SizeOfCallbackTable:PULONG
	Call SEH_Epilog_Reference
	Call SEH_Prolog
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
	and ebx,0FF000000H
	mov edi,esi
@@:
	lodsd
	and eax,0FF000000H
	cmp eax,ebx
	je @b
	sub esi,edi	; Размер таблицы в байтах.
	mov eax,STATUS_UNSUCCESSFUL
	sub esi,4
	mov edx,SizeOfCallbackTable
	jz Exit
	mov dword ptr [edx],esi
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
QueryKernelCallbackTable endp

; +
; Поиск pfnClientArrayA(PFNCLIENT).
; Массив выравнен в памяти на 4 байта.
;
QueryPfnClientArray proc uses ebx esi edi ImageBase:PVOID, PfnClientArray:PVOID
Local ImageHeader:PIMAGE_NT_HEADERS
Local EntriesList[2]:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	invoke LdrImageNtHeader, ImageBase, addr ImageHeader
	test eax,eax
	mov dword ptr [EntriesList],14345B5CH	; CRC32("DefDlgProcA")
	jnz Exit
	mov dword ptr [EntriesList + 4],eax
	invoke NtEncodeEntriesList, ImageBase, 0, addr EntriesList, addr EntriesList
	test eax,eax
	mov edx,ImageHeader
	jnz Exit
	assume edx:PIMAGE_NT_HEADERS
	mov edi,[edx].OptionalHeader.BaseOfCode
	mov ecx,[edx].OptionalHeader.SizeOfCode
	add edi,ImageBase
	lea edx,[edi + ecx]
	shr ecx,2
	mov ebx,edi
Next:
	cld
	mov eax,dword ptr [EntriesList]
	repne scasd
	jne Error
	std
	mov esi,edi
@@:
	lodsd
	cmp eax,ebx
	jbe @f
	cmp eax,edx
	jb @b
@@:
	mov eax,esi
	sub eax,edi
	cmp eax,8*4
	jnb Store
	jmp Next
Store:
	add esi,2*4
	mov ebx,PfnClientArray
	xor eax,eax
	mov dword ptr [ebx],esi
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	cld
	ret
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
QueryPfnClientArray endp

$User32	CHAR "User32.dll",0
$WaitStr	CHAR "..",0

Entry proc
Local CallbackTable:PVOID, SizeOfCallbackTable:ULONG
Local PfnClientArray:PVOID
	invoke GetModuleHandle, addr $User32
	BREAKZ
	mov ebx,eax
	invoke QueryPfnClientArray, Ebx, addr PfnClientArray
	BREAKERR
	invoke QueryKernelCallbackTable, addr CallbackTable, addr SizeOfCallbackTable
	BREAKERR
	mov esi,CallbackTable
	mov ecx,SizeOfCallbackTable
	lea edi,_apfnDispatchBuffer
	shr ecx,2
	push edi
	lea eax,offset fnDWORD
	mov edx,PfnClientArray
	rep movsd
	assume fs:nothing
	mov ebx,fs:[TEB.Peb]
	assume ebx:PPEB
	cmp [ebx].NtMajorVersion,6
	setz cl
	mov edx,dword ptr [edx + ecx * 4 + PFNDISPATCHMESSAGE * 4]
	xchg dword ptr [_apfnDispatchBuffer + APFNDWORD * 4],eax
	mov GL_PfnDispatchMessage,edx
	pop [ebx].KernelCallbackTable
	mov GL_FnDWORD,eax
	invoke MessageBox, NULL, addr $WaitStr, addr $WaitStr, MB_OK
	ret
Entry endp
end Entry