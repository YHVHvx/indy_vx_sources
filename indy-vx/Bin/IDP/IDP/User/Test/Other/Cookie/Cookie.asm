; Поиск переменных SecurityCookieInitialized и SecurityCookieInitCount.
; Механизм поиска:
; - Обнуляем селектор сегмента данных.
; - Вызываем LdrInitializeThunk().
; - Обрабатываем исключение(SEH) при доступе к SecurityCookieInitialized.
; - Обрабатываем исключение(SEH) при доступе к SecurityCookieInitCount.
; - Восстанавливаем контекст текущего потока.
;
; \IDP\Public\User\Test\Other\Cookie\Cookie.asm
;
; +	
; o Для kernel32.dll куки могут быть найдены из хидера(см. LdrpFetchAddressOfSecurityCookie()).
;
;QueryCookieReference proc C
;	assume fs:nothing
;	mov eax,fs:[TEB.Peb]
;	mov eax,PEB.Ldr[eax]
;	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
;	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
;	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
;	mov eax,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; kernel32.dll
;	mov ecx,IMAGE_DOS_HEADER.e_lfanew[eax]
;	add eax,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG*sizeof(IMAGE_DATA_DIRECTORY) + eax + ecx]	; _load_config_used
;	mov eax,IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie[eax]
;	ret
;QueryCookieReference endp
 
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

.code
	jmp QueryCookieEnvironment
	
DISP_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call DISP_GetReference
	push eax
	assume fs:nothing
	push dword ptr fs:[TEB.Tib.ExceptionList]
	mov dword ptr fs:[TEB.Tib.ExceptionList],esp
	jmp ecx
DISP_Prolog endp

COOKIE_ENVIRONMENT struct
_SecurityCookieInitialized	PVOID ?
_SecurityCookieInitCount		PVOID ?
COOKIE_ENVIRONMENT ends
PCOOKIE_ENVIRONMENT typedef ptr COOKIE_ENVIRONMENT

TbCookieEnvironment	equ (PAGE_SIZE - sizeof(COOKIE_ENVIRONMENT))

SEH_FRAME struct
NextFrame		PVOID ?
Handler		PVOID ?
SafeEip		PVOID ?
rEbp			PVOID ?
SEH_FRAME ends
PSEH_FRAME typedef ptr SEH_FRAME

	include ..\..\..\Bin\Graph\Mm\Img.asm
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DISP_GetReference::
	GET_CURRENT_GRAPH_ENTRY
; Normal SEH.
$SEH proc uses ebx ExceptionRecord:PEXCEPTION_RECORD, EstablisherFrame:PSEH_FRAME, Context:PCONTEXT, DispatcherContext:PVOID
; o Трассировочное исключение в диспетчере должно быть обработано сторонним кодом(для закрытия бага).
	assume fs:nothing
	mov ecx,ExceptionRecord
	assume ecx:PEXCEPTION_RECORD
	mov edx,Context
	assume edx:PCONTEXT
	mov ebx,EstablisherFrame
	assume ebx:PSEH_FRAME
	cmp [ecx].ExceptionCode,STATUS_ACCESS_VIOLATION
	mov eax,[edx].regEip
	jne is_trap_
	cmp word ptr [eax],3D80H	; cmp byte ptr ds:[SecurityCookieInitialized],0
	je env_init_
	cmp dword ptr [eax],08C10FF0H	; lock xadd dword ptr ds:[eax],ecx
	jne chain_
	push [edx].regEax
	pop fs:[TbCookieEnvironment + COOKIE_ENVIRONMENT._SecurityCookieInitCount]
return_:
	push [ebx].NextFrame
	push [ebx].SafeEip
	push [ebx].rEbp
	mov [edx].regSegDs,KGDT_R3_DATA or RPL_MASK
	pop [edx].regEbp
	pop [edx].regEip
	pop [edx].regEsp
continue_:
	xor eax,eax
exit_:
	ret
env_init_:
	cmp byte ptr [eax + 6],0
	jne chain_
	push dword ptr [eax + 2]
	or [edx].regEFlags,EFLAGS_TF
	mov [edx].regSegDs,KGDT_R3_DATA or RPL_MASK
	pop fs:[TbCookieEnvironment + COOKIE_ENVIRONMENT._SecurityCookieInitialized]
	jmp continue_
is_trap_:
	cmp [ecx].ExceptionCode,STATUS_SINGLE_STEP
	jne chain_
	btr [edx].regEFlags,8	; TF
	mov [edx].regSegDs,0	; Ds
	bts [edx].regEFlags,6	; ZF
	jmp continue_
chain_:
	xor eax,eax
	mov [edx].regSegDs,KGDT_R3_DATA or RPL_MASK
	dec eax
	jmp exit_
$SEH endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
QueryCookieEnvironment proc uses ebx CookieEnvironment:PCOOKIE_ENVIRONMENT
Local CrcList[2]:DWORD
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor eax,eax
	lea ecx,CrcList
	mov dword ptr [CrcList],0FCEA01E0H	; Crc32(LdrInitializeThunk)
	mov dword ptr [CrcList + 4],eax
	push ecx
	mov fs:[TbCookieEnvironment + COOKIE_ENVIRONMENT._SecurityCookieInitialized],eax
	push ecx
	mov fs:[TbCookieEnvironment + COOKIE_ENVIRONMENT._SecurityCookieInitCount],eax
	push eax
	push eax
	Call NtEncodeEntriesList
	test eax,eax
	jnz exit_
	Call DISP_Epilog_Reference
	Call DISP_Prolog
	push 0
	push 0
	push 0
	push 0
	push 0
	pop ds
	jmp dword ptr [CrcList]
DISP_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
	mov ecx,fs:[TbCookieEnvironment + COOKIE_ENVIRONMENT._SecurityCookieInitialized]
	mov edx,fs:[TbCookieEnvironment + COOKIE_ENVIRONMENT._SecurityCookieInitCount]
	mov ebx,CookieEnvironment
	assume ebx:PCOOKIE_ENVIRONMENT
	mov eax,STATUS_UNSUCCESSFUL
	.if Ecx && Edx
	mov [ebx]._SecurityCookieInitialized,ecx
	mov [ebx]._SecurityCookieInitCount,edx
	xor eax,eax
	.endif
	jmp exit_
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
exit_:
	Call SEH_Epilog
	ret
QueryCookieEnvironment endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.code
ThreadStartThunk proc UserParameter:PVOID
	invoke Beep, 2000, 140
	invoke RtlExitUserThread, STATUS_SUCCESS
	int 3
ThreadStartThunk endp

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

Entry proc
Local CookieEnvironment:COOKIE_ENVIRONMENT
Local ThreadHandle:HANDLE, ClientId:CLIENT_ID
	invoke RtlCreateUserThread, NtCurrentProcess, NULL, TRUE, 0, 0, 0, addr ThreadStartThunk, 0, addr ThreadHandle, addr ClientId
	BREAKERR
	invoke QueryCookieEnvironment, addr CookieEnvironment
	BREAKERR
	mov esi,CookieEnvironment._SecurityCookieInitialized
	mov edi,CookieEnvironment._SecurityCookieInitCount
	mov byte ptr [esi],al	; Lock cookie.
	mov ebx,dword ptr [edi]	; SecurityCookieInitCount
	invoke ZwResumeThread, ThreadHandle, NULL
	BREAKERR
; Цикл ожидания запуска нового потока.
@@:
	invoke Sleep, 30
	cmp dword ptr [edi],ebx
	je @b
	invoke Sleep, 3000
; Тред покинет цикл ожижания.
	mov byte ptr [esi],1	; Unlock cookie.
	invoke WaitForSingleObject, ThreadHandle, INFINITE
	ret
Entry endp
end Entry
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; o Teory
;
KiUserApcDispatcher:
	lea edi,dword ptr ss:[esp+10]
	pop eax
	call eax	; -> LdrInitializeThunk()
	push 1
	push edi
	call ntdll.ZwContinue

; Первичная апк, ставит в очередь потока ядро.
;
LdrInitializeThunk:
	lea eax,dword ptr ss:[esp+10]
	mov dword ptr ss:[esp+4],eax
	xor ebp,ebp
	jmp ntdll._LdrpInitialize@12

_LdrpInitialize@12:
	mov edi,edi
	push ebp
	mov ebp,esp
	cmp byte ptr ds:[_SecurityCookieInitialized],0	; Для захвата потока обнулить.
	je ntdll.7C92217D
7C91AAB9:
	pop ebp
	jmp ntdll.__LdrpInitialize@12

7C92217D:
	call ntdll._InitSecurityCookie@0
7C922182:
	jmp ntdll.7C91AAB9

InitSecurityCookie@0:
	mov edi,edi
	push ebp
	mov ebp,esp
	push ecx
	push ecx
	xor ecx,ecx
	mov eax,offset ntdll._SecurityCookieInitCount
	inc ecx
	lock xadd dword ptr ds:[eax],ecx
	inc ecx
	cmp ecx,1
	jnz ntdll.7C93F359	; Всегда > 1(декремент не выполняется).
	call ntdll.___security_init_cookie
	mov byte ptr ds:[_SecurityCookieInitialized],1
	leave
	ret

7C93F359:
	or dword ptr ss:[ebp-4],FFFFFFFF
	mov dword ptr ss:[ebp-8],FFFB6C20	; 30 milliseconds.
	jmp short ntdll.7C93F371
; Здесь иной поток может остановить текущий тред, получить 
; из контекста значение регистра Ebp(бактрейс), это указат
; ель на стековый фрейм, который содержит адрес возврата и
; з InitSecurityCookie(), это адрес 0x7C922182. Заменим эт
; от адрес в стековом фрейме на свой, тогда при возврате у
; правление получит наш обработчик перед тем, как будет вы
; полнен переход на LdrpInitialize(). Иначе можно использо
; вать захват Eip в контексте, либо механизм исключений. В
; зведём в контексте текущего треда TF(прежде остановив ег
; о). На следующей инструкции будет сгенерирован пошаговый 
; останов, VEH получит управление в контексте текущего пот
; ока. Захват можно выполнить посредством переодической до
; ставки апк, отличной от первичной, например по таймеру, 
; либо выполняя цикл опроса с задержкой. Определяем создан
; ие потока по инкременту переменной SecurityCookieInitCou
; nt. При этом делаем слепок и определяем вновь созданный 
; поток в нём. Далее открываем его и выполняем необходимые 
; манипуляции.
7C93F366:
	lea eax,dword ptr ss:[ebp-8]
	push eax
	push 0
	call ntdll.ZwDelayExecution
7C93F371:
	cmp byte ptr ds:[_SecurityCookieInitialized],0	; Цикл ожидания инициализации.
	je short ntdll.7C93F366
	leave
	ret