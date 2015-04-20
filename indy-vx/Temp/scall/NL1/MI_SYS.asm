; Морф системнозависимых инструкций:
;
; - INT
; - SYSENTER
; - RDTSC
;
; (c) Indy, 2012.
;
; Морфинг сисколов(Int0x2e/Sysenter).
;
; Формат стабов меняется в версиях, посему можно поступить следующим образом:
; 1. Генерируем шлюз в буфер, для генерации необходима аллокация RWE памяти. Для такой аллокации необходим доступ к апи, 
;    что требует включения процедур парсинга экспорта. Так как генерируемый в буфер код не морфится, то при эмуляции шлюз 
;    может служить сигнатурой. Эмулятор должен быть остановлен до генерации стаба. Сгенерированный стаб может быть обнаружен 
;   сигнатурно при сканировании памяти, что требует добавления мусора в стаб.
; 2. Находим KiIntSystemCall()/KiFastSystemCall в юзермоде, для ядра поиск данной процедуры не приемлим, ибо в старших 
;    версиях поиск проекции нтдлл отображённой на ядро является проблемным. Вызов шлюза через ссылку в USD не годится - 
;    смещение станет причиной детекта и в старших версиях системы эта ссылка отсутствует.
; 3. Используем один из системных стабов, немного изменив его. В ядре стабы являются заглушками для KiSystemService(), 
;    которая является шлюзом 0x2e прерывания. Из ядра получить шлюз можно без анализа экспорта, прочитав смещение из IDT.
; o Модель вызова фасткола отлична от шлюза прерывания. Из ядра фасткол не доступен.
; o Необходима глобальная среда для хранения ссылки на сформированный шлюз. В качестве ссылки на среду используем конец 
;   сегмента Fs. Память под среду аллоцируем при первом обращении к среде.
; o Фасткол может быть отключен(!SYSENTER_CS_MSR) - тогда генерится #GP, либо не поддерживаться - #UD.
; -
; Поступим следующим образом:
; 1. Включаем процедуры анализа экспорта(пе-парсер). Вызываем парсер не через среду, а непосредственно из отморфленного кода.
; 2. Если ссылка на среду обнулена, то вызываем парсер, находим процедуры аллокации памяти, выделяем буфер под среду и загружаем 
; ссылку на него в сегмент Fs.
; 3. Не используем интеграцию графа, а сохраняем ссылку на шлюз в среде(отсутствуют аргументы этого сервиса). Вызов шлюза требует 
;    поправку ссылки на стек(rEdx). Шлюз выбираем в зависимости от мода. Мод необходимо указать морферу. Стандартный вызов:
;   	push Args
;   	...
;   	mov eax,ID
;   	mov edx,esp	; @Arg's
;   	Int 0x2e
;   	add esp,4 * Arg's
; 
; Отморфленный:
;   	push Args
;   	...
;   	mov eax,ID
;   	mov edx,esp	; @Arg's
;    -
;   	Call SysGate
;    -
;    add esp,4 * Args
; o Шлюз K-mode:
; ZwYieldExecution:
;   	mov eax,ID
;   	lea edx,[esp + 4]	; - Ip
; Gate:
;   	pushfd	; IRET-фрейм.
;   	push KGDT_R0_CODE
;   	call KiSystemService
;   	ret
; o Шлюз U-mode:
; KiIntSystemCall:
;   	lea edx,dword ptr ss:[esp + 2*4]	; - 2Ip
; Gate:
;   	Int 0x2E
;   	ret
;
.code
ifdef OPT_ENABLE_DBG_LOG
	$GtInitU_CALLED	CHAR "GtInitU ( PENV = 0x%X", CRLF
	$GtInitU_RETURNED	CHAR "GtInitU ) 0x%X", CRLF
	$GtInitU_LdrGetNtImageBaseU	CHAR "GtInitU.LdrGetNtImageBaseU: 0x%X", CRLF
	$GtInitU_OPT_SYSGATE_FAST_SEARCH	CHAR "GtInitU.OPT_SYSGATE_FAST_SEARCH: 0x%X", CRLF
	$GtInitU_LdrEncodeEntriesList	CHAR "GtInitU.LdrEncodeEntriesList(Ki*): 0x%X", CRLF
endif

; OPT_SYSGATE_FAST_SEARCH

; +
; IN ESI: PUENV
;
GtInitU proc C
	%DBG $GtInitU_CALLED, Ebx
	push edx
	push esi
	push ebx
	push edi
	assume ebx:PUENV
	invoke LdrGetNtImageBaseU
	%DBG $GtInitU_LdrGetNtImageBaseU, Eax
	test eax,eax
	jz Error
	mov esi,eax	; NT base.
	ifdef OPT_SYSGATE_FAST_SEARCH
		; o @KiIntSystemCall() = 16 + @KiFastSystemCall(),
		;   (оба шлюза выравнены на границу 16-и байт).
		; Align 16
		; KiFastSystemCall:
		; 	8BD4		mov edx,esp
		; 	0F34		sysenter
		; 	...
		; KiFastSystemCallRet:
		; 	C3		ret
		; 	...
		; Align 16
		; KiIntSystemCall:
		; 	8D5424 08	lea edx,dword ptr ss:[esp + 8]
		; 	CD 2E		int 2E
		; 	C3		ret
		mov ecx,esi
		mov edi,esi
		cld	
		mov eax,340FD48BH	; mov edx,esp/sysenter
		add ecx,IMAGE_DOS_HEADER.e_lfanew[esi]
		assume ecx:PIMAGE_NT_HEADERS
		add edi,[ecx].OptionalHeader.BaseOfCode
		mov ecx,[ecx].OptionalHeader.SizeOfCode
		shr ecx,2
@@:
		repne scasd
		jne Error
		cmp byte ptr [edi - 4 + 16 + 5],2EH
		jne @b
		lea eax,[edi - 4 + 16 + 4]
		lea ecx,[edi - 4 + 2]
		%DBG $GtInitU_OPT_SYSGATE_FAST_SEARCH, Eax
	else
		push EOL
		push 074C34F63H	; HASH("KiIntSystemCall")
		push 016C40A62H	; HASH("KiFastSystemCall")
		push esp
		push esi
		Call LdrEncodeEntriesList
		%DBG $GtInitU_LdrEncodeEntriesList, Eax
		test eax,eax
		pop ecx	; @KiFastSystemCallRet()
		pop eax	; @KiIntSystemCall()
		pop edx
		jnz Error
		add eax,4
		add ecx,2
	endif
Unlock:
	mov [ebx].SysGate,eax
	mov [ebx].FastGate,ecx
Exit:
	pop edi
	pop ebx
	pop esi
	pop edx
	%DBG $GtInitU_RETURNED, Eax
	ret
Error:
	xor eax,eax
	xor ecx,ecx
	jmp Unlock
GtInitU endp

ifdef OPT_ENABLE_DBG_LOG
	$MI_SYSENTER_CALLED		CHAR "MI_SYSENTER ( rEax = 0x%X", CRLF
	$MI_SYSENTER_RETURNED	CHAR "MI_SYSENTER ) 0x%X", CRLF
	$MI_SYSENTER_GATE		CHAR "MI_SYSENTER ..)", CRLF
	$MI_SYSENTER_GETENVPTR	CHAR "MI_SYSENTER.GETENVPTR: 0x%X", CRLF
endif

; +
; Системный шлюз(Sysenter).
;
; o Аргументы:
;   Eax: ID, Edx: @Arg's
;
; o Сохраняется EFLAGS.
; o Мод не проверяется, только U.
;
xMI_SYSENTER:
	%GET_CURRENT_GRAPH_ENTRY
MI_SYSENTER proc C
	%DBG $MI_SYSENTER_CALLED, Eax
	pushfd
	push eax
	push ebx
	%GETENVPTR
	%DBG $MI_SYSENTER_GETENVPTR, Eax
	jz Error
	mov ebx,eax
	%CPLCF0
	jc Error
	assume ebx:PUENV
	%SPINLOCK [ebx].LockGate, Init, Error
CallGate:
	mov ecx,[ebx].FastGate
	pop ebx
	pop eax
	popfd
	%DBG $MI_SYSENTER_GATE
   	jmp Ecx	; Возврат на KiFastSystemCallRet().
Init:
	Call GtInitU
	test eax,ecx
	.if !Zero?
		%UNLOCK [ebx].LockGate,LOCK_INIT
		jmp CallGate
	.endif
	%UNLOCK [ebx].LockGate,LOCK_FAIL
Error:
	pop ebx
	pop ecx
	mov eax,STATUS_INTERNAL_ERROR
	popfd
	%DBG $MI_SYSENTER_RETURNED, Eax
	ret
MI_SYSENTER endp

ifdef OPT_ENABLE_DBG_LOG
	$MI_INT2E_CALLED		CHAR "MI_INT2E ( rEax = 0x%X", CRLF
	$MI_INT2E_RETURNED		CHAR "MI_INT2E ) 0x%X", CRLF
	$MI_INT2E_GETENVPTR		CHAR "MI_INT2E.GETENVPTR: 0x%X", CRLF
endif

; +
; Системный шлюз(Int 0x2E).
;
; o Аргументы:
;   Eax: ID, Edx: @Arg's
;
; o Сохраняется EFLAGS.
;
xMI_INT2E:
	%GET_CURRENT_GRAPH_ENTRY
MI_INT2E proc C
	%DBG $MI_INT2E_CALLED, Eax
	pushfd
	push eax
	push ebx
	%GETENVPTR
	%DBG $MI_INT2E_GETENVPTR, Eax
	jz Error
	mov ebx,eax
	%CPLCF0
	jc Kmode
	assume ebx:PUENV
	%SPINLOCK [ebx].LockGate, InitU, Error
CallGateU:
	mov ecx,UENV.SysGate[ebx]
	pop ebx
	pop eax
	popfd
	Call Ecx
	%DBG $MI_INT2E_RETURNED, Eax
	ret
InitU:
	Call GtInitU
	test eax,ecx
	.if !Zero?
		%UNLOCK [ebx].LockGate,LOCK_INIT
		jmp CallGateU
	.endif
	%UNLOCK [ebx].LockGate,LOCK_FAIL
Error:
	pop esi
	pop ecx
	mov eax,STATUS_INTERNAL_ERROR
	popfd
	%DBG $MI_INT2E_RETURNED, Eax
	ret
Kmode:
	assume ebx:PKENV
	%LOCKREAD [ebx].LockGate, InitK, ErrorK
CallGateK:
	mov ecx,[ebx].SysGate
	pop ebx
	pop eax
	push cs	; KGDT_R0_CODE
	Call Ecx	; KiSystemService()
	ret
InitK:
	ifdef OPT_SYSGATE_IDT
		ifdef OPT_SYSGATE_IDT_PCR
			mov eax,dword ptr fs:[PcIdt]
		else
			%IDT Eax
		endif
		movzx ecx,word ptr [eax + 2EH*8 + 6]	; KiSystemService(), Hi
		shl ecx,16
		mov cx,word ptr [eax + 2EH*8]	; Lo
	else
		push edx
		push EOL
		push 0438AFBAFH	; HASH("ZwYieldExecution")
		push esp
		push [ebx].NtBase
		Call LdrEncodeEntriesList
		test eax,eax
		pop ecx	; @ZwYieldExecution()
		pop eax
		pop edx
		jnz ErrorK
		mov eax,12
		.repeat
			cmp dword ptr [ecx],0E8086A9CH	; pushfd/push KGDT_R0_CODE/Call KiSystemService
			je @f
			inc ecx
			dec eax
		.until Zero?
		jmp ErrorK
	@@:
		add ecx,dword ptr [ecx + 4]
		add ecx,6 + 4	; @KiSystemService()
	endif
	mov [ebx].SysGate,ecx
	%UNLOCK [ebx].LockGate,LOCK_INIT
	jmp CallGateK
ErrorK:
	mov [ebx].SysGate,NULL
	%UNLOCK [ebx].LockGate,LOCK_FAIL
	jmp Error
MI_INT2E endp

ifdef OPT_ENABLE_DBG_LOG
	$MI_INT2A_CALLED	CHAR "MI_INT2A (", CRLF
	$MI_INT2A_RETURNED	CHAR "MI_INT2A ) rEax = 0x%X, rEdx = 0x%X", CRLF
	$MI_INT2A_GETENVPTR	CHAR "MI_INT2A.GETENVPTR: 0x%X", CRLF
	$MI_INT2A_SystemTimeOfDayInformation	CHAR "MI_INT2A.SystemTimeOfDayInformation: 0x%X", CRLF
	$MI_INT2A_LdrEncodeEntriesList_ZwQuerySystemInformation	CHAR "MI_INT2A.LdrEncodeEntriesList(ZwQuerySystemInformation): 0x%X", CRLF
	$MI_INT2A_ZwSetLdtEntries	CHAR "MI_INT2A.ZwSetLdtEntries: 0x%X", CRLF
	$MI_INT2A_LdrEncodeEntriesList_ZwSetLdtEntries	CHAR "MI_INT2A.LdrEncodeEntriesList(ZwSetLdtEntries): 0x%X", CRLF
	$MI_INT2A_GpKit	CHAR "MI_INT2A.GpKit: 0x%X", CRLF
	$MI_INT2A_SEG		CHAR "MI_INT2A.SEG(Cs): 0x%X", CRLF
	$MI_INT2A_XCPT_CALLED	CHAR "MI_INT2A.XCPT", CRLF
	$MI_INT2A_XCPT_LOCKED	CHAR "MI_INT2A.XCPT_LOCKED", CRLF
endif

; +
; Хэндлер Int 0x2A.
;
xMI_INT2A:
	%GET_CURRENT_GRAPH_ENTRY
MI_INT2A proc C
	%DBG $MI_INT2A_CALLED
	pushfd	; +0
	push ecx	; +4
	push ebx	; +8
	%GETENVPTR
	%DBG $MI_INT2A_GETENVPTR, Eax
	jz Exit
	mov ebx,eax
	%CPLCF0
	jc Kmode
	assume ebx:PUENV
	push cs
	add dword ptr [ebx].Tick,64
	pop eax
	adc dword ptr [ebx].Tick + 4,0
	cmp ax,KGDT_R3_CODE or RPL_MASK
	je KiTick
	%DBG $MI_INT2A_SEG, Eax
	test byte ptr byte ptr [esp + 2*4 + 2],EFLAGS_V86_MASK/10000H
	jnz XcptGp	; #GP
	cmp eax,ebp
	jne XcptGp
	sub eax,0F0F0F0F0H
	jz KiTick
	dec eax
	jz KiLdt
XcptGp:
	%DBG $MI_INT2A_XCPT_CALLED
	%SPINLOCK [ebx].LpRtlRaiseStatus, InitRtl, ErrorU
	%DBG $MI_INT2A_XCPT_LOCKED
Raise:
	mov eax,[ebx].pRtlRaiseStatus
; Вызов не скрываем(%APICALL), выполняем безусловное ветвление на стаб.
	pop ebx
	pop ecx
	popfd
	pop edx	; Ip
	push STATUS_ACCESS_VIOLATION	; #GP
	push edx
	Jmp Eax	; RtlRaiseStatus(STATUS_ACCESS_VIOLATION)
InitRtl:
	push EOL
	push 0D70DB44DH	; HASH("RtlRaiseStatus")
	invoke LdrEncodeEntriesList, NULL, Esp
	test eax,eax
	pop [ebx].pRtlRaiseStatus
	pop ecx
	.if Zero?
		%UNLOCK [ebx].LpRtlRaiseStatus,LOCK_INIT
		jmp Raise
	.endif
	%UNLOCK [ebx].LpRtlRaiseStatus,LOCK_FAIL
	jmp ErrorU
KiTick:
	%SPINLOCK [ebx].LpZwQuerySystemInformation, InitU, ErrorU
Time:
	sub esp,sizeof(SYSTEM_TIME_OF_DAY_INFORMATION)
	mov ecx,esp
	push NULL
	push sizeof(SYSTEM_TIME_OF_DAY_INFORMATION)
	push ecx
	push SystemTimeOfDayInformation
	%APICALL [ebx].pZwQuerySystemInformation, 4
	%DBG $MI_INT2A_SystemTimeOfDayInformation, Eax
	test eax,eax
	.if Zero?
		mov eax,dword ptr SYSTEM_TIME_OF_DAY_INFORMATION.CurrentTime[esp]
		mov edx,dword ptr SYSTEM_TIME_OF_DAY_INFORMATION.CurrentTime[esp] + 4
	.else
		mov eax,dword ptr [ebx].Tick
		mov edx,dword ptr [ebx].Tick + 4
	.endif
	add esp,sizeof(SYSTEM_TIME_OF_DAY_INFORMATION)
Exit:
	pop ebx
	pop ecx
	popfd
	%DBG $MI_INT2A_RETURNED, Edx, Eax
	ret
InitU:
	push EOL
	push 7085AB5AH	; HASH("ZwQuerySystemInformation")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG $MI_INT2A_LdrEncodeEntriesList_ZwQuerySystemInformation, Eax
	test eax,eax
	pop [ebx].pZwQuerySystemInformation
	pop ecx
	.if Zero?
		%UNLOCK [ebx].LpZwQuerySystemInformation,LOCK_INIT
		jmp Time
	.endif
	%UNLOCK [ebx].LpZwQuerySystemInformation,LOCK_FAIL
ErrorU:
	mov eax,dword ptr [ebx].Tick
	mov edx,dword ptr [ebx].Tick + 4
	jmp Exit
KiLdt:
	%SPINLOCK [ebx].LpZwSetLdtEntries, InitLdt, ErrorU
Ldt:
	push NULL
	push NULL
	push NULL
	push edx
	push dword ptr [esp + 5*4]	; Ecx
	push dword ptr [esp + 5*4]	; Ebx
	%APICALL [ebx].pZwSetLdtEntries, 6	; ZwSetLdtEntries
	%DBG $MI_INT2A_ZwSetLdtEntries, Eax
	test eax,eax
	btr dword ptr [esp + 2*4],1	; !EFLAGS_CF
	.if Zero?
		bts dword ptr [esp + 2*4],1
	.endif
	jmp Exit
InitLdt:
	push EOL
	push 0AB2E5566H	; HASH("ZwSetLdtEntries")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG $MI_INT2A_LdrEncodeEntriesList_ZwSetLdtEntries, Eax
	test eax,eax
	pop [ebx].pZwSetLdtEntries
	pop ecx
	.if Zero?
		%UNLOCK [ebx].LpZwSetLdtEntries,LOCK_INIT
		jmp Ldt
	.endif
	%UNLOCK [ebx].LpZwSetLdtEntries,LOCK_FAIL
	mov eax,STATUS_INTERNAL_ERROR
	jmp Exit
Kmode:
; В среде не храним ссылку, получаем её динамически.
	%IDT Eax
	movzx ecx,word ptr [eax + 2EH*8 + 6]	; KiGetTickCount(), Hi
	shl ecx,16
	mov cx,word ptr [eax + 2EH*8]	; Lo
	pop ebx
	pop edx
	popfd
	pop eax	; Ip
	pushfd
	push cs
	push eax
	Jmp Ecx	; KiGetTickCount()
MI_INT2A endp

ifdef OPT_ENABLE_DBG_LOG
	$MI_RDTSC_CALLED	CHAR "MI_RDTSC (", CRLF
	$MI_RDTSC_RETURNED	CHAR "MI_RDTSC ) 0x%X", CRLF
	$MI_RDTSC_GETENVPTR	CHAR "MI_RDTSC.GETENVPTR: 0x%X", CRLF
	$MI_RDTSC_APICALL_ZwQueryPerformanceCounter	CHAR "MI_RDTSC.APICALL(ZwQueryPerformanceCounter): 0x%X", CRLF
	$MI_RDTSC_LdrEncodeEntriesList_ZwQueryPerformanceCounter	CHAR "MI_RDTSC.LdrEncodeEntriesList(ZwQueryPerformanceCounter): 0x%X", CRLF
	$MI_RDTSC_GpKit	CHAR "MI_RDTSC.GpKit: 0x%X", CRLF
endif

%TSC macro
	Call MI_RDTSC
endm

; +
; Хэндлер RDTSC.
;
; CR4.TSD не проверяем.
;
xMI_RDTSC:
	%GET_CURRENT_GRAPH_ENTRY
MI_RDTSC proc C
	%DBG $MI_RDTSC_CALLED
	pushfd
	push ecx
	push ebx
	%GETENVPTR
	%DBG $MI_RDTSC_GETENVPTR, Eax
	jz ErrEnv
	mov ebx,eax
	%CPLCF0
	jc Kmode
	assume ebx:PUENV
	add dword ptr [ebx].Tsc,4
	adc dword ptr [ebx].Tsc + 4,0
	%SPINLOCK [ebx].LpZwQueryPerformanceCounter, InitU, ErrorU
Tsc:
	push eax
	push edx
	mov ecx,esp
	push NULL	; Freq.
	push ecx	; Count: PLARGE_INTEGER
	%APICALL [ebx].pZwQueryPerformanceCounter, 2
	%DBG $MI_RDTSC_APICALL_ZwQueryPerformanceCounter, Eax
	pop eax	; Lo
	pop edx	; Hi
	jmp Exit
ExitK:
	pop edi
	pop esi
Exit:
	pop ebx
	pop ecx
	popfd
	%DBG $MI_RDTSC_RETURNED, Eax
	ret
InitU:
	push EOL
	push 0E3F0C117H	; HASH("ZwQueryPerformanceCounter")
	invoke LdrEncodeEntriesList, NULL, Esp
	%DBG $MI_RDTSC_LdrEncodeEntriesList_ZwQueryPerformanceCounter, Eax
	test eax,eax
	pop [ebx].pZwQueryPerformanceCounter	; @ZwQueryPerformanceCounter
	pop ecx
	.if Zero?
		%UNLOCK [ebx].LpZwQueryPerformanceCounter,LOCK_INIT
		jmp Tsc
	.endif
	%UNLOCK [ebx].LpZwQueryPerformanceCounter,LOCK_FAIL
ErrorU:
	mov eax,dword ptr [ebx].Tsc
	mov edx,dword ptr [ebx].Tsc + 4
	jmp Exit
ErrEnv:
	inc eax
	jmp Exit
Kmode:
	push esi
	push edi
	assume ebx:PKENV
	add dword ptr [ebx].Tsc,4
	adc dword ptr [ebx].Tsc + 4,0
	%SPINLOCK [ebx].LpKeQueryPerformanceCounter, InitK, ErrorK 
Read:
	push NULL
	Call [ebx].pKeQueryPerformanceCounter
	jmp Exit
InitK:
	push EOL
	push 0DB164279H	; HASH("RtlFreeUnicodeString")
	push 001FB4AD3H	; HASH("MmGetSystemRoutineAddress")
	push 059B88A67H	; HASH("RtlCreateUnicodeStringFromAsciiz")
	invoke LdrEncodeEntriesList, [ebx].NtBase, Esp
	test eax,eax
	pop ecx	; @RtlCreateUnicodeStringFromAsciiz()
	pop esi	; @MmGetSystemRoutineAddress()
	pop edi	; @RtlFreeUnicodeString()
	jnz ErrK1
	sub esp,sizeof(UNICODE_STRING)
	mov eax,esp
	push dword ptr "r"
	push "etnu"
	push "oCec"
	push "namr"
	push "ofre"
	push "Pyre"
	push "uQeK"
	push esp
	push eax
	Call Ecx	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea esp,[esp + 7*4]
	jz ErrK2
	push esp
	Call Esi	; MmGetSystemRoutineAddress()
	lea ecx,[esp + 2*4]
	mov [ebx].pKeQueryPerformanceCounter,eax
	push ecx
	Call Edi	; RtlFreeUnicodeString()
	push NULL
	Call Esi
	cmp [ebx].pKeQueryPerformanceCounter,NULL
	je ErrK2
	add esp,sizeof(UNICODE_STRING) + 4
	%UNLOCK [ebx].LpKeQueryPerformanceCounter,LOCK_INIT
	jmp Read
ErrK2:
	add esp,sizeof(UNICODE_STRING)
ErrK1:
	pop ecx	; EOL
	%UNLOCK [ebx].LpKeQueryPerformanceCounter,LOCK_FAIL
ErrorK:
	mov eax,dword ptr [ebx].Tsc
	mov edx,dword ptr [ebx].Tsc + 4
	jmp ExitK
MI_RDTSC endp