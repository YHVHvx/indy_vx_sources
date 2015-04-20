; Морфинг сисколов(Int0x2e/Sysenter).
;
; (c) Indy, 2012.
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
UENV struct
SysGate	PVOID ?
FastGate	PVOID ?
UENV ends
PUENV typedef ptr UENV

KENV struct
ZwSysGate	PVOID ?
KiSysGate	PVOID ?
; ?
KENV ends
PKENV typedef ptr KENV

EOL	equ NULL

; +
; Определение мода(CF/ZF ~ K-mode).
; 
; 1.
;	push cs
;	test dword ptr [esp],MODE_MASK
;	pop ecx
; 2.
;	mov cx,KGDT_R0_DATA
;	verr cx
;
%CPLCF0 macro
	bt esp,31
endm	

	include Img.asm
	
U_SYSGATE_HASH		equ 074C34F63H	; HASH("KiIntSystemCall")
U_FASTGATE_HASH	equ 016C40A62H	; HASH("KiFastSystemCall")
K_SYSGATE_HASH		equ 0438AFBAFH	; HASH("ZwYieldExecution")

ENV_OFFSET	equ (X86_PAGE_SIZE - 4)

; defin ks386.inc
TePeb	equ 30H	; TEB.Peb
PcSelfPcr	equ 1CH
PcIdt	equ 38H

 OPT_SYSGATE_FAST_SEARCH	equ TRUE

; OPT_SYSGATE_FAST_SEARCH - разрешает GtFastSearchGate().
; OPT_SYSGATE_IDT - разрешает извлечение шлюза из IDT.
; OPT_SYSGATE_IDT_PCR - разрешает извлечение ссылки на IDT из PCR.

; +
; Системный шлюз(Int 0x2E).
;
; o Аргументы:
;   Eax: ID, Edx: @Arg's
;
; o Сохраняется EFLAGS.
;
xGtSysGate:
	%GET_CURRENT_GRAPH_ENTRY
GtSysGate proc C
	pushfd
	push eax
	push edx
	Call GtEnvPtr
	test eax,eax
	pop edx
	pop ecx
	jz Error
Gate:
	xchg eax,ecx
	%CPLCF0
	.if Carry?
	; * Смещение поля определяет модель вызова вектора.
		.if KENV.ZwSysGate[ecx]
			popfd
			Call KENV.ZwSysGate[ecx]
			ret
		.else
			cmp KENV.KiSysGate[ecx],NULL
			je Error
			push KGDT_R0_CODE
			Call KENV.KiSysGate[ecx]	; KiSystemService()
			ret
		.endif
	.endif
	popfd
   	Call UENV.SysGate[ecx]
   	ret
Error:
	mov eax,STATUS_INTERNAL_ERROR
	mov edx,esp
	popfd
	ret
GtSysGate endp

; +
; Системный шлюз(Sysenter).
;
; o Аргументы:
;   Eax: ID, Edx: @Arg's
;
; o Сохраняется EFLAGS.
;
xGtFastGate:
	%GET_CURRENT_GRAPH_ENTRY
GtFastGate proc C
	pushfd
	push eax
	push edx
	Call GtEnvPtr
	test eax,eax
	pop edx
	pop ecx
	jz Error
Gate:
	xchg eax,ecx
	popfd
   	Jmp UENV.FastGate[ecx]	; Возврат на KiFastSystemCallRet().
Error:
	mov eax,STATUS_INTERNAL_ERROR
	popfd
	lea edx,dword ptr [edx + 2*4]
	ret
GtFastGate endp

; +
; Инициализация среды.
;	
GtEnvPtr proc C
	%CPLCF0	; CF, ~ZF
; В U-mode реда хранится в PEB, для ядра во всех PCR.
	mov edx,1
	.if Carry?
		mov ecx,dword ptr fs:[PcSelfPcr]
	.else
		mov ecx,dword ptr fs:[TePeb]
	.endif
@@:
; Инициализация выполняется однократно, только на одном камне одним тредом. В ядре возможна 
; реинициализация, так как ссылка на среду размещается в текущем PCR. Для атомарного доступа 
; необходимо использовать IPI.
	xor eax,eax
	lock cmpxchg dword ptr [ecx + ENV_OFFSET],edx
	je @f
	cmp eax,1
	je @b	; Ожидаем окончание инициализации среды в спинлоке.
	ret
@@:
	push ebx	; NT
	push esi	; PENV
	push edi
	%CPLCF0
	mov esi,ecx
	jc Kmode
Umode:
	invoke LdrGetNtImageBaseU
	test eax,eax
	mov ebx,eax	; NT base.
	jz Error
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
		mov ecx,ebx
		mov edi,ebx
		cld	
		mov eax,340FD48BH	; mov edx,esp/sysenter
		add ecx,IMAGE_DOS_HEADER.e_lfanew[ebx]
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
	else
		push EOL
		push U_SYSGATE_HASH
		push U_FASTGATE_HASH
		push esp
		push ebx
		Call LdrEncodeEntriesList
		test eax,eax
		pop ecx	; @KiFastSystemCallRet()
		pop eax	; @KiIntSystemCall()
		pop edx
		jnz Error
		add eax,4
		add ecx,2
	endif
	push eax	; @KiIntSystemCall + 4
	push ecx	; @KiFastSystemCall + 2
	push EOL
	push 24741E13H	; HASH("ZwAllocateVirtualMemory")
	push esp
	push ebx
	Call LdrEncodeEntriesList
	test eax,eax
	pop eax	; @ZwAllocateVirtualMemory()
	pop edx
	pop edi
	pop ebx
	jnz Error
	push sizeof(UENV)	; Size
	mov ecx,esp
	push 0	; Base
	mov edx,esp
	push PAGE_READWRITE
	push MEM_COMMIT
	push ecx
	push 0
	push edx
	push NtCurrentProcess
	Call Eax
	test eax,eax
	pop eax
	pop edx
	jnz Error
	mov UENV.SysGate[eax],ebx
	mov UENV.FastGate[eax],edi
	mov dword ptr [esi + ENV_OFFSET],eax
	jmp Unlock
Kmode:
	invoke LdrGetNtImageBaseK
	test eax,eax
	mov ebx,eax
	jz Error
	push EOL
	push 0F56E599BH	; HASH("ExAllocatePool")
	push esp
	push ebx
	Call LdrEncodeEntriesList
	test eax,eax
	pop edi	; @ExAllocatePool()
	pop edx
	jnz Error
	push eax
	invoke LdrQueryKiAbiosGdt, Ebx, Esp
	test eax,eax
	pop esi	; @KiAbiosGdt
	jnz Error
	ifdef OPT_SYSGATE_IDT
		ifdef OPT_SYSGATE_IDT_PCR
			mov ecx,dword ptr fs:[PcIdt]
		else
			sub esp,2*4
			sidt qword ptr [esp]
			mov ecx,dword ptr [esp + 2]	; IDT Base
			add esp,2*4
		endif
		movzx edx,word ptr [ecx + 2EH*8 + 6]	; KiSystemService(), Hi
		shl edx,16
		mov dx,word ptr [ecx + 2EH*8]	; Lo
		push KENV.KiSysGate
	else
		push EOL
		push K_SYSGATE_HASH
		push esp
		push ebx
		Call LdrEncodeEntriesList
		test eax,eax
		pop edx	; @ZwYieldExecution()
		pop eax
		jnz Error
		mov ecx,12
		.repeat
			cmp dword ptr [edx],0E8086A9CH	; pushfd/push KGDT_R0_CODE/Call KiSystemService
			je @f
			inc edx
			dec ecx
		.until !Ecx
		jmp Error
	@@:
		push KENV.ZwSysGate
	endif
	push edx
	push sizeof(KENV)	; Size
	push NonPagedPool
	Call Edi
	test eax,eax
	pop edx	; @Gate
	pop ecx	; @KENV.X
	jz Error
	mov dword ptr [eax + ecx],edx
	push eax
	invoke LdrLoadVariableInPcrs, Esi, 0, Eax, ENV_OFFSET
	test eax,eax
	pop eax
	jnz Error	; Память не освобождаем, ошибка маловероятна.
Unlock:
	pop edi
	pop esi
	pop ebx
	ret
Error:
	xor eax,eax
	jmp Unlock
GtEnvPtr endp

OP_INT		equ 0CDH
OP_2T		equ 0FH
OP_SYSENTER	equ 34H

; +
; 
; o GCBE_PARSE_SEPARATE, линейный граф.
;
; В парсер передаём ссылку на предыдущую часть графа, тогда не будет повторного включения глобальных процедур в граф.
;
MIP_SYSCALL proc uses ebx esi edi GpBase:PVOID, GpLimit:PVOID
Local StubIp:PVOID
	mov esi,GpLimit
	mov ebx,GpBase
	mov edi,dword ptr [esi]
	mov StubIp,NULL
	.repeat
		mov eax,dword ptr [ebx + EhEntryType]
		and eax,TYPE_MASK
		jz Line
	Next:
		add ebx,ENTRY_HEADER_SIZE
	.until Ebx >= Edi
	xor eax,eax
Exit:
	ret
Line:
	invoke QueryPrefixLength, dword ptr [ebx + EhAddress]
	cmp al,MAX_INSTRUCTION_SIZE - 2
	ja Next
	add eax,dword ptr [ebx + EhAddress]
	xor ecx,ecx
	cmp byte ptr [eax],OP_INT
	je Is2e
	cmp byte ptr [eax],OP_2T
	jne Next
	cmp byte ptr [eax + 1],OP_SYSENTER
	jne Next
	%GET_GRAPH_ENTRY xGtFastGate
	jmp Gate	
Is2e:
	cmp byte ptr [eax + 1],2EH
	jne Next
	%GET_GRAPH_ENTRY xGtSysGate
Gate:
; При обнаружении прерыванья первый раз, описываем графом менеджер сисколов.
	.if StubIp == Ecx
		push ecx
		mov StubIp,eax
		push ecx
		push ecx
		push ecx
		push ecx
		push GCBE_PARSE_NL_UNLIMITED
		push GCBE_PARSE_SEPARATE or GCBE_PARSE_IPCOUNTING
		push GpBase
		push GpLimit
		push eax
		Call GpKit
		test eax,eax
		jnz Exit
	.endif
; Интегрируем менеджер через процедурное ветвление. Конструктор не использует Ip.
	mov ecx,StubIp
	lea edx,[edi + DISCLOSURE_CALL_FLAG]
	or dword ptr [ebx + EhEntryType],HEADER_TYPE_CALL
	mov dword ptr [ebx + EhBranchAddress],ecx
	mov dword ptr [ebx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	mov dword ptr [ebx + EhBranchLink],edx
	or dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jmp Next
MIP_SYSCALL endp