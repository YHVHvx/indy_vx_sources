; o MI, UM
;
; (с) Indy, 2011
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

.code
	jmp GpInitialize
	
	assume fs:nothing
%GET_NT_BASE macro Reg32
	mov Reg32,fs:[TEB.Peb]
	mov Reg32,PEB.Ldr[Reg32]
	mov Reg32,PEB_LDR_DATA.InLoadOrderModuleList.Flink[Reg32]
	mov Reg32,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[Reg32]
	mov Reg32,LDR_DATA_TABLE_ENTRY.DllBase[Reg32]	; ntdll.dll
endm

%GET_CURRENT_GRAPH_ENTRY macro
	Call GetGraphReference
endm

%GET_GRAPH_ENTRY macro PGET_CURRENT_GRAPH_ENTRY
	Call PGET_CURRENT_GRAPH_ENTRY
endm

%GET_GRAPH_REFERENCE macro
GetGraphReference::
	pop eax
	ret
endm

	%GET_GRAPH_REFERENCE

	assume fs:nothing
SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	push ecx
	ret
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 2*4]
	pop ebp
	push ecx
	ret
SEH_Epilog endp

SEH_GetRef proc C
	%GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov ecx,dword ptr [esp + 3*4]	; Ctx.
	mov edx,dword ptr [esp]	; ~ nt!ExecuteHandler2().
	mov ebx,CONTEXT.regEbx[ecx]
	mov esi,CONTEXT.regEsi[ecx]
	mov edi,CONTEXT.regEdi[ecx]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov ecx,EXCEPTION_RECORD.ExceptionAddress[eax]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	push dword ptr [esp + 2*4]
	ret
SEH_GetRef endp

FLG_ENABLE_SEH	equ TRUE

%SEHPROLOG macro EpilogLabel
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog_Reference
		Call SEH_Prolog
	endif
endm

%SEHEPILOG macro ExitLabel
	ifdef FLG_ENABLE_SEH
		jmp Exit
  	SEH_Epilog_Reference:
		%GET_CURRENT_GRAPH_ENTRY
	endif
	ifndef ExitLabel
  Exit:
  	else
  ExitLabel:
  	endif
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog
	endif
endm

LdrGetNtBase proc C
	%GET_NT_BASE Eax
	ret
LdrGetNtBase endp

	include Img.asm
xGCBE:
	%GET_CURRENT_GRAPH_ENTRY
	include Gcbe.inc

; * Стабы динамически генерируются в буфер(пикод). Можно отморфить его с интеграцией, но это излишне. В буфер сохраняется стаб и вех, 
; * последний выполняет стековую маршрутицазию через один из сервисов GCBE. Из за этого движок не может быть выгружен(движок). Можно 
; * сгенерировать в буфер этот код, выполнив ребилд, но это потребует аллокацию 3-х буферов. При необходимости можно генерировать в 
; * буфер, обьединять графы етц. в любых сочетаниях. Текущая сборка движка позволяет это.
;
; * Весь код пермутирующий(микод). Из за этого стабы генерируются динамически в буфер в виде пикода. Ребилд стабов не используется. 
; * Для получения генератора кода(%PSGEN etc.) смотрите макро %PRE/%POSTGENHASH и генерацию таблицы Cx-примитивов из морфера GCBE.
;
; * Размер буферов фиксирован. Это значения принято на основе NT5.1 и увеличено в нессколько раз, NL также фиксирован. Возможно испо
; * льзование расширяемых буферов, но учитывая NX, потребуется эмуляция SEH из VEH. Сервисный вход GCBE поддерживает внешний SEH(опр
; * еделяется флагом в макро %GPCALL). Для использования внутреннего сех потребуется описание тела графом и вызов GP_CHECK_IP_BELONG
; * _TO_SNAPSHOT. Это опять же требует аллокацию буферов, память драгоценна.
;
; * В идеале следует учесть всё выше сказанное. Такой подход позволит избежать сигнатурного детекта, ибо стабы фиксированы.

comment '
VMSTUB struct
ProcessHandle	HANDLE ?
BaseAddress	PVOID ?
InfoClass		ULONG ?
Information	PVOID ?
InfoLength	ULONG ?
ReturnLength	PULONG ?
VMSTUB ends
PVMSTUB typedef ptr VMSTUB

; +
; 
; Стаб для обработки ZwQueryVirtualMemory().
;
;xVM_Stub:
;	%GET_CURRENT_GRAPH_ENTRY
;VM_Stub proc C
;	cmp VMSTUB.ProcessHandle[esp + 4],NtCurrentProcess
;	jne Chain
;	cmp VMSTUB.InfoClass[esp + 4],MEMORY_BASIC_INFORMATION
;	jne Chain
;	cmp InfoLength,sizeof(MEMORY_BASIC_INFORMATION)
;	jne Chain
;	...
;	ret
;VM_Stub endp

PSSTUB struct
ProcessHandle	HANDLE ?
InfoClass		ULONG ?
Information	PVOID ?
InfoLength	ULONG ?
ReturnLength	PULONG ?
PSSTUB ends
PPSSTUB typedef ptr PSSTUB

ProcessExecuteFlags	equ 22H

MEM_EXECUTE_OPTION_DISABLE				equ 1 
MEM_EXECUTE_OPTION_ENABLE				equ 2
MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION	equ 4
MEM_EXECUTE_OPTION_PERMANENT				equ 8
MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE	equ 10H
MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE	equ 20H

; +
; Стаб для обработки ZwQueryInformationProcess().
;
; o Инфокласс задаём статически, можно определить анализом ветви.
;
xPS_Stub:
	%GET_CURRENT_GRAPH_ENTRY
PS_Stub proc C
	cmp PSSTUB.ProcessHandle[esp + 4],NT_CURRENT_PROCESS
	mov ecx,PSSTUB.Information[esp + 4]
	jne @f
	cmp PSSTUB.InfoClass[esp + 4],ProcessExecuteFlags
	jne @f
	cmp PSSTUB.InfoLength[esp + 4],4
	jne @f
	test ecx,ecx
	mov edx,PSSTUB.ReturnLength[esp + 4]
	jz @f
	mov dword ptr [ecx],40H or MEM_EXECUTE_OPTION_PERMANENT \
		or MEM_EXECUTE_OPTION_ENABLE \
		or MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE \
		or MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE
	.if Edx
		mov dword ptr [edx],4
	.endif
	xor eax,eax
	retn sizeof(PSSTUB)
@@:
	push dword ptr 0
PS_Stub_Ptr::
	retn
PS_Stub endp'

PSSTUBSIZE	equ 3CH
PSSTUBPTR		equ (PSSTUBSIZE - 5)	; push imm32/ret

%PSGEN macro
	xor eax,eax
	sub eax,0FBDB837DH
	stosd
	xor eax,02068F77CH
	stosd
	add eax,05EDEE90DH
	stosd
	sub eax,061235090H
	stosd
	xor eax,05E8B0009H
	stosd
	add eax,0F880EBAFH
	stosd
	sub eax,0E93A8B07H
	stosd
	xor eax,0FFDDA149H
	stosd
	add eax,005EDA2C1H
	stosd
	sub eax,06F01C715H
	stosd
	xor eax,0CC0674D2H
	stosd
	add eax,038F98F30H
	stosd
	sub eax,03D3FD102H
	stosd
	xor eax,0C2A83314H
	stosd
	add eax,0C297FFECH
	stosd
endm

DISPATCHER_NL	equ 5

API_LIST struct
pKiUserExceptionDispatcher		PVOID ?
pZwAllocateVirtualMemory			PVOID ?
pZwProtectVirtualMemory			PVOID ?
pZwFreeVirtualMemory			PVOID ?
pZwQueryVirtualMemory			PVOID ?
pZwQueryInformationProcess		PVOID ?
pRtlAddVectoredExceptionHandler	PVOID ?
Eol							PVOID ?
PsStub						GP_SNAPSHOT <>
API_LIST ends
PAPI_LIST typedef ptr API_LIST

; +
; 
; Трассировочный колбек. Выполняет корректировку описателей в графе, загружая ссылки в ветвлениях на стабы.
; 
xGpLoadStubsCallback:
	%GET_CURRENT_GRAPH_ENTRY
GpLoadStubsCallback proc GpEntry:PVOID, Apis:PAPI_LIST
	mov ecx,GpEntry
	mov edx,Apis
	mov eax,dword ptr [ecx + EhEntryType]
	and al,TYPE_MASK
	cmp al,HEADER_TYPE_CALL
	jne Exit
	test dword ptr [ecx + EhBranchType],BRANCH_DEFINED_FLAG
	mov eax,dword ptr [ecx + EhBranchAddress]
	jz Exit
	assume edx:PAPI_LIST
;	cmp [edx].pZwQueryVirtualMemory,eax
;	je VM
	cmp [edx].pZwQueryInformationProcess,eax
	je PS
Exit:
	xor eax,eax
	ret
PS:
	mov eax,[edx].PsStub.GpBase
Load:
; * Билдер формирует смещение в ветвлении на основе адреса(DISCLOSURE_CALL_FLAG), а не ссылки.
	xchg dword ptr [ecx + EhBranchAddress],eax
	and dword ptr [ecx + EhDisclosureFlag],NOT(DISCLOSURE_CALL_FLAG)
	mov [edx].Eol,TRUE
	mov ecx,[edx].PsStub.GpBase
	mov dword ptr [ecx + PSSTUBPTR],eax
	jmp Exit
GpLoadStubsCallback endp

SNAPS struct
RwSnap	GP_SNAPSHOT <>	; Нелинейный граф.
CsSnap	GP_SNAPSHOT <>	; Линейный граф для билдера.
BdSnap	GP_SNAPSHOT <>	; Выходной буфер.
SNAPS ends
PSNAPS typedef ptr SNAPS

PcStackBase	equ 4
PcStackLimit	equ 8

comment '
; +
; 
; VEH, выполняет S-маршрутизацию(стековое переключение на отморфленный код).
;
VEH proc uses ebx ExceptionPointers:PEXCEPTION_POINTERS
Local GpEntry:PVOID
	mov ebx,ebp
	assume ebx:PSTACK_FRAME
	jmp @f
Next:
	mov ebx,[ebx].Next
@@:
	cmp fs:[PcStackBase],ebx
	jna Exit
	cmp fs:[PcStackLimit],ebx
	lea eax,GpEntry
	ja Exit
	Call Delta
Delta:
VEH_Ptr::
	mov edx,dword ptr 0	; PGCBE
	pop ecx
	push eax
	lea ecx,SNAPS.RwSnap[ecx + (offset VEH_Snp - offset Delta)]
	push [ebx].Ip
	push GCBE_PARSE_NL_UNLIMITED
	push ecx
	mov eax,GP_RW_CHECK_IP_BELONG_TO_SNAPSHOT
	Call Edx
	test eax,eax
	mov ecx,GpEntry
	jnz Next
	mov ecx,dword ptr [ecx + EhCrossLink]
	and ecx,NOT(TYPE_MASK)	
	mov eax,dword ptr [ecx + EhAddress]
	mov [ebx].Ip,eax
	jmp Next
Exit:
	xor eax,eax
	ret
VEH_Snp SNAPS <>
VEH endp'

PVEHSNP	equ 5DH	; (offset VEH_Snp - offset VEH)
PVEHGPE	equ 28H	; (offset VEH_Ptr - offset VEH + 1)

%VEHGEN macro
	xor eax,eax
	sub eax,07C1374ABH
	stosd
	xor eax,008BF7791H
	stosd
	add eax,0FFAEEF19H
	stosd
	sub eax,06DC987C2H
	stosd
	xor eax,01D39641FH
	stosd
	add eax,039644072H
	stosd
	sub eax,039643859H
	stosd
	xor eax,0FC45851DH
	stosd
	add eax,04A2A777H
	stosd
	sub eax,046E83477H
	stosd
	xor eax,0BA000000H
	stosd
	add eax,0898D5059H
	stosd
	sub eax,0898D5023H
	stosd
	xor eax,06A0473C9H
	stosd
	add eax,09CB3DDFFH
	stosd
	sub eax,007B851FEH
	stosd
	xor eax,074C085D2H
	stosd
	add eax,037B5767BH
	stosd
	sub eax,04059B2C2H
	stosd
	xor eax,0C297B56AH
	stosd
	add eax,0C2B78C27H
	stosd
	sub eax,0440FD31DH
	stosd
	xor eax,0C4F17CB0H
	stosd
	add eax,0FB3D36A5H
	stosd
endm

; +
; 
; Инициализация.
;
GpInitialize proc uses ebx esi edi
Local Apis:API_LIST
Local GpSize:ULONG
Local Sn:SNAPS
	%SEHPROLOG
	xor ecx,ecx
	mov Apis.pKiUserExceptionDispatcher,0C5713067H
	mov Apis.pZwAllocateVirtualMemory,24741E13H
	mov Apis.pZwProtectVirtualMemory,39542311H
	mov Apis.pZwFreeVirtualMemory,0DA44E712H
	mov Apis.pZwQueryVirtualMemory,0EA7DF819H
	mov Apis.pZwQueryInformationProcess,34DF9700H
	mov Apis.pRtlAddVectoredExceptionHandler,815C378DH
	mov Apis.Eol,ecx
	invoke LdrEncodeEntriesList, NULL, Ecx, addr Apis
	test eax,eax
	jnz Exit
; Аллоцируем буфер для конструктора.
	lea ebx,Sn.RwSnap
	mov Sn.RwSnap.GpBase,eax
	mov GpSize,4 * 20H * X86_PAGE_SIZE
	Call Alloc
	jnz Exit
	lea ecx,Sn.RwSnap.GpLimit
	push eax
	push eax
	push eax
	push eax
	push eax
	push DISPATCHER_NL
	push GCBE_PARSE_IPCOUNTING or GCBE_PARSE_SEPARATE
	push ecx
	push Apis.pKiUserExceptionDispatcher
	%GPCALL GP_PARSE	; !OPT_EXTERN_SEH_MASK - расширяемый буфер не используем.
	test eax,eax
	lea ebx,Apis.PsStub
	jnz RwFree	; #AV etc.
	mov Apis.PsStub.GpBase,eax
	mov GpSize,2 * X86_PAGE_SIZE
	Call Alloc
	jnz RwFree
; Генерируем стаб в буфер.
	mov edi,Apis.PsStub.GpBase
	%PSGEN
; Формируем стабы для процедур валидации.
	lea ecx,Apis
	%GET_GRAPH_ENTRY xGpLoadStubsCallback
	push ecx
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push Sn.RwSnap.GpBase
	%GPCALL GP_TRACE
	test eax,eax
	jnz StFree
	cmp Apis.Eol,FALSE
	jne @f
	mov eax,STATUS_NOT_FOUND
	jmp StFree
@@:
; Аллоцируем буфера для конвертора и билдера.
	lea ebx,Sn.CsSnap
	mov Sn.CsSnap.GpBase,eax
	mov GpSize,4 * 20H * X86_PAGE_SIZE
	Call Alloc
	jnz StFree
	lea ebx,Sn.BdSnap
	mov Sn.BdSnap.GpBase,eax
	mov GpSize,16 * X86_PAGE_SIZE	; < 2p
	Call Alloc
	jnz CsFree
	push Sn.BdSnap.GpBase
	push Sn.CsSnap.GpBase
	push Sn.RwSnap.GpLimit
	push Sn.RwSnap.GpBase
	%GPCALL GP_BUILD
	test eax,eax
	cld
	jnz BdFree
	push edi
	%VEHGEN
	lea esi,Sn
	mov edi,dword ptr [esp]
	mov ecx,sizeof(SNAPS)/4
	mov edx,edi
	add edi,PVEHSNP
	%GET_GRAPH_ENTRY xGCBE
	rep movsd
	mov dword ptr [edx + PVEHGPE],eax
	push 1
	Call Apis.pRtlAddVectoredExceptionHandler
	.if !Eax
		mov eax,STATUS_UNSUCCESSFUL
		jmp BdFree
	.endif
	xor eax,eax
	jmp Exit
BdFree:
	lea ebx,Sn.BdSnap
	Call AllocFree
CsFree:
	lea ebx,Sn.CsSnap
	Call AllocFree
StFree:
	lea ebx,Apis.PsStub
	Call AllocFree
RwFree:
	lea ebx,Sn.RwSnap
	Call AllocFree
	%SEHEPILOG
	ret
Alloc:
	assume ebx:PGP_SNAPSHOT
	xor eax,eax
	mov [ebx].GpBase,eax
	lea ecx,GpSize
	lea edx,[ebx].GpBase
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	Call Apis.pZwAllocateVirtualMemory
	test eax,eax
	mov ecx,GpSize
	jnz AllocFail
	sub ecx,X86_PAGE_SIZE
	push [ebx].GpBase
	mov GpSize,X86_PAGE_SIZE
	add [ebx].GpBase,ecx
	lea eax,[ebx].GpLimit
	lea ecx,GpSize
	lea edx,[ebx].GpBase
	push eax
	push PAGE_NOACCESS
	push ecx
	push edx
	push NtCurrentProcess
	Call Apis.pZwProtectVirtualMemory
	pop ecx
	test eax,eax
	mov [ebx].GpBase,ecx
	mov [ebx].GpLimit,ecx
	jnz AllocFree
AllocFail:
	retn
AllocFree:
	push eax
	mov GpSize,NULL
	lea eax,GpSize
	lea ecx,[ebx].GpBase
	push MEM_RELEASE
	push eax
	push ecx
	push NtCurrentProcess
	Call Apis.pZwFreeVirtualMemory
	pop eax
	test eax,eax
	retn
GpInitialize endp
end GpInitialize