PPVOID typedef ptr PVOID

EOL	equ 0	; End Of List

BADREF_MAGIC_BASE	equ 00DBAC0D0H

STACK_FRAME struct
Next		PVOID ?	; PSTACK_FRAME
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

; Описатель сервиса. Эта структура следует за именем сервиса.
;
SYSLIST struct
Entry	PVOID ?	; Адрес стаба.
Id		USHORT ?	; Номер сервиса.
Args		USHORT ?	; Число аргументов.
Hash		DWORD ?	; Хэш от имени сервиса.
SYSLIST ends
PSYSLIST typedef ptr SYSLIST

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

PROCESS_HANDLE_TRACING_ENABLE struct
Flags		ULONG ?
PROCESS_HANDLE_TRACING_ENABLE ends

PROCESS_HANDLE_TRACING_MAX_STACKS	equ 16

HANDLE_TRACE_DB_OPEN	equ 1
HANDLE_TRACE_DB_CLOSE	equ 2
HANDLE_TRACE_DB_BADREF	equ 3

PROCESS_HANDLE_TRACING_ENTRY struct
Handle		HANDLE ?
ClientId		CLIENT_ID <>
_Type		ULONG ?	; HANDLE_TRACE_DB_*
Stacks		PVOID PROCESS_HANDLE_TRACING_MAX_STACKS DUP (?)
PROCESS_HANDLE_TRACING_ENTRY ends

PROCESS_HANDLE_TRACING_QUERY struct
Handle		HANDLE ?
TotalTraces	ULONG ?
HandleTrace	PROCESS_HANDLE_TRACING_ENTRY 1 DUP (<>)
PROCESS_HANDLE_TRACING_QUERY ends

ProcessHandleTracing	equ 32

RTL_PROCESS_MODULE_INFORMATION struct
Section			HANDLE ?
MappedBase		PVOID ?
ImageBase			PVOID ?
ImageSize			ULONG ?
Flags			ULONG ?
LoadOrderIndex		USHORT ?
InitOrderIndex		USHORT ?
LoadCount			USHORT ?
OffsetToFileName	USHORT ?
FullPathName		UCHAR 256 DUP (?)
RTL_PROCESS_MODULE_INFORMATION ends
PRTL_PROCESS_MODULE_INFORMATION typedef ptr RTL_PROCESS_MODULE_INFORMATION

SYSTEM_BASIC_INFORMATION struct
Reserved					ULONG ?
TimerResolution			ULONG ?
PageSize					ULONG ?
NumberOfPhysicalPages		ULONG ?
LowestPhysicalPageNumber		ULONG ?
HighestPhysicalPageNumber	ULONG ?
AllocationGranularity		ULONG ?
MinimumUserModeAddress		ULONG ?
MaximumUserModeAddress		ULONG ?
ActiveProcessorsAffinityMask	ULONG ?
NumberOfProcessors			BYTE ?
_align					byte 3 dup (?)
SYSTEM_BASIC_INFORMATION ends
PSYSTEM_BASIC_INFORMATION typedef ptr SYSTEM_BASIC_INFORMATION

FLG_ANALYSIS_FAILURE	equ 001B	; Ошибка при анализе.
FLG_FILTER_PRESENT		equ 010B	; Наличие фильтра.
FLG_FILTER_DEFINED		equ 100B	; Модуль фильтра определён.

; Структура описывает одну NTAPI.
;
SYSENTRY struct
Id		USHORT ?	; Номер сервиса.
Args		BYTE ?	; Число аргументов.
Flags	BYTE ?	; FLG_*
; Последовательность проверки флагов: FLG_ANALYSIS_FAILURE -> FLG_FILTER_PRESENT -> FLG_FILTER_DEFINED.
; Если фильтр определён(FLG_FILTER_DEFINED), то AvList содержит ссылку на описатель модуля.
SsList	PVOID ?	; Ссылка на информацию про сервис, это имя сервиса, за которым следует структура SYSLIST.
Filter	PVOID ?	; Адрес возврата в фильтр, это тело фильтра.
AvList	PRTL_PROCESS_MODULE_INFORMATION ?	; Информация про модуль, валидна если FLG_FILTER_DEFINED.
SYSENTRY ends
PSYSENTRY typedef ptr SYSENTRY

ObjectHandleFlagInformation	equ 4

OBJECT_HANDLE_FLAG_INFORMATION struct
Inherit			BOOLEAN ?
ProtectFromClose	BOOLEAN ?
OBJECT_HANDLE_FLAG_INFORMATION ends