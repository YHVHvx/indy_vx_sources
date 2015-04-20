MAX_INSTRUCTION_LENGTH	equ 15

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B

; TEB.Tib.StackBase и StackLimit.
;
PcStackBase	equ 4
PcStackLimit	equ 8

EOL	equ NULL	; End Of List.

; ~ RtlpCheckHeapSignature().
;
MSG_HEAP_INVALID_SIGNATURE		equ 033391F16H	; HASH("Invalid heap signature for heap "), 0x20
MSG_HEAP_INVALID_SIGNATURE_LENGTH	equ 32

WSP_PARSE_DATA struct
WsHandle			HANDLE ?	; mswsock.dll
WSPSocketLvl2		GP_SNAPSHOT <>	; Cs'
WSPSocketLvl0		GP_SNAPSHOT <>	; Rw', !GpLimit
WSP_PARSE_DATA ends
PWSP_PARSE_DATA typedef ptr WSP_PARSE_DATA

BADREF_MAGIC_BASE	equ 00DBAC0D0H

; Число описателей в таблице хэндлов AFD.
;
HT_ENTRIES	equ 64

; Запись в таблице хэндлов.
;
HT_ENTRY struct
Handle	HANDLE ?
Magic	ULONG ?
HT_ENTRY ends
PHT_ENTRY typedef ptr HT_ENTRY

; Среда.
;
ENVIRONMENT struct
Apis			APIS <>	; В начале структуры!
ifdef DBGBUILD
; Для многопоточной отладки счётчики следует перенести в TLS.
   TraceOverCount		ULONG ?
   TraceIntoCount		ULONG ?
   SkipTraceStubCount	ULONG ?
   OpenCount			ULONG ?
   CloseCount			ULONG ?
   BadrefCount			ULONG ?
   IoControlCount		ULONG ?
   BreakCount			ULONG ?
   PrintCount			ULONG ?
   RtlpCheckHeapSignatureCalls	ULONG ?
   BadrefStubCount		ULONG ?
   LastTraceIp			PVOID ?
endif
WspSnapshot	WSP_PARSE_DATA <>
HmgrSnapshot	GP_SNAPSHOT <>
BodySnapshot	GP_SNAPSHOT <>
HandleTable	HT_ENTRY HT_ENTRIES + 1 DUP (<>)
ENVIRONMENT ends
PENVIRONMENT typedef ptr ENVIRONMENT

; TLS.
;
TLS struct
RouteIp	PVOID ?	; Адрес возврата при маршрутизации RtlpCheckHeapSignature().
SkipIp	PVOID ?	; Адрес возврата при трассировке.
Ip2ndf	PVOID ?	; Адрес возврата в WSPSocket().
PostIp	PVOID ?	; Адрес возврата из WSPSocket() для блокировки паразитной трассировки.
Flags	ULONG ?
TLS ends
PTLS typedef ptr TLS

; Смещение ссылки на среду в PEB.
;
PEB_ENV_PTR	equ X86_PAGE_SIZE - 4

; Получение среды.
;
%GET_ENV_PTR macro Reg32
	mov Reg32,fs:[TEB.Peb]
	mov Reg32,dword ptr [Reg32 + PEB_ENV_PTR]
endm

; Загрузка среды.
;
%SET_ENV_PTR macro pEnv
	mov eax,fs:[TEB.Peb]
	mov dword ptr [eax + PEB_ENV_PTR],pEnv
endm

%HALT macro
	jmp $
endm

OBJECT_HANDLE_FLAG_INFORMATION struct
Inherit			BOOL ?
ProtectFromClose	BOOL ?
OBJECT_HANDLE_FLAG_INFORMATION ends
POBJECT_HANDLE_FLAG_INFORMATION typedef ptr OBJECT_HANDLE_FLAG_INFORMATION