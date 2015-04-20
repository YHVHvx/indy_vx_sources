; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
	include Graph.inc

%GPCALL macro Service, Opt
	ifdef Opt
	   mov eax,Service or Opt
	else
	   mov eax,Service
	endif
	Call GCBE
endm

OPT_EXTERN_SEH_MASK		equ 10000000B
OPT_EXTERN_SEH_BIT		equ 7

GP_LDE	equ 0	; ULONG (*PGCBE)(IN PVOID Ip);

GP_PFX	equ 1	; ULONG (*PGCBE)(IN PVOID Ip);

; Возвращает:
; o Eax тип инструкции(HEADER_TYPE_*).
; o Edx адрес ветвления.

GP_PARSE	equ 2

; Flags
GCBE_PARSE_DISCLOSURE	equ 000001B	; Не используется, определяет NL.
GCBE_PARSE_SEPARATE		equ 000010B	; Для каждой инструкции создаётся описатель.
GCBE_PARSE_MAKELIST		equ 000100B	; Не используется в данной версии. Список процедур ведётся вне зависимости от флага.
GCBE_PARSE_CROSSBREAK	equ 001000B	; Проверка разрыва графа(ветвление не на начало инструкции) и останов.
GCBE_PARSE_OPENLIST		equ 010000B	; В списке процедур сохраняются ссылки на CALL_HEADER, если установлен этот флаг, то на начало процедуры.
GCBE_PARSE_IPCOUNTING	equ 100000B	; Вычисляет число инструкций в блоке. Если флаг сброшен, то поле IpCount будет инвалидным(обнуляется при вставке).

; * GCBE_PARSE_CROSSBREAK и GCBE_PARSE_IPCOUNTING не взводить без необходимости, так как отрицательно скажется на производительности.

; NL
GCBE_PARSE_NL_UNLIMITED	equ -2
GCBE_PARSE_NL_PRIMARY	equ 0

comment '
typedef NTSTATUS (*PPARSE_CALLBACK_ROUTINE)(
   IN PVOID *Graph,		// Ссылка на граф.
   IN PVOID GraphEntry,	// Ссылка на описатель инструкции.
   IN PVOID SubsList,	// Список описателей входов процедур в порядке вызова.
   IN ULONG SubsCount,	// Число процедур в списке является уровнем вложенности(NL).
   IN BOOLEAN PreOrPost,	// Тип вызова.
   IN PVOID Context
   );

 o Список процедур завершается нулём(EOL).
 o Описатель процедурного ветвления на текущую процедуру: SubsList[0].BranchLink.
 o Описатель может измениться изза вставки. Выполняется разрыв описателя при обнаружении ветвление внутрь линейного блока.
   * В следствии этого нельзя выполнять анализ графа на этапе его создания(из калбэка парсера).
 o Обратная ссылка(Blink) описателя может отсутствовать. Парсер определит её далее при анализе следующего ветвления.
 o Первый описатель в списке может быть не заполнен, он будет заполнен на следующем вызове.

typedef PVOID (*PSEARCH_CALLBACK_ROUTINE)(
   IN PVOID Address,
   IN PVOID Context,
   IN BOOLEAN FirstSearch
   );

; o Перед вызовом ядерный стек потока должен быть расширен конвертацией в Gui-поток посредством PsConvertToGuiThread(), 
;   либо вызовом любого теневого сервиса(можно инвалидного за пределами сст).

typedef NTSTATUS (*PENTRY)(
  IN PVOID Entry,
  IN OUT PVOID *Graph,
  IN ULONG ParseFlags,
  IN ULONG NestingLevel,
  IN PVOID LastIp OPTIONAL,
  IN PPARSE_CALLBACK_ROUTINE ParseCallbackRoutine OPTIONAL,
  IN PVOID ParseCallbackParameter,
  IN PSEARCH_CALLBACK_ROUTINE SearchCallbackRoutine OPTIONAL,
  IN PVOID SearchCallbackParameter
  );
  '

GP_TRACE	equ 3

comment '
typedef NTSTATUS (*PTRACE_CALLBACK_ROUTINE)(
    IN PVOID GpEntry,
    IN PVOID CallbackParameter
    );

typedef NTSTATUS (*PGCBE)(
  IN PVOID Graph,
  IN ULONG NL,
  IN PTRACE_CALLBACK_ROUTINE CallbackRoutine,
  IN PVOID CallbackParameter
  );
  
 o Трассировка прекращается возвратом из калбэка значения, 
   отличного от STATUS_SUCCESS. В этом случае должен быть 
   выполнен цикл очистки флажка ACCESSED_MASK_FLAG во всех
   описателях после возврата из трассировщика, либо при 
   следующем его вызове.
  '

GP_BUILD	equ 4

STACK_FRAME struct
Next		PVOID ?	; PSTACK_FRAME
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

GP_CALLER struct
GpEntry		PVOID ?	; 1st
Frame		PSTACK_FRAME ?
SFN			ULONG ?
GP_CALLER ends
PGP_CALLER typedef ptr GP_CALLER

GP_SNAPSHOT struct
Ip		PVOID ?	; Адрес разбираемой процедуры.
GpBase	PVOID ?	; Базовый адрес буфера с графом.
GpLimit	PVOID ?	; Лимит графа(размер + GpBase).
GP_SNAPSHOT ends
PGP_SNAPSHOT typedef ptr GP_SNAPSHOT

GP_CS_CHECK_IP_BELONG_TO_SNAPSHOT		equ 5

comment '  
typedef NTSTATUS (*PGCBE)(
  IN PGP_SNAPSHOT Snapshot,
  IN PVOID Ip,
  OUT PVOID GraphEntry
  );
  '

GP_RW_CHECK_IP_BELONG_TO_SNAPSHOT		equ 6

comment '  
typedef NTSTATUS (*PGCBE)(
  IN PGP_SNAPSHOT Snapshot,
  IN PVOID NL,
  IN ULONG Ip,
  OUT PVOID GraphEntry
  );
  '

GP_FIND_CALLER_BELONG_TO_SNAPSHOT		equ 7

KernelMode	equ 0
UserMode		equ 1

comment '  
typedef NTSTATUS (*PGCBE)(
  IN PGP_SNAPSHOT Snapshot,
  IN BOOLEAN Raw,
  IN ULONG NL,
  IN PSTACK_FRAME Sfc,
  IN ULONG Mode,
  IN BOOLEAN Trace,
  OUT PGP_CALLER Caller
  );

 o Mode определяет режим, если указан KernelMode, то выполняется 
   идентификация фрейма(стек- или трап-) для изоляции ISR.
 o Trace определяет тип графа, если TRUE, то Rw.
 '
GP_CS_UNLINK_ENTRY		equ 8
GP_CS_INSERT_HEAD_ENTRY	equ 9
GP_RW_UNLINK_FLOW		equ 10
GP_MERGE				equ 11
GP_SWITCH_THREAD		equ 12