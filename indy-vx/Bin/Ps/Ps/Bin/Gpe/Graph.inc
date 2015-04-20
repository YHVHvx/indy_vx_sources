; Линейным блоком кода будем считать группу инструкци
; й, которые расположены в памяти последовательно и н
; е являются ветвлениями. Линейный блок описывается о
; дним входом таблицы(не описывает каждую инструкцию).
; Таблица ветвлений содержит описатели для каждого ли
; нейного блока и ветвлений. Таблица, все описатели в 
; ней и поля в описателях выравнены на границу 4-х ба
; йт. Таким образом младшие два бита ссылки на описат
; ель свободны и используются как флаги.

TYPE_MASK			equ 11B

; [Имена смещений полей в описателях начинаются с пре
; фикса Eh(Entry Header). Флажки определяются наложе
; нием соответствующей маски на поле в описателе.]
; Смещение первых 4-х полей всех описателей одинаково.
 
; Описатель линейного блока.
BLOCK_HEADER struct
Link			LIST_ENTRY <>	; Link.Flink & HEADER_TYPE_MASK = HEADER_TYPE_LINE
; Flink:
; > 00 Line
;   01 Subroutine
;   10 Branch
;   11 Conditional branch
; Blink:
; - Макро(GCBE_PARSE_SEPARATE).
;   XN
; - Для трассировщика флаг(ACCESSED_MASK_FLAG).
;   NX
Address		PVOID ?
UserData		PVOID ?
_Size		ULONG ?	; Размер блока(сумма длин всех инструкций входящих в описываемый блок).
_Align		ULONG ?
BLOCK_HEADER ends
PBLOCK_HEADER typedef ptr BLOCK_HEADER

; Флаг определяет что вход описывает несколько линейных инструкций.
EhSepatateFlag		equ BLOCK_HEADER.Link.Blink
SEPARATE_MACRO_FLAG	equ 01B

EhSize			equ BLOCK_HEADER._Size

; Описатели всех типов имеют одинаковый размер, что 
; позволяет заменять их.

ENTRY_HEADER_SIZE	equ sizeof(BLOCK_HEADER)

; Все описатели связаны между собой и представляют со
; бой двусвязанный список.

EhFlink			equ BLOCK_HEADER.Link.Flink
EhBlink			equ BLOCK_HEADER.Link.Blink

; Первые два поля описателей(Link) - две ссылки, на с
; ледующий и предыдущий описатели. Младшие два бита с
; сылки на следующий описатель(Link.Flink) определяют 
; тип описателя.

EhEntryType		equ BLOCK_HEADER.Link.Flink	; TYPE_MASK

; Всего используется 4 типа:

HEADER_TYPE_LINE	equ 00B	; Линейный блок.
HEADER_TYPE_CALL	equ 01B	; Процедурное ветвление.
HEADER_TYPE_JMP	equ 10B	; Безусловное ветвление.
HEADER_TYPE_JXX	equ 11B	; Условное ветвление.

; Инструкции Loop, Loope, Loopne и Jcxz являются условными ветвлениями(HEADER_TYPE_JXX).

; Третье поле описателей(Address) содержит указатель 
; на описываемую инструкцию.

EhAddress			equ BLOCK_HEADER.Address

; Бит 1 поля Link.Blink во всех описателях внешний и 
; используется при трассировке таблицы ветвлений. (Тр
; ассировщик производит инверсию этого бита при каждо
; м проходе, помечая тем самым описатели которые пере
; числены).

EhAccessFlag		equ BLOCK_HEADER.Link.Blink	; ACCESSED_MASK_FLAG
ACCESSED_MASK_FLAG	equ 10B	; _HEADER.Link.Blink

; 4-е поле описателей внешнее и используется для хран
; ения пользовательских данных, связанных с описателе
; м. Используется при создании таблицы перекрёстных с
; сылок.

EhUserData		equ BLOCK_HEADER.UserData

; Описатель процедурного ветвления.
CALL_HEADER struct
Link			LIST_ENTRY <>	; ..HEADER_TYPE_CALL
; Flink:
;   00 Line
; > 01 Subroutine
;   10 Branch
;   11 Conditional branch
; Blink:
;   X0 Адрес ветвления определён.
;   X1 Адрес ветвления не определён(Call Eax, etc.)
; - Для трассировщика флаг(ACCESSED_MASK_FLAG).
;   NX
Address		PVOID ?
UserData		PVOID ?
BranchAddress	PVOID ?
BranchLink	PVOID ?
CALL_HEADER ends
PCALL_HEADER typedef ptr CALL_HEADER

DISCLOSURE_CALL_FLAG	equ 01B
EhDisclosureFlag		equ CALL_HEADER.BranchLink	; DISCLOSURE_CALL_FLAG

; Описатель безусловного ветвления.	
BRANCH_HEADER struct
Link			LIST_ENTRY <>	; ..HEADER_TYPE_JMP
; Flink:
;   00 Line
;   01 Subroutine
; > 10 Branch
;   11 Conditional branch
; Blink:
;   X0 Адрес ветвления определён.
;   X1 Адрес ветвления не определён(Jmp Eax, etc.)
; - Для трассировщика флаг(ACCESSED_MASK_FLAG).
;   NX
Address		PVOID ?
UserData		PVOID ?
BranchAddress	PVOID ?	; Адрес куда происходит ветвление.
BranchLink	PVOID ?	; Описатель инструкции по адресу, на который происходит ветвление.
; - Тип ветвления(определяет оптимизатор).
;   X0 Short
;   X1 Near
; - Холостое ветвление(готовится к удалению оптимизатором).
;   NX
BRANCH_HEADER ends
PBRANCH_HEADER typedef ptr BRANCH_HEADER

EhBranchAddress	equ BRANCH_HEADER.BranchAddress
EhBranchLink		equ BRANCH_HEADER.BranchLink

BRANCH_SIZE_MASK	equ 01H	; BRANCH_HEADER.BranchLink
EhBranchSize		equ BRANCH_HEADER.BranchLink	; BRANCH_SIZE_MASK

; Внутренний флаг оптимизатора ветвлений.
BRANCH_IDLE_FLAG	equ 10B	; BRANCH_HEADER.BranchLink
EhIdleBranch		equ BRANCH_HEADER.BranchLink	; BRANCH_IDLE_FLAG

BRANCH_DEFINED_FLAG	equ 01B	; BRANCH_HEADER.Link.Blink
EhBranchType		equ BRANCH_HEADER.Link.Blink	; BRANCH_DEFINED_FLAG

; Описатель условного ветвления(Jcc, Loop, Loope, Loopne и Jcxz).	
XX_BRANCH_HEADER struct
Link			LIST_ENTRY <>	; ..HEADER_TYPE_JXX
; Flink:
;   00 Line
;   01 Subroutine
;   10 Branch
; > 11 Conditional branch
; Blink:
;   X0 Jcc.
;   X1 Loop, Loope, Loopne и Jcxz.
; - Для трассировщика флаг(ACCESSED_MASK_FLAG).
;   NX
Address		PVOID ?
UserData		PVOID ?
BranchAddress	PVOID ?	; Адрес куда происходит ветвление.
BranchLink	PVOID ?	; Описатель инструкции по адресу, на который происходит ветвление.
; - Тип ветвления.
;   X0 Short
;   X1 Near
; - Холостое ветвление.
;   NX
XX_BRANCH_HEADER ends
PXX_BRANCH_HEADER typedef ptr XX_BRANCH_HEADER

BRANCH_CX_FLAG		equ 01B	; XX_BRANCH_HEADER.Link.Blink
EhJccType			equ XX_BRANCH_HEADER.Link.Blink	; BRANCH_CX_FLAG