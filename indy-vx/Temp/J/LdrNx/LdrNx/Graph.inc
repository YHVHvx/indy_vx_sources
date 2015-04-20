; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
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

; o При изменении размера описателей пересчитать константу CX_REPLACE_GRAPH_LENGTH.
; o В данной версии в таблице перекрёстных ссылок поле Address будет содержать адрес 
;   инструкции в собираемом буфере, адрес оригинальной инструкции находится в первичном 
;   графе, они связаны перекрёстными ссылками.
; o Если граф не линейный(части графа расположены в разных регионах ап), то должен быть 
;   сконвертирован в линейный посредством GP_MERGE.

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
IpCount		ULONG ?	; Число инструкций в блоке.
IpLength		BYTE ?
KitFlags		BYTE 3 DUP (?)
CrossLink		PVOID ?	; Перекрёстная ссылка между таблицами Rw' и Cs'.
BLOCK_HEADER ends
PBLOCK_HEADER typedef ptr BLOCK_HEADER

; Флаг определяет что вход описывает несколько линейных инструкций.
EhSepatateFlag		equ BLOCK_HEADER.Link.Blink
SEPARATE_MACRO_FLAG	equ 01B

EhSize			equ BLOCK_HEADER._Size

; Длина инструкции(LDE(Ip)).

EhIpLength	equ BLOCK_HEADER.IpLength

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
HEADER_TYPE_JCC	equ 11B	; Условное ветвление.

; Инструкции Loop, Loope, Loopne и Jcxz являются условными ветвлениями(HEADER_TYPE_JCC).

; Третье поле описателей(Address) содержит указатель на описываемую инструкцию.
; Если это поле обнулено, то псевдоописатель(не описывает код, напр. ветвление).

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

; Число инструкций в линейном блоке.
EhIpCount			equ BLOCK_HEADER.IpCount

; Описатель процедурного ветвления.
CALL_HEADER struct
Link			LIST_ENTRY <>	; ..HEADER_TYPE_CALL
; Flink:
;   00 Line
; > 01 Subroutine
;   10 Branch
;   11 Conditional branch
; Blink:
;   X0 Адрес ветвления не определён(Call Eax, etc.)
;   X1 Адрес ветвления определён.
; - Для трассировщика флаг(ACCESSED_MASK_FLAG).
;   NX
Address		PVOID ?
UserData		PVOID ?
BranchAddress	PVOID ?
BranchLink	PVOID ?
;   X0 Ветвление закрытое.
;   X1 Ветвление раскрыто.
IpLength		BYTE ?
KitFlags		BYTE 3 DUP (?)
CrossLink		PVOID ?
CALL_HEADER ends
PCALL_HEADER typedef ptr CALL_HEADER

DISCLOSURE_CALL_FLAG	equ 01B
EhDisclosureFlag		equ CALL_HEADER.BranchLink	; DISCLOSURE_CALL_FLAG

; Описатель безусловного ветвления.	
JMP_HEADER struct
Link			LIST_ENTRY <>	; ..HEADER_TYPE_JMP
; Flink:
;   00 Line
;   01 Subroutine
; > 10 Branch
;   11 Conditional branch
; Blink:
;   X0 Адрес ветвления не определён(Jmp Eax, etc.)
;   X1 Адрес ветвления определён.
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
IpLength		BYTE ?
KitFlags		BYTE 3 DUP (?)
CrossLink		PVOID ?
JMP_HEADER ends
PJMP_HEADER typedef ptr JMP_HEADER

EhBranchAddress	equ JMP_HEADER.BranchAddress
EhBranchLink		equ JMP_HEADER.BranchLink

BRANCH_SIZE_MASK	equ 01H	; BRANCH_HEADER.BranchLink
EhBranchSize		equ JMP_HEADER.BranchLink	; BRANCH_SIZE_MASK
; 0 - short, 1 - near.

; Внутренний флаг оптимизатора ветвлений.
BRANCH_IDLE_FLAG	equ 10B	; BRANCH_HEADER.BranchLink
EhIdleBranch		equ JMP_HEADER.BranchLink	; BRANCH_IDLE_FLAG

BRANCH_DEFINED_FLAG	equ 01B	; BRANCH_HEADER.Link.Blink
EhBranchType		equ JMP_HEADER.Link.Blink	; BRANCH_DEFINED_FLAG

; Описатель условного ветвления(Jcc, Loop, Loope, Loopne и Jcxz).	
JCC_HEADER struct
Link			LIST_ENTRY <>	; ..HEADER_TYPE_JCC
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
IpLength		BYTE ?
KitFlags		BYTE 3 DUP (?)
CrossLink		PVOID ?
JCC_HEADER ends
PJCC_HEADER typedef ptr JCC_HEADER

BRANCH_CX_FLAG		equ 01B	; XX_BRANCH_HEADER.Link.Blink
EhJcxType			equ JCC_HEADER.Link.Blink	; BRANCH_CX_FLAG

EhKitFlags		equ BLOCK_HEADER.KitFlags
EhCrossLink		equ JCC_HEADER.CrossLink

; Тип ветвления формируется вычитанием базы из опкода. Далее обращение к LDE не 
; выполняется, а испольуется указанный тип ветвления. Это позволяет использовать 
; псевдокод(сслка на код в описателе обнулена).

JCC_SHORT_OPCODE_BASE	equ 70H
JCC_NEAR_OPCODE_BASE	equ 80H

JCC_O	equ 0	; OF
JCC_NO	equ 1	; !OF
JCC_C	equ 2	; CF
JCC_B	equ 2	; CF
JCC_NAE	equ 2	; CF
JCC_NC	equ 3	; !CF
JCC_NB	equ 3	; !CF
JCC_AE	equ 3	; !CF
JCC_Z	equ 4	; ZF
JCC_E	equ 4	; ZF
JCC_NZ	equ 5	; !ZF
JCC_NE	equ 5	; !ZF
JCC_NA	equ 6	; CF | ZF
JCC_BE	equ 6	; CF | ZF
JCC_A	equ 7	; !CF & !ZF
JCC_NBE	equ 7	; !CF & !ZF
JCC_S	equ 8	; SF
JCC_NS	equ 9	; !SF
JCC_P	equ 0AH	; PF
JCC_PE	equ 0AH	; PF
JCC_NP	equ 0BH	; !PF
JCC_PO	equ 0BH	; !PF
JCC_L	equ 0CH	; SF != OF
JCC_NGE	equ 0CH	; SF != OF
JCC_NL	equ 0DH	; SF = OF
JCC_GE	equ 0DH	; SF = OF
JCC_NG	equ 0EH	; ZF | (SF != OF)
JCC_LE	equ 0EH	; ZF | (SF != OF)
JCC_G	equ 0FH	; !ZF & (SF = OF)
JCC_NLE	equ 0FH	; !ZF & (SF = OF)

; o Jump short: 0x70 + JCC_*
; o Jump near: 0x0F 0x80 + JCC_*

JCC_LOOPNE	equ 0E0H	; Ecx & !ZF
JCC_LOOPE		equ 0E1H	; Ecx & ZF
JCC_LOOP		equ 0E2H	; Ecx
JCC_ECXZ		equ 0E3H	; !Ecx

JCX_OPCODE_BASE	equ 0E0H

JCC_TYPE_MASK	equ 00001111B	; BLOCK_HEADER.KitFlags
EhJccType	equ BLOCK_HEADER.KitFlags	; JCC_TYPE_MASK
JCC_X16_MASK	equ 00010000B	; BLOCK_HEADER.KitFlags, Pfx 0x67

BRANCH_DELTA_SIGN	equ 00100000B	; Знак смещения(0: +, 1: -).

EhBranchOffset	equ EhUserData	; Смещение ветвления в собираемом коде.

FLOW_UNLINK_MARK	equ 01000000B	; Флаг используется при удалении ветвей.
EhFlowMark	equ BLOCK_HEADER.KitFlags	; FLOW_UNLINK_MARK