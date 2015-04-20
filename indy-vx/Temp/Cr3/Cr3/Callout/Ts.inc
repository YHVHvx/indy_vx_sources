KTRAP_FRAME_LENGTH equ 0008CH

; Trap Frame Offset Definitions
;
TsDr0	equ 00018H
TsDr1	equ 0001CH
TsDr2	equ 00020H
TsDr3	equ 00024H
TsDr6	equ 00028H
TsDr7	equ 0002CH
TsSegGs	equ 00030H
TsSegEs	equ 00034H
TsSegDs	equ 00038H
TsEdx	equ 0003CH
TsEcx	equ 00040H
TsEax	equ 00044H
TsSegFs	equ 00050H
TsEdi	equ 00054H
TsEsi	equ 00058H
TsEbx	equ 0005CH
TsEbp	equ 00060H
; IRET-frame.
TsEip	equ 00068H
TsSegCs	equ 0006CH
TsEflags	equ 00070H
TsHardwareEsp		equ 00074H
TsHardwareSegSs	equ 00078H

KTRAP_FRAME struct
DbgEbp		ULONG ?
DbgEip		ULONG ?
DbgArgMark	ULONG ?
DbgArgPointer	ULONG ?

TempSegCs		ULONG ?
TempEsp		ULONG ?

rDr0			ULONG ?
rDr1			ULONG ?
rDr2			ULONG ?
rDr3			ULONG ?
rDr6			ULONG ?
rDr7			ULONG ?

SegGs		ULONG ?
SegEs		ULONG ?
SegDs		ULONG ?

rEdx			ULONG ?
rEcx			ULONG ?
rEax			ULONG ?

PreviousPreviousMode	ULONG ?

ExceptionList	PVOID ?

SegFs		ULONG ?

rEdi			ULONG ?
rEsi			ULONG ?
rEbx			ULONG ?
rEbp			ULONG ?

; IRET-frame.
ErrCode		ULONG ?
rEip			ULONG ?
rSegCs		ULONG ?
rEFlags		ULONG ?

HardwareEsp	ULONG ?
HardwareSegSs	ULONG ?

V86Es		ULONG ?
V86Ds		ULONG ?
V86Fs		ULONG ?
V86Gs		ULONG ?
KTRAP_FRAME ends
PKTRAP_FRAME typedef ptr KTRAP_FRAME

;
; Usermode callout frame.
;
CALLOUT_FRAME struct
InitialStack	PVOID ?
TrapFrame		PKTRAP_FRAME ?
CallbackStack	PVOID ?	; PCALLBACK_STACK
rEdi			DWORD ?
rEsi			DWORD ?
rEbx			DWORD ?
rEbp			DWORD ?
rEip			DWORD ?
Buffer		PVOID ?
BufferLength	ULONG ?
CALLOUT_FRAME ends
PCALLOUT_FRAME typedef ptr CALLOUT_FRAME

; ETHREAD.CalloutStack:PCALLOUT_FRAME
;
ThCallbackStack	equ 12CH	; XP

; KTRAP_FRAME.rEip
;
TsEip	equ 00068H

; ~
; Eax: PETHREAD
;	mov eax,dword ptr [eax + ThCallbackStack]
;	.if Eax
;	mov eax,CALLOUT_FRAME.TrapFrame[eax]
;	mov eax,dword ptr [eax + TsEip]
;	.endif