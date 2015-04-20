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

ErrCode		ULONG ?
rEip			ULONG ?
rSegCs		ULONG ?
rEFlags		ULONG ?

; WARNING - Ss:Esp are only here for stacks that involve a ring transition.
HardwareEsp	ULONG ?
HardwareSegSs	ULONG ?

V86Es		ULONG ?
V86Ds		ULONG ?
V86Fs		ULONG ?
V86Gs		ULONG ?
KTRAP_FRAME ends
PKTRAP_FRAME typedef ptr KTRAP_FRAME

KEXCEPTION_FRAME typedef KTRAP_FRAME
PKEXCEPTION_FRAME typedef PKTRAP_FRAME

KTRAP_FRAME_LENGTH	equ sizeof(KTRAP_FRAME)

KTRAP_FRAME_ALIGN	equ sizeof(ULONG)
KTRAP_FRAME_ROUND	equ (KTRAP_FRAME_ALIGN - 1)

KPROCESSOR_MODE	typedef ULONG

X86_PAGE_SIZE	equ 1000H

KernelMode	equ 0
UserMode		equ 1
MODE_MASK		equ 1

PbEnvironment	equ (X86_PAGE_SIZE - 4)

OPCODE_CALL	equ 0E8H
OPCODE_RET	equ 0C3H

MODRM_MOD_MASK		equ 11000000B
MODRM_REG_MASK		equ 00111000B
MODRM_RM_MASK		equ 00000111B