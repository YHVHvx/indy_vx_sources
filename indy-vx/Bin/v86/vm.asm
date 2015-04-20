; Indy, 2011
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

.code
; NtVdmControl:
;	- VdmQueryVdmProcess
;	- Is PS_PROCESS_FLAGS_VDM_ALLOWED	; ProcessWx86Information
;	- VdmInitialize	; Process->VdmObjects
;	- Is Process->VdmObjects
;	- Vdm*

; Флаг PS_PROCESS_FLAGS_VDM_ALLOWED устанавливается в ProcessWx86Information, 
; для чего требуется TCB-привилегия. Вызывается из Csrss как BasepUpdateVDMEntry(BaseSrvUpdateVDMEntry()).
; Для последнего сервиса имеется стаб kernel32!VDMOperationStarted().
;
; VOID VDMOperationStarted(BOOL IsWowCaller);

CSR_API_NUMBER struct
Index	WORD ?	; CSR-service ID.
Subsystem	WORD ?
CSR_API_NUMBER ends

BASESRV_SERVERDLL_INDEX	equ 1

CSR_CAPTURE_HEADER struct
_Length				ULONG ?
RelatedCaptureBuffer	PVOID ?	; PCSR_CAPTURE_HEADER
CountMessagePointers	ULONG ?	
FreeSpace				PCHAR ?
MessagePointerOffsets	ULONG 1 DUP (?)	; Offsets within CSR_API_MSG of pointers
CSR_CAPTURE_HEADER ends
PCSR_CAPTURE_HEADER typedef ptr CSR_CAPTURE_HEADER

USER_API_MSG struct
h			PORT_MESSAGE <>
CaptureBuffer	PCSR_CAPTURE_HEADER <>	; +0x18
ApiNumber		CSR_API_NUMBER <>	; +0x1C
ReturnValue	ULONG ?	; +0x20
Reserved		ULONG ?	; +0x24
; +0x28
USER_API_MSG ends

BasepUpdateVDMEntry			equ 6

comment '
NTSTATUS CsrClientCallServer(
    IN OUT PCSR_API_MSG m,
    IN OUT PCSR_CAPTURE_HEADER CaptureBuffer OPTIONAL,
    IN CSR_API_NUMBER ApiNumber,
    IN ULONG ArgLength
    );
    '

PCSR_API_MSG typedef ptr USER_API_MSG

CsrClientCallServer proto :ULONG, :ULONG, :ULONG, :ULONG

BASE_UPDATE_VDM_ENTRY_MSG struct
iTask			DWORD ?
BinaryType		DWORD ?	; +4
ConsoleHandle		HANDLE ?	; +8
VDMProcessHandle	HANDLE ?	; +0xC
WaitObjectForParent	HANDLE ?	; +0x10
EntryIndex		WORD ?	; +0x14
VDMCreationState	WORD ?	; +0x18
BASE_UPDATE_VDM_ENTRY_MSG ends
PBASE_UPDATE_VDM_ENTRY_MSG typedef ptr BASE_UPDATE_VDM_ENTRY_MSG

comment '
NTSTATUS
NtVdmControl (
    IN VDMSERVICECLASS Service,
    IN OUT PVOID ServiceData
    );
    '
    
NtVdmControl proto :ULONG, :PVOID

; VDMSERVICECLASS
VdmStartExecution		equ 0
VdmQueueInterrupt		equ 1
VdmDelayInterrupt		equ 2
VdmInitialize			equ 3
VdmFeatures			equ 4
VdmSetInt21Handler		equ 5
VdmQueryDir			equ 6
VdmPrinterDirectIoOpen	equ 7
VdmPrinterDirectIoClose	equ 8
VdmPrinterInitialize	equ 9
VdmSetLdtEntries		equ 10
VdmSetProcessLdtInfo	equ 11
VdmAdlibEmulation		equ 12
VdmPMCliControl		equ 13
VdmQueryVdmProcess		equ 14

; VdmQueryVdmProcess
VDM_QUERY_VDM_PROCESS_DATA struct
ProcessHandle	HANDLE ?
IsVdmProcess	BOOLEAN ?		; BOOL.
VDM_QUERY_VDM_PROCESS_DATA ends

; VdmSetLdtEntries
VDMSET_LDT_ENTRIES_DATA struct
Selector0		ULONG ?
Entry0Low		ULONG ?
Entry0Hi		ULONG ?
Selector1		ULONG ?
Entry1Low		ULONG ?
Entry1Hi		ULONG ?
VDMSET_LDT_ENTRIES_DATA ends

; VdmSetProcessLdtInfo
VDMSET_PROCESS_LDT_INFO_DATA struct
LdtInformation			PVOID ?	; PPROCESS_LDT_INFORMATION
LdtInformationLength	ULONG ?
VDMSET_PROCESS_LDT_INFO_DATA ends

; VdmSetInt21Handler
VDMSET_INT21_HANDLER_DATA struct
Selector		ULONG ?	; Валидация селектора в Ki386GetSelectorParameters(), Process->LdtDescriptor должен быть установлен.
_Offset		ULONG ?
Gate32		BOOLEAN ?
VDMSET_INT21_HANDLER_DATA ends
PVDMSET_INT21_HANDLER_DATA typedef ptr VDMSET_INT21_HANDLER_DATA

PVDMVIRTUALICA typedef PVOID

VDMICAUSERDATA struct
pIcaLock			PRTL_CRITICAL_SECTION ?
pIcaMaster		PVDMVIRTUALICA ?
pIcaSlave			PVDMVIRTUALICA ?
pDelayIrq			PULONG ?
pUndelayIrq		PULONG ?
pDelayIret		PULONG ?
pIretHooked		PULONG ?
pAddrIretBopTable	PULONG ?
phWowIdleEvent		PHANDLE ?
pIcaTimeout		PLARGE_INTEGER ?
phMainThreadSuspended	PHANDLE ?
VDMICAUSERDATA ends
PVDMICAUSERDATA typedef ptr VDMICAUSERDATA

VDMVIRTUALICA struct
ica_count		LONG 8 DUP (?)
ica_int_line	LONG ?
ica_cpu_int	LONG ?
ica_base		USHORT ?
ica_hipri		USHORT ?
ica_mode		USHORT ?
ica_master	UCHAR ?
ica_irr		UCHAR ?
ica_isr		UCHAR ?
ica_imr		UCHAR ?
ica_ssr		UCHAR ?
VDMVIRTUALICA ends

; VdmInitialize
VDM_INITIALIZE_DATA struct
TrapcHandler	PVOID ?
IcaUserData	PVDMICAUSERDATA ?
VDM_INITIALIZE_DATA ends

ThVdm		equ 0F18H	; TEB.Vdm
VDM_TIB_SIZE	equ 674H	; sizeof(VDM_TIB)

FIXED_NTVDMSTATE_LINEAR	equ 714H	; Ki386VdmReflectException -> VdmFetchULONG().

VDM_BREAK_EXCEPTIONS	equ 8H
VDM_BREAK_DEBUGGER		equ 10H
VDM_USE_DBG_VDMEVENT	equ 4000H

CR	equ 13
LF	equ 10

%NTERR macro
	.if Eax
		Int 3
	.endif
endm

%APIERR macro
	.if !Eax
		Int 3
	.endif
endm

$BasepUpdateVDMEntry	CHAR "BasepUpdateVDMEntry(): 0x%X", CR, LF, 0
$VdmAllowedFlags		CHAR "PS_PROCESS_FLAGS_VDM_ALLOWED = %X", CR, LF, 0
$IsVdm				CHAR "IsVdmProcess: %X", CR, LF, 0

.data
IcaUserData	VDMICAUSERDATA <\
	offset IcaLock, \
	offset IcaMaster, \
	offset IcaSlave, \
	offset DelayIrq, \
	offset UndelayIrq, \
	offset DelayIret, \
	offset IretHooked, \
	offset AddrIretBopTable, \
	offset hWowIdleEvent, \
	offset IcaTimeout, \
	offset hMainThreadSuspended>
	
IcaLock			RTL_CRITICAL_SECTION <>
IcaMaster			VDMVIRTUALICA <>
IcaSlave			VDMVIRTUALICA <>
DelayIrq			ULONG ?
UndelayIrq		ULONG ?
DelayIret			ULONG ?
IretHooked		ULONG ?
AddrIretBopTable	ULONG ?
hWowIdleEvent		HANDLE ?
IcaTimeout		LARGE_INTEGER <>
hMainThreadSuspended	HANDLE ?

VdmInit	VDM_INITIALIZE_DATA <, offset IcaUserData>

Ldt		VDMSET_LDT_ENTRIES_DATA <LDT_SEL,,,,,>

.code
MM_SHARED_USER_DATA_VA	equ 7FFE0000H

TABLE_MASK	equ 100B
LDT_SEL		equ KGDT_R3_CODE or RPL_MASK or TABLE_MASK

CREATE_DESCRIPTOR macro Base, Limit
	mov eax,Base
	mov edx,Limit
	mov ecx,eax
	and edx,0F0000H
	shr eax,16
	and ecx,0FF000000h
	and eax,0FFH
	lea edx,[eax + edx + 100H * 11111000B + 100000H * 1100B]	; Type 100B - code.
	or edx,ecx
	mov eax,Limit
	mov ecx,Base
	and eax,0FFFFH
	shl ecx,16
	lea ecx,[ecx + eax]
; Edx:Ecx
endm

Int21Handler proc C
;	and dword ptr [esp + 2*4],NOT(EFLAGS_TF)
	invoke Beep, 1000, 1000
	iretd
Int21Handler endp

	assume fs:nothing
Ip proc
Local Msg[sizeof(USER_API_MSG) + sizeof(BASE_UPDATE_VDM_ENTRY_MSG)]:BYTE
Local VdmAllowedFlags:DWORD, Vdm:VDM_QUERY_VDM_PROCESS_DATA
Local RegionBase:PVOID, RegionSize:ULONG
Local Int21Data:VDMSET_INT21_HANDLER_DATA

; --
; BaseSrvUpdateVDMEntry() вначале копирует описатель VDMProcessHandle в Csrss посредством NtDuplicateObject, 
; только при успешном копировании будет вызван ProcessWx86Information. Описатель процесса должен быть валиден, 
; остальные аргументы используются в BaseSrvUpdateWOWEntry()/BaseSrvUpdateDOSEntry().
;
; * BUGBUG:
; * Тип возвращаемого значения из BaseSrvUpdateVDMEntry() - BOOL для NtDuplicateObject/NtSetInformationProcess, 
;   NTSTATUS для BaseSrvUpdateWOWEntry()BaseSrvUpdateDOSEntry().

	invoke OpenProcess, PROCESS_ALL_ACCESS, FALSE, fs:[TEB.Cid.UniqueProcess]
	%APIERR
	mov BASE_UPDATE_VDM_ENTRY_MSG.VDMProcessHandle[Msg + sizeof(USER_API_MSG)],eax

	mov BASE_UPDATE_VDM_ENTRY_MSG.iTask[Msg + sizeof(USER_API_MSG)],NULL
	mov BASE_UPDATE_VDM_ENTRY_MSG.BinaryType[Msg + sizeof(USER_API_MSG)],FALSE	; IsWowCaller

; При передаче нулевого хэндла консоли BaseSrvGetConsoleRecord() возвратит STATUS_INVALID_PARAMETER.
	mov BASE_UPDATE_VDM_ENTRY_MSG.ConsoleHandle[Msg + sizeof(USER_API_MSG)],NULL
	
	invoke CsrClientCallServer, addr Msg, NULL, (BASESRV_SERVERDLL_INDEX shl 16) or BasepUpdateVDMEntry, sizeof Msg
	
	invoke DbgPrint, addr $BasepUpdateVDMEntry, Eax	; STATUS_INVALID_PARAMETER
	
	invoke ZwQueryInformationProcess, NtCurrentProcess, ProcessWx86Information, addr VdmAllowedFlags, 4, NULL
	%NTERR
	invoke DbgPrint, addr $VdmAllowedFlags, VdmAllowedFlags
	
	mov RegionBase,4
	mov RegionSize,PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr RegionBase, 0, addr RegionSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
	%NTERR
	
	mov RegionBase,eax
	mov RegionSize,VDM_TIB_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr RegionBase, 0, addr RegionSize, MEM_COMMIT, PAGE_READWRITE
	mov ecx,RegionBase
	%NTERR
	
; Make VDM TIB(for VdmpGetVdmTib()).
; ntvdm!host_CreateThread()..
	mov dword ptr fs:[ThVdm],ecx
	mov dword ptr [ecx],VDM_TIB_SIZE
	
	invoke NtVdmControl, VdmInitialize, addr VdmInit
	mov ecx,RegionBase
	%NTERR
	
	mov dword ptr fs:[ThVdm],ecx
	mov dword ptr [ecx],VDM_TIB_SIZE

	mov Vdm.ProcessHandle,NtCurrentProcess
	invoke NtVdmControl, VdmQueryVdmProcess, addr Vdm
	%NTERR
	movzx ecx,byte ptr [Vdm.IsVdmProcess]
	invoke DbgPrint, addr $IsVdm, Ecx
	
	CREATE_DESCRIPTOR 0, MM_SHARED_USER_DATA_VA/PAGE_SIZE	; Dyn.
	
	mov Ldt.Entry0Low,ecx
	mov Ldt.Entry0Hi,edx

	invoke NtVdmControl, VdmSetLdtEntries, addr Ldt
	%NTERR
	
	mov Int21Data.Selector,LDT_SEL
	mov Int21Data._Offset,offset Int21Handler
	mov Int21Data.Gate32,TRUE
	invoke NtVdmControl, VdmSetInt21Handler, addr Int21Data
	%NTERR
	
	and dword ptr ds:[FIXED_NTVDMSTATE_LINEAR],NOT(VDM_BREAK_EXCEPTIONS or VDM_BREAK_DEBUGGER or VDM_USE_DBG_VDMEVENT)	; Dbg(STATUS_SEGMENT_NOTIFICATION).
	
	Int 21H

	ret
Ip endp
end Ip