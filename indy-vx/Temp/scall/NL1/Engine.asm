; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
OPT_ENABLE_DBG_LOG	equ TRUE
GP_LINK_VALIDATION	equ TRUE	; for GpSwitchThread()

OPT_NX_SEHGATE	equ TRUE
FLG_ENABLE_SEH	equ TRUE

GCBE_NL_UNLIMITED	equ -2
GCBE_NL_PRIMARY	equ 0

GCBE_PARSE_NL_UNLIMITED	equ GCBE_NL_UNLIMITED
GCBE_PARSE_NL_PRIMARY	equ GCBE_NL_PRIMARY

%GPCALL macro Service, Opt
	ifdef Opt
	   mov eax,Service or Opt
	else
	   mov eax,Service
	endif
	Call GpStub
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

	assume fs:nothing
.code
OPT_EXTERN_SEH_MASK		equ 10000000B
OPT_EXTERN_SEH_BIT		equ 7

comment '
	Name							Id	Args
GP_LDE							0	1
GP_PFX							1	1
GP_PARSE							2	10
GP_TRACE							3	4
GP_BUILD							4	5
GP_CS_CHECK_IP_BELONG_TO_SNAPSHOT		5	3
GP_RW_CHECK_IP_BELONG_TO_SNAPSHOT		6	5
GP_FIND_CALLER_BELONG_TO_SNAPSHOT		7	6
GP_CS_UNLINK_ENTRY					8	3
GP_CS_INSERT_HEAD_ENTRY				9	4
GP_RW_UNLINK_FLOW					10	1
GP_MERGE							11	2
GP_SWITCH_THREAD					12	10
RW)IS_VALID_CALLER					13	3
	'
GCBE_MAX_SERVICE		equ 13

; Не сохраняются Ecx и Edx.
;
GpStub proc C
	btr eax,OPT_EXTERN_SEH_BIT
	jc Gate
	cmp eax,GCBE_MAX_SERVICE
	jnb Limit
	mov ecx,eax
	shr eax,3	; /8
	mov edx,65354A11H	; [0%7]
	test eax,eax
	.if !Zero?
;		dec eax
;		.if Zero?
		mov edx,03A2143H	; [8%15]
;		.else
;			mov edx,0H	; [16%31]
;		.endif
	.endif
	mov eax,ecx
	push ebx
	and cl,1111B	; Nibl id.
	push esi
	shl ecx,2
	push edi
	shr edx,cl
	and edx,1111B	; Arg's
; ^
	push edx
	push ebp
	Call @f
Safe:
	pop dword ptr fs:[0]
	lea esp,[esp + 2*4]
	pop ebp
	pop ecx	; Arg's
	pop edi
	pop esi
	pop ebx
	pop edx	; Ip
	lea esp,[esp + 4*ecx]
	Jmp edx	
@@:
	Call @f
; SEH
	mov eax,dword ptr [esp + 4]
	mov esp,dword ptr [esp + 2*4]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	Jmp Safe
@@:
	push dword ptr fs:[0]
	mov ecx,edx
	mov dword ptr fs:[0],esp
	test edx,edx
	.if !Zero?
		.repeat
			push dword ptr [esp + 4*edx + 4*9 - 4]	; SEH(Next, Ip, Ip', Esp), Ebx, Esi, Edi, Arg's, Ip.
			dec ecx
		.until Zero?
	.endif 
	Call Gate
	jmp Safe
Gate:
	test eax,eax
	jz QueryOpcodeSize
	dec eax
	jz QueryPrefixLength
	dec eax
	jz GpKit
	dec eax
	jz RwTrace
	dec eax
	jz GpBuildGraph
	dec eax
	jz CsCheckIpBelongToSnapshot
	dec eax
	jz RwCheckIpBelongToSnapshot
	dec eax
	jz GpFindCallerBelongToSnapshot
	dec eax
	jz CsUnlinkEntry
	dec eax
	jz CsInsertHeadEntry
	dec eax
	jz RwUnlinkFlow
	dec eax
	jz RwConvertRawTableToCrossTable
	dec eax
	jz GpSwitchThread
	dec eax
	jz RwIsValidCaller
Limit:
	mov eax,STATUS_ILLEGAL_FUNCTION
	ret
	
GpStub endp

	%GET_GRAPH_REFERENCE
	
	include VirXasm32b.asm
	include GrpKit.asm
	include GrpTrace.asm
	include GrpLink.asm
	include GrpFlow.asm
	include GrpCross.asm
	include GrpJcx.asm
	include GrpSnap.asm
	
	include HDR.inc
	include Img.asm
; %GETENVPTR
	include Envir.asm
	
	include ApiGate.asm
	include EvUtils.asm
	
; OPT_SYSGATE_IDT
; OPT_SYSGATE_IDT_PCR
; OPT_SYSGATE_FAST_SEARCH
	include MI_SYS.asm
	include GrpBuild.asm	
	
	include GrpSwitch.asm
	
;	include OUTF.asm
;	include STBAL.asm

; OPT_NX_SEHGATE
	include XcptNx.asm

.code
		includelib \masm32\lib\ntdll.lib

_imp__ZwRaiseHardError proto :dword, :dword, :dword, :dword, :dword, :dword

$Time	CHAR "dT: 0x%X", 13, 10, 0

TestIp proc
Local Response:ULONG
	int 3
; dTick's
	Int 2AH
	mov ebx,eax
	invoke Sleep, 500
	Int 2AH
	sub eax,ebx
	invoke DbgPrint, addr $Time, Eax
; Int 0x2E
	lea eax,Response
	push eax
	push OptionOkCancel
	push 0
	push 0
	push 1
	push STATUS_SUCCESS
	mov eax,dword ptr [_imp__ZwRaiseHardError]
	mov eax,dword ptr [eax + 1]	; Id
	mov edx,esp
	Int 2Eh
	add esp,6*4
	
; Sysenter
	lea eax,Response
	push eax
	push OptionOkCancel
	push 0
	push 0
	push 1
	push STATUS_SUCCESS
	mov eax,dword ptr [_imp__ZwRaiseHardError]
	mov eax,dword ptr [eax + 1]	; Id
	Call Stub
	
; STPT ENGINE:
	lea eax,Response
	push eax
	push OptionOkCancel
	push 0
	push 0
	push 1
	push STATUS_SUCCESS
	%APICALL dword ptr [_imp__ZwRaiseHardError], 6
	ret
Stub:
	Call Gate
	retn 6*4
Gate:
	mov edx,esp
	db 0FH, 34H	; Sysenter
	retn
TestIp endp

SNAPS struct
RwSnap	GP_SNAPSHOT <>	; Нелинейный граф.
CsSnap	GP_SNAPSHOT <>	; Линейный граф для билдера.
BdSnap	GP_SNAPSHOT <>	; Выходной буфер.
SNAPS ends
PSNAPS typedef ptr SNAPS

.data
gVar	db 30 dup (?)

ifdef OPT_ENABLE_DBG_LOG
$GpInitialize_Alloc1	CHAR "GpInitialize.Alloc1: 0x%X", CRLF
$GpInitialize_Alloc2	CHAR "GpInitialize.Alloc2: 0x%X", CRLF
$GpInitialize_Alloc3	CHAR "GpInitialize.Alloc3: 0x%X", CRLF
$GpInitialize_GP_PARSE	CHAR "GpInitialize.GP_PARSE: 0x%X", CRLF
$GpInitialize_GP_BUILD	CHAR "GpInitialize.GP_BUILD: 0x%X", CRLF
endif

.code

xgen proc
	%SEHPROLOGEX
	cli
	%SEHEPILOG
	ret
xgen endp

GpInitialize proc uses ebx esi edi
Local GpSize:ULONG
Local Sn:SNAPS
Local Info:SYSSTUB
	Call xgen
	int 3
	
	push 0;GCBE_BUILD_CROSS_UNLINK
	Call NxInit
	cli

;	lea eax,Sn
;	push eax
;	push OptionOkCancel
;	push 0
;	push 0
;	push 1
;	push STATUS_SUCCESS
;	%APICALL dword ptr [_imp__ZwRaiseHardError], 6


	lea ebx,Sn.RwSnap
	mov Sn.RwSnap.GpBase,eax
	mov GpSize,16 *  2 * X86_PAGE_SIZE
	Call Alloc
	%DBG $GpInitialize_Alloc1, Eax
	jnz Exit
	lea ecx,Sn.RwSnap.GpLimit
	push eax
	push eax
	push eax
	push eax
	push eax
	push -2
	push GCBE_PARSE_IPCOUNTING or GCBE_PARSE_SEPARATE
	push eax
	push ecx
	push offset TestIp
	%GPCALL 2	; GP_PARSE	; !OPT_EXTERN_SEH_MASK - расширяемый буфер не используем.
	%DBG $GpInitialize_GP_PARSE, Eax
	test eax,eax
	jnz RwFree	; #AV etc.
; Аллоцируем буфера для конвертора и билдера.
	lea ebx,Sn.CsSnap
	mov Sn.CsSnap.GpBase,eax
	mov GpSize,16 * 2 * X86_PAGE_SIZE
	Call Alloc
	%DBG $GpInitialize_Alloc2, Eax
	jnz StFree
	lea ebx,Sn.BdSnap
	mov Sn.BdSnap.GpBase,eax
	mov GpSize,16 *  2 * X86_PAGE_SIZE	; < 2p
	Call Alloc
	%DBG $GpInitialize_Alloc3, Eax
	jnz CsFree

	Int 3
	
	push GCBE_BUILD_CROSS_UNLINK \
		or GCBE_BUILD_MORPH_SYSENTER \
		or GCBE_BUILD_MORPH_INT2E \
		or GCBE_BUILD_MORPH_INT2A \
		or GCBE_BUILD_MORPH_RDTSC
	push Sn.BdSnap.GpBase
	push Sn.CsSnap.GpBase
	push Sn.RwSnap.GpLimit
	push Sn.RwSnap.GpBase
	%GPCALL 4	; GP_BUILD
	%DBG $GpInitialize_GP_BUILD, Eax
	test eax,eax
	jnz Exit
	
	invoke EvFree, Sn.CsSnap.GpBase
	
	Call Sn.BdSnap.GpBase
	jmp Exit
	
BdFree:
	lea ebx,Sn.BdSnap
	Call AllocFree
CsFree:
	lea ebx,Sn.CsSnap
	Call AllocFree
StFree:
	Call AllocFree
RwFree:
	lea ebx,Sn.RwSnap
	Call AllocFree
Exit:
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
	Call ZwAllocateVirtualMemory
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
	Call ZwProtectVirtualMemory
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
	Call ZwFreeVirtualMemory
	pop eax
	test eax,eax
	retn
GpInitialize endp
end GpInitialize