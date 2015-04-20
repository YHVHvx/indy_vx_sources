; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

GP_LINK_VALIDATION	equ TRUE	; for GpSwitchThread()

;FLG_ENABLE_SEH	equ TRUE

GCBE_PARSE_NL_UNLIMITED	equ -2
GCBE_PARSE_NL_PRIMARY	equ 0

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

%GPCALL macro Service, Opt
	ifdef Opt
	   mov eax,Service or Opt
	else
	   mov eax,Service
	endif
	Call GpStub
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
GP_BUILD							4	4
GP_CS_CHECK_IP_BELONG_TO_SNAPSHOT		5	3
GP_RW_CHECK_IP_BELONG_TO_SNAPSHOT		6	4
GP_FIND_CALLER_BELONG_TO_SNAPSHOT		7	7
GP_CS_UNLINK_ENTRY					8	3
GP_CS_INSERT_HEAD_ENTRY				9	4
GP_RW_UNLINK_FLOW					10	1
GP_MERGE							11	2
GP_SWITCH_THREAD					12	10
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
	mov edx,74344A11H	; [0%7]
	test eax,eax
	.if !Zero?
;		dec eax
;		.if Zero?
		mov edx,0A2143H	; [8%15]
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
Limit:
	mov eax,STATUS_ILLEGAL_FUNCTION
	ret
	
GpStub endp

	%GET_GRAPH_REFERENCE

	include SEH.inc
	include VirXasm32b.asm
	include GrpKit.asm
	include GrpTrace.asm
	include GrpSnap.asm
	include GrpLink.asm
	include GrpFlow.asm
	include GrpCross.asm
	include GrpJcx.asm
	include GrpBuild.asm
	include GrpSwitch.asm	

_imp__ZwRaiseHardError proto :dword, :dword, :dword, :dword, :dword, :dword

; ??? Включить морф импорта.

TestIp proc
Local Response:ULONG
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
	ret
Stub:
	Call Gate
	retn 6*4
Gate:
	mov edx,esp
	db 0FH, 34H	; Sysenter
	retn
TestIp endp

	includelib \masm32\lib\ntdll.lib
	
SNAPS struct
RwSnap	GP_SNAPSHOT <>	; Нелинейный граф.
CsSnap	GP_SNAPSHOT <>	; Линейный граф для билдера.
BdSnap	GP_SNAPSHOT <>	; Выходной буфер.
SNAPS ends
PSNAPS typedef ptr SNAPS

GpInitialize proc uses ebx esi edi
Local GpSize:ULONG
Local Sn:SNAPS
	lea ebx,Sn.RwSnap
	mov Sn.RwSnap.GpBase,eax
	mov GpSize,16 * X86_PAGE_SIZE
	Call Alloc
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
	test eax,eax
	jnz RwFree	; #AV etc.
; Аллоцируем буфера для конвертора и билдера.
	lea ebx,Sn.CsSnap
	mov Sn.CsSnap.GpBase,eax
	mov GpSize,16 * X86_PAGE_SIZE
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
	%GPCALL 4	; GP_BUILD
	test eax,eax
	jnz Exit
	
	Int 3
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