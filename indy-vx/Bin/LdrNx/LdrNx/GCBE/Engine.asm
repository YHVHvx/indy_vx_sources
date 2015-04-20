; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

GP_LINK_VALIDATION	equ TRUE	; for GpSwitchThread()

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
GP_PARSE							2	9
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
	mov edx,74344911H	; [0%7]
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
end GpStub