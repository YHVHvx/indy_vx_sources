; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; o Урезанный движок, только базовый парсер.
; o Не линейный граф, конвертор исключён.
;
	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib

GP_LINK_VALIDATION	equ TRUE	; for GpSwitchThread()

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
GP_CS_CHECK_IP_BELONG_TO_SNAPSHOT		4	3
GP_RW_CHECK_IP_BELONG_TO_SNAPSHOT		5	4
GP_FIND_CALLER_BELONG_TO_SNAPSHOT		6	6
GP_CS_SEARCH_ROUTINE_ENTRY			7	5
	'
GCBE_MAX_SERVICE		equ 8

; Не сохраняются Ecx и Edx.
;
GpStub proc C
	btr eax,OPT_EXTERN_SEH_BIT
	jc Gate
	cmp eax,GCBE_MAX_SERVICE
	jnb Limit
	mov ecx,eax
	mov edx,56434911H	; [0%7]
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
	jz GpParse
	dec eax
	jz RwTrace
	dec eax
	jz CsCheckIpBelongToSnapshot
	dec eax
	jz RwCheckIpBelongToSnapshot
	dec eax
	jz RwFindCallerBelongToSnapshot
	dec eax
	jz CsSearchRoutineEntry
Limit:
	mov eax,STATUS_ILLEGAL_FUNCTION
	ret
GpStub endp

	%GET_GRAPH_REFERENCE
	
	include VirXasm32b.asm
	include GrpParse.asm
	include GrpTrace.asm
	include GrpSnap.asm

end GpStub