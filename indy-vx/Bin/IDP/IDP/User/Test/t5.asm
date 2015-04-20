; \IDP\Public\User\Test\t5.asm
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

.data
align_	byte 3 dup (?)
Space	dd 123456H
		
Ref1	dd offset Space
Ref2	dd offset Space + 1
Ref3	dd offset Space + 2
Ref4	dd offset Space + 100
Ref5	dd offset Space + 0ABCDH
Ref6	dd offset Space - 1

.code
	include ..\Engine\mi\idp.inc
	
ExceptionDispatcher proc ExceptionPointers:PEXCEPTION_POINTERS
	assume fs:nothing
	mov eax,ExceptionPointers
	mov ecx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume ecx:PEXCEPTION_RECORD
	mov edx,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edx:PCONTEXT
	cmp [ecx].ExceptionFlags,NULL
	jnz chain_
	cmp [ecx].ExceptionCode,IDP_BREAKPOINT
	je cont_
	cmp [ecx].ExceptionCode,IDP_SINGLE_STEP
	je cont_
;	...
chain_:
	xor eax,eax
	ret
cont_:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	ret
ExceptionDispatcher endp

Entry proc
	assume fs:nothing
	mov eax,IDP_INITIALIZE_ENGINE
	Call IDP
	BREAKERR
	push 4
	push offset Ref1
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	push 4
	push offset Ref2
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	push 4
	push offset Ref3
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	push 4
	push offset Ref4
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	push 4
	push offset Ref5
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	push 4
	push offset Ref6
	mov eax,IDP_ADD_REFERENCE
	Call IDP
	BREAKERR
	ret
Entry endp
end Entry

comment '
; @Ref1
$ ==>    00402007  00402003
$+4      0040200B  00402004
$+8      0040200F  00402005
$+C      00402013  00402067
$+10     00402017  0040CBD0
$+14     0040201B  00402002

$ ==>    00402007  00000003
$+4      0040200B  00001004
$+8      0040200F  00002005
$+C      00402013  00002067
$+10     00402017  00002BD0
$+14     0040201B  00003002

> ldt
LDTBase=815E1000  Limit=37
Sel.  Type      Base      Limit     DPL  Attributes
0004  Reserved  00000000  00000000  0    NP
000F  Data32    00402000  7FBEDFFF  3    P   RW
0017  Data32    00401000  7FBEDFFF  3    P   RW
001F  Data32    00400000  7FBEDFFF  3    P   RW
0027  Data32    00400000  7FBEDFFF  3    P   RW
002F  Data32    0040A000  7FBE3FFF  3    P   RW
0037  Data32    003FF000  7FBEDFFF  3    P   RW
'