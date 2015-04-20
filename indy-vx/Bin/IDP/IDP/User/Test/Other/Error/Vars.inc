; Position Independent, only for test!
;
$LOAD macro Reg32, Variable
Local dt_
	Call dt_
dt_:
	pop Reg32
	mov Reg32,dword ptr [Reg32 + (offset Variable - offset dt_)]
endm

$SAVE macro Variable, Value
Local dt_
	Call dt_
dt_:
	pop eax
	mov dword ptr [eax + (offset Variable - offset dt_)],Value
endm

$PUSH macro Variable
Local dt_
	Call dt_
dt_:
	pop eax
	push dword ptr [eax + (offset Variable - offset dt_)]
endm

$POP macro Variable
Local dt_
	Call dt_
dt_:
	pop eax
	pop dword ptr [eax + (offset Variable - offset dt_)]
endm

$GET_REF macro Reg32, Variable
Local dt_
	Call dt_
dt_:
	pop Reg32
	lea Reg32,dword ptr [Reg32 + (offset Variable - offset dt_)]
endm

$PUSH_REF macro Variable
Local dt_
	Call dt_
dt_:
	add dword ptr [esp],(offset Variable - offset dt_)
endm

$CALL macro Variable
Local dt_
	Call dt_
dt_:
	pop eax
	Call dword ptr [eax + (offset Variable - offset dt_)]
endm

$JMP macro Variable
Local dt_
	Call dt_
dt_:
	pop eax
	jmp dword ptr [eax + (offset Variable - offset dt_)]
endm

$PUSH_STRING macro Value
Local ld_
	Call ld_
	DB Value
	DB 0
ld_:
endm

$PUSH_CRC32 macro p1, p2, p3, p4, p5, p6, p7, p8
Local ld_
	Call ld_
	FOR Arg, <p1,p2,p3,p4,p5,p6,p7,p8>
	IFNB <Arg>
	DD Arg
	ENDIF
	ENDM
	DD 0
ld_:
endm