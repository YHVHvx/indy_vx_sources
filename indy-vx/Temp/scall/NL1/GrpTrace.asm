; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; Трассировка.
;
comment '
 Перечисление входов таблицы ветвлений. Выполняется инверсия флага ACCESSED_MASK_FLAG в каждом входе.
 Рекурсивные вызовы не допускаются!

typedef NTSTATUS (*PTRACE_CALLBACK_ROUTINE)(
    IN PVOID GpEntry,
    IN ULONG NL,
    IN PVOID List,
    IN PVOID CallbackParameter
    );

typedef NTSTATUS (*PENTRY)(
  IN PVOID Graph,
  IN ULONG NL,
  IN PTRACE_CALLBACK_ROUTINE CallbackRoutine OPTIONAL,
  IN PVOID CallbackParameter
  )'

STACK_MARKER_MASK	equ 1B
STACK_MARKER_BIT	equ 0
CALL_STACK_MARKER	equ 0B
JCC_STACK_MARKER	equ 1B

RwTrace proc uses ebx esi edi Graph:PVOID, NL:ULONG, CallbackRoutine:PVOID, CallbackParameter:PVOID
Local FlowCount:ULONG
Local AccessFlag:DWORD
Local StartNL:ULONG
	mov ebx,Graph
	mov ecx,NL
	cld
	mov eax,dword ptr [ebx + EhAccessFlag]
	mov FlowCount,NULL
	and eax,ACCESSED_MASK_FLAG
	push NULL	; EOL
	mov StartNL,ecx
	mov AccessFlag,eax
FindHead:
	mov edx,dword ptr [ebx + EhBlink]
	and edx,NOT(TYPE_MASK)
	jz NewBlock
	mov ebx,edx
	jmp FindHead
NewBlock:
	mov edx,dword ptr [ebx + EhAccessFlag]
	and edx,ACCESSED_MASK_FLAG
	cmp AccessFlag,edx
	jne PopEntry
	xor dword ptr [ebx + EhAccessFlag],ACCESSED_MASK_FLAG
	cmp CallbackRoutine,NULL
	mov ecx,esp
	.if !Zero?
		mov edx,StartNL
		push CallbackParameter
		sub edx,NL
		push ecx
		push edx
		push ebx
		Call CallbackRoutine
		test eax,eax
		jnz Exit
	.endif
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	jz LineEntry
	cmp eax,ENTRY_TYPE_CALL
	jne @f
; Call
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz LineEntry
	test dword ptr [ebx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	jz LineEntry
	cmp NL,0
	je LineEntry
	push ebx
	inc FlowCount
	jmp LineEntry
@@:
	assume ebx:PJMP_ENTRY
	cmp eax,ENTRY_TYPE_JCC
	je @f
; Jmp
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz PopEntry	; * Здесь возможно нарушение NL.
	jmp NewEntry
@@:
; Jcc.
	mov eax,[ebx].BranchLink
	inc FlowCount
	and eax,NOT(TYPE_MASK)
	or eax,JCC_STACK_MARKER
	push eax
LineEntry:
	mov ebx,[ebx].Link.Flink
	and ebx,NOT(TYPE_MASK)
	jnz NewBlock
PopEntry:
	mov eax,FlowCount
	test eax,eax
	jz Exit
	mov ecx,eax
@@:
	test dword ptr [esp + 4*ecx - 4],JCC_STACK_MARKER
	jnz PopJxxEntry
	dec ecx
	jnz @b
PopCallEntry:
	inc NL
	dec FlowCount
	lea edi,[esp + 4*eax - 4]
	lea esi,[edi - 4]
	mov ebx,dword ptr [esp + 4*eax - 4]
	mov ecx,eax
	std
	btr ebx,0	; and ebx,NOT(JCC_STACK_MARKER)
	rep movsd
	add esp,4
	assume ebx:PCALL_ENTRY
NewEntry:
	mov ebx,[ebx].BranchLink
	cld
	and ebx,NOT(TYPE_MASK)
	mov eax,dword ptr [ebx + EhAccessFlag]
	and eax,ACCESSED_MASK_FLAG
	cmp AccessFlag,eax
	jne PopEntry
	dec NL
	jmp FindHead
PopJxxEntry:
	dec FlowCount
	lea edi,[esp + 4*ecx - 4]
	lea esi,[edi - 4]
	mov ebx,dword ptr [esp + 4*ecx - 4]
	std
	btr ebx,0	; and ebx,NOT(JCC_STACK_MARKER)
	rep movsd
	add esp,4
	mov eax,dword ptr [ebx + EhAccessFlag]
	cld
	and eax,ACCESSED_MASK_FLAG
	cmp AccessFlag,eax
	jne PopEntry
	jmp FindHead
Exit:
	pop ecx
	ret
RwTrace endp