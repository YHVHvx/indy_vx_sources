; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; Трассировка.
;
comment '
 Перечисление входов таблицы ветвлений.
 Выполняется инверсия флага ACCESSED_MASK_FLAG в каждом входе.
 Рекурсивные вызовы не допускаются!

typedef NTSTATUS (*PTRACE_CALLBACK_ROUTINE)(
    IN PVOID GpEntry,
    IN PVOID CallbackParameter
    );

typedef NTSTATUS (*PENTRY)(
  IN PVOID Graph,
  IN ULONG NL,
  IN PTRACE_CALLBACK_ROUTINE CallbackRoutine,
  IN PVOID CallbackParameter
  )'

CALL_STACK_MARKER	equ 00B
JCC_STACK_MARKER	equ 01B

RwTrace proc uses ebx esi edi Graph:PVOID, NL:ULONG, CallbackRoutine:PVOID, CallbackParameter:PVOID
Local FlowCount:ULONG
Local AccessFlag:DWORD
	mov ebx,Graph
	cld
	mov eax,dword ptr [ebx + EhAccessFlag]
	mov FlowCount,NULL
	and eax,ACCESSED_MASK_FLAG
	inc NL
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
	push CallbackParameter
	push ebx
	Call CallbackRoutine
	test eax,eax
	jnz Exit
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	jz LineEntry
	cmp eax,HEADER_TYPE_CALL
	jne @f
; Call
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz LineEntry
	test dword ptr [ebx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	jz LineEntry
	cmp NL,0
	je LineEntry
	dec NL
	push ebx
	inc FlowCount
	jmp LineEntry
@@:
	assume ebx:PJMP_HEADER
	cmp eax,HEADER_TYPE_JCC
	je @f
; Jmp
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz PopEntry
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
	loop @b
PopCallEntry:
	dec FlowCount
	lea edi,[esp + 4*eax - 4]
	inc NL
	lea esi,[edi - 4]
	mov ebx,dword ptr [esp + 4*eax - 4]
	mov ecx,eax
	std
	btr ebx,0	; and ebx,NOT(JCC_STACK_MARKER)
	rep movsd
	add esp,4
	assume ebx:PCALL_HEADER
NewEntry:
	mov ebx,[ebx].BranchLink
	cld
	and ebx,NOT(TYPE_MASK)
	mov eax,dword ptr [ebx + EhAccessFlag]
	and eax,ACCESSED_MASK_FLAG
	cmp AccessFlag,eax
	jne PopEntry
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
	ret
RwTrace endp