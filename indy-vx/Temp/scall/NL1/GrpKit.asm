; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; Конструктор.
;
Public GpKit

; DBG
Public GpParse$SYM_PUSH_JXX
Public GpParse$SYM_PUSH_CALL
Public GpParse$SYM_POP
Public GpParse$SYM_ADD_CHAIN
Public GpParse$SYM_DEL_CHAIN
Public GpParse$SYM_CALLBACK
Public GpParse$SYM_ERROR

	include Graph.inc
	include GrpDasm.asm

STACK_FRAME struct
Next		PVOID ?	; PSTACK_FRAME
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME
	
; +
; Разбивает описатель блока на два и связывает их.
;
RwInsertLineEntryInternal proc uses ebx edi Entry:PBLOCK_ENTRY, Address:PVOID
Local FullSize:ULONG
Local IpCount:ULONG
	mov edi,Entry
	assume edi:PBLOCK_ENTRY
	mov eax,Address
	mov edx,[edi].Link.Flink
	and edx,NOT(TYPE_MASK)
	assume esi:PBLOCK_ENTRY
	assume edx:PBLOCK_ENTRY
	test edx,edx
	mov [edi].Link.Flink,esi
	mov [esi].Link.Flink,edx
	.if !Zero?
		and [edx].Link.Blink,TYPE_MASK
		or [edx].Link.Blink,esi
	.endif
	mov [esi].Link.Blink,edi
	mov [esi].Address,eax
	mov edx,[edi]._Size
	sub eax,[edi].Address
	mov FullSize,edx
	jna GpParse$SYM_ERROR
	mov [edi]._Size,eax
	sub edx,eax
	mov ecx,STACK_FRAME.Next[ebp]
	jbe GpParse$SYM_ERROR	; * Псевдоописатель.
	test dword ptr [ecx + 2*4 + sizeof(STACK_FRAME)],GCBE_PARSE_IPCOUNTING
	mov [esi]._Size,edx
	jnz Validate
	xor edx,edx
	mov [esi].IpCount,edx
	mov [edi].IpCount,edx
Exit:
	mov eax,esi
	mov [esi].UserData,NULL
	add esi,ENTRY_SIZE
	ret
Validate:
	mov IpCount,0
	mov ebx,[edi].Address
@@:
	inc IpCount
	invoke QueryOpcodeSize, Ebx
	sub FullSize,eax
	jbe GpParse$SYM_ERROR
	add ebx,eax
	cmp Address,ebx
	jb GpParse$SYM_ERROR
	ja @b
	mov ecx,IpCount
	xchg [edi].IpCount,ecx
	sub ecx,IpCount
	jbe GpParse$SYM_ERROR
	mov [esi].IpCount,ecx
; Остальную часть блока не проверяем.
	jmp Exit
RwInsertLineEntryInternal endp

; +
; Ищет описатель для адреса в таблице.
; Eax - указатель на описатель.
;
RwSearchEntryForAddress proc GpBase:PVOID, GpLimit:PVOID, Address:PVOID, SearchCallback:PVOID, CallbackParameter:PVOID
	mov eax,GpBase
	cmp GpLimit,eax
	je Callback
	assume eax:PBLOCK_ENTRY
	.if SearchCallback
	   push TRUE
	   push CallbackParameter
	   push Address
	   Call SearchCallback
	   test eax,eax
	   jnz Exit
	   mov eax,GpBase
	.endif
; * IPCOUNTING не используем и не выполняем валидацию.
Entry:
	mov edx,[eax].Address
	cmp Address,edx
	je Exit
	jb Next
	mov ecx,dword ptr [eax + EhEntryType]
	and ecx,TYPE_MASK
	jnz Next
	add edx,[eax]._Size
	cmp Address,edx
	jb Validate
Next:
	add eax,ENTRY_SIZE
	cmp GpLimit,eax
	ja Entry
Callback:
	.if SearchCallback
	   push FALSE
	   push CallbackParameter
	   push Address
	   Call SearchCallback
	.else
Error:
	   xor eax,eax
	.endif
Exit:
	ret
Validate:
	mov ecx,STACK_FRAME.Next[ebp]
	test dword ptr [ecx + 2*4 + sizeof(STACK_FRAME)],GCBE_PARSE_SEPARATE
	jnz GpParse$SYM_ERROR
	test dword ptr [ecx + 2*4 + sizeof(STACK_FRAME)],GCBE_PARSE_CROSSBREAK
	jz Exit
	push esi
	push ebx
	push eax
	mov esi,edx
	mov ebx,[eax]._Size
Check:
	Call VirXasm32
	add esi,eax
	sub ebx,eax
	ja @f
	pop eax
	pop ebx
	pop esi
	jne GpParse$SYM_ERROR
@@:
	cmp Address,esi
	ja Check
	pop eax
	pop ebx
	pop esi
	je Exit
	jmp GpParse$SYM_ERROR
RwSearchEntryForAddress endp

comment '
typedef NTSTATUS (*PPARSE_CALLBACK_ROUTINE)(
   IN PVOID *Graph,		// Ссылка на граф.
   IN PVOID GraphEntry,	// Ссылка на описатель инструкции.
   IN PVOID SubsList,	// Список описателей входов процедур в порядке вызова.
   IN ULONG SubsCount,	// Число процедур в списке является уровнем вложенности(NL).
   IN BOOLEAN PreOrPost,	// Тип вызова.
   IN PVOID Context
   );

 o Список процедур завершается нулём(EOL).
 o Описатель процедурного ветвления на текущую процедуру: SubsList[0].BranchLink.
 o Описатель может измениться изза вставки. Выполняется разрыв описателя при обнаружении ветвление внутрь линейного блока.
 o Обратная ссылка описателя может отсутствовать. Парсер определит её далее при анализе следующего ветвления.
 o Первый описатель в списке может быть не заполнен, он будет заполнен на следующем вызове.

typedef PVOID (*PSEARCH_CALLBACK_ROUTINE)(
   IN PVOID Address,
   IN PVOID Context,
   IN BOOLEAN FirstSearch
   );

typedef NTSTATUS (*PENTRY)(
  IN PVOID Entry,
  IN OUT PVOID *Graph,	; Отсюда начинается построение графа.
  IN PVOID GpBase,	; База графа для поиска ссылок(Graph < GpBase).
  IN ULONG ParseFlags,
  IN ULONG NestingLevel,
  IN PVOID LastIp OPTIONAL,
  IN PPARSE_CALLBACK_ROUTINE ParseCallbackRoutine OPTIONAL,
  IN PVOID ParseCallbackParameter,
  IN PSEARCH_CALLBACK_ROUTINE SearchCallbackRoutine OPTIONAL,
  IN PVOID SearchCallbackParameter
  );
  '
  
; [esp]:		[Jcc list]
; [esp + N]:	[Sub list]
; [esp + M]:	[Sub chain]

GCBE_PARSE_DISCLOSURE	equ 000001B
GCBE_PARSE_SEPARATE		equ 000010B
GCBE_PARSE_MAKELIST		equ 000100B
GCBE_PARSE_CROSSBREAK	equ 001000B
GCBE_PARSE_OPENLIST		equ 010000B
GCBE_PARSE_IPCOUNTING	equ 100000B

; o AccessFlag сбрасывается!
;
GpKit proc uses ebx esi edi Entry:PVOID, Graph:PVOID, GpBase:PVOID, ParseFlags:ULONG, NestingLevel:ULONG, LastIp:PVOID, ParseCallbackRoutine:PVOID, ParseCallbackParameter:PVOID, SearchCallbackRoutine:PVOID, SearchCallbackParameter:PVOID
Local LastEntry:PJMP_ENTRY
Local JumpCount:ULONG
Local CallCount:ULONG
Local InitialNL:ULONG
Local TR[3]:DWORD
	xor ebx,ebx
	mov esi,Graph
	push ebx	; Sub's EOL.
	mov ecx,NestingLevel
	mov esi,dword ptr [esi]
	mov CallCount,ebx
	mov JumpCount,ebx
	mov InitialNL,ecx
	mov edi,esi
	mov LastEntry,ebx
	mov dword ptr [edi + EhBlink],ebx
	push edi	; ???
	.if !GpBase
		mov GpBase,esi
	.endif
	mov ebx,Entry
	jmp Block
; Esi: Limit.
NextBlock:
	lea eax,[edi + ENTRY_SIZE]
	or dword ptr [edi + EhFlink],eax
	mov TR[0],eax
	mov dword ptr [eax + EhBlink],edi
	xor edx,edx	; Pre'
	Call GpParse$SYM_CALLBACK
	mov edi,TR[0]
Block:
	invoke QueryOpcodeSize, Ebx
	cmp LastIp,ebx
	mov [edi].IpLength,al
	mov dword ptr [edi + EhAddress],ebx
	mov dword ptr [edi + EhKitFlags],0
	jne @f
	mov edx,LastIp
CallbackEnd:
	xor ecx,ecx
	mov LastEntry,edi
	jmp JmpEntry
@@:
	invoke QueryOpcodeType, Ebx
	test eax,eax
	jnz Branch
; + Line
	assume edi:PBLOCK_ENTRY
	add esi,ENTRY_SIZE
	mov [edi].Link.Flink,ENTRY_TYPE_LINE
	mov [edi].UserData,eax
	invoke IsRetOpcode, Ebx
	test eax,eax
	mov [edi].IpCount,1
	mov [edi]._Size,eax
	jnz PopEntry
NextLine:
	invoke QueryOpcodeSize, Ebx
	add [edi]._Size,eax
	add ebx,eax
	invoke RwSearchEntryForAddress, GpBase, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jnz InsertLine
	.if SearchCallbackRoutine != Eax
	   push SearchCallbackParameter
	   push ebx
	   push edi
	   Call SearchCallbackRoutine
	   test eax,eax
	   mov edx,eax
	   jnz @f
	.endif
	.if LastIp == Ebx
	   mov edx,LastIp
@@:
	   xor ecx,ecx
	   mov LastEntry,edi
	   mov eax,ENTRY_TYPE_JMP
	.else
	   invoke QueryOpcodeType, Ebx
	   test eax,eax
	   jnz BranchNew
	   test ParseFlags,GCBE_PARSE_SEPARATE
	   jnz NextBlock
	   or dword ptr [edi + EhSepatateFlag],SEPARATE_MACRO_FLAG
	   invoke IsRetOpcode, Ebx
	   inc [edi].IpCount
	   test eax,eax
	   jz NextLine
	   add [edi]._Size,eax
	   jmp PopEntry
	.endif
BranchNew:
	mov TR[0],eax
	mov TR[4],ecx
	mov TR[8],edx
	lea eax,[edi + ENTRY_SIZE]
	or dword ptr [edi + EhFlink],eax
	mov dword ptr [eax + EhBlink],edi
	mov dword ptr [eax + EhAddress],ebx
	xor edx,edx
	mov dword ptr [edi + EhKitFlags],edx
	Call GpParse$SYM_CALLBACK
	invoke QueryOpcodeSize, Ebx
	add edi,ENTRY_SIZE
	mov ecx,TR[4]
	mov [edi].IpLength,al
	mov edx,TR[8]
	mov eax,TR[0]	
Branch:
	cmp eax,ENTRY_TYPE_JCC
	jne Branch2
; + Jxx opcode.
	add esi,ENTRY_SIZE
	assume edi:PJCC_ENTRY
	mov [edi].BranchAddress,edx	; Edx - адрес ветвления.
	mov [edi].BranchLink,NULL	; Определим далее.
	inc JumpCount
GpParse$SYM_PUSH_JXX::
	push edi
	push ecx
	mov [edi].Link.Flink,eax
	push ebx
	mov [edi].UserData,NULL
	Call QueryPrefixLength
	movzx eax,byte ptr [ebx + eax]
	sub al,JCX_OPCODE_BASE
	.if (!Carry?) && (al < 4)
	   or dword ptr [edi + EhJcxType],BRANCH_CX_FLAG
	   or byte ptr [edi + EhJccType],al	; Opcode
	.else
	   invoke QueryJccType, Ebx
	   test eax,eax
	   jz GpParse$SYM_ERROR
	   dec eax
	   or byte ptr [edi + EhJccType],al	; Jcc type
	.endif
	test edx,edx
	pop ecx
; x16 Jcc.
	.if !Zero?
	   or byte ptr [edi + EhJccType],JCC_X16_MASK
	.endif
	add ebx,ecx
	invoke RwSearchEntryForAddress, GpBase, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jz NextBlock
InsertLine:
	cmp dword ptr [Eax + EhAddress],ebx
	jz InsertAndPop
	invoke RwInsertLineEntryInternal, Eax, Ebx
	jmp PopEntry
Branch2:
	cmp eax,ENTRY_TYPE_CALL
	jne JmpEntry
; + Call opcode.
	add esi,ENTRY_SIZE
	assume edi:PCALL_ENTRY
	mov [edi].UserData,NULL
	mov [edi].BranchLink,NULL
	test ecx,ecx
	mov [edi].Link.Flink,eax
	jz IndirCall
	mov [edi].BranchAddress,edx	; Edx - адрес ветвления.
	or [edi].Link.Blink,BRANCH_DEFINED_FLAG
	invoke QueryOpcodeSize, Ebx
	cmp NestingLevel,0
	lea ebx,[ebx + eax]
	je NextBlock
	or dword ptr [edi + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
; * Ebx: следующая за ветвлением инструкция.
; * Edx: адрес процедуры.
; * Esi: следующий описатель.
GpParse$SYM_PUSH_CALL::
	mov edx,esi
	mov eax,edi
	mov ecx,JumpCount
	push eax
	mov edi,esp	; * SP
	cld
	lea esi,[edi + 4]
	inc CallCount
	rep movsd
	stosd	; Sub's list.
	mov esi,edx
	mov edi,eax
	invoke RwSearchEntryForAddress, GpBase, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jnz InsertLine
	jmp NextBlock
IndirCall:
	mov [edi].BranchAddress,NULL
	and [edi].Link.Blink,NOT(TYPE_MASK)
	invoke QueryOpcodeSize, Ebx
	add ebx,eax
	jmp NextBlock
JmpEntry:
; + Jmp opcode.
	add esi,ENTRY_SIZE
	assume edi:PJMP_ENTRY
	test ecx,ecx
	mov [edi].Link.Flink,ENTRY_TYPE_JMP
	mov [edi].UserData,NULL
	jnz @f
	mov [edi].BranchLink,ecx
	mov [edi].BranchAddress,ecx
	and [edi].Link.Blink,NOT(TYPE_MASK)
	jmp PopEntry
@@:
	mov ebx,edx
	or [edi].Link.Blink,BRANCH_DEFINED_FLAG
	mov [edi].BranchAddress,ebx
	invoke RwSearchEntryForAddress, GpBase, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jz @f
InsertBranchLine:
	.if dword ptr [Eax + EhAddress] != Ebx
	   invoke RwInsertLineEntryInternal, Eax, Ebx
	.endif
	or [edi].BranchLink,eax
	mov edx,1	; Post'
	Call GpParse$SYM_CALLBACK
	jmp GpParse$SYM_POP
@@:
	lea ecx,[edi + ENTRY_SIZE]
	xor edx,edx	; Pre'
	mov dword ptr [ecx + EhBlink],eax
	mov TR[0],ecx
	mov [edi].BranchLink,ecx
	Call GpParse$SYM_CALLBACK
	mov edi,TR[0]
	invoke QueryOpcodeSize, Ebx
	mov [edi].IpLength,al
	jmp Block
InsertAndPop:
	or dword ptr [eax + EhBlink],edi
	or [edi].Link.Flink,eax
PopEntry:
	.if Edi
	   xor edx,edx	; Pre'
	   Call GpParse$SYM_CALLBACK
	.endif
GpParse$SYM_POP::
	cmp JumpCount,0
	pop edi
	je PopCallEntry
PopJxxEntry:
	assume edi:PJMP_ENTRY
	dec JumpCount
	mov ebx,[edi].BranchAddress
	invoke RwSearchEntryForAddress, GpBase, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jnz InsertBranchLine
	mov dword ptr [esi + EhBlink],eax
	or [edi].BranchLink,esi
	lea edx,[eax + 1]	; Post'
	Call GpParse$SYM_CALLBACK
	mov edi,esi
	jmp Block
PopCallEntry:
	cmp CallCount,0
	je ParseEnd
	assume edi:PCALL_ENTRY
	dec CallCount
	.if !Edi	; NL
GpParse$SYM_DEL_CHAIN::
	   mov ecx,JumpCount
 	   mov edx,esi
	   add ecx,CallCount
	   lea edi,[esp + ecx*4]
	   std
	   lea esi,[edi - 4]	; Sub's chain, * SP
	   rep movsd
	   inc NestingLevel
	   cld
	   add esp,4
	   mov esi,edx
	   jmp GpParse$SYM_POP	; PopEntry
	.endif
	mov ebx,[edi].BranchAddress
	invoke RwSearchEntryForAddress, GpBase, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jnz InsertBranchLine
	dec NestingLevel
	push eax
	inc CallCount
GpParse$SYM_ADD_CHAIN::
	push eax	; NL mark.
	mov ecx,JumpCount
	mov eax,esi
	mov edx,edi
	add ecx,CallCount
	mov edi,esp	; * SP
	cld
	lea esi,[edi + 4]
	rep movsd
	or CALL_ENTRY.BranchLink[edx],eax
	test ParseFlags,GCBE_PARSE_OPENLIST
	mov dword ptr [eax + EhBlink],ecx
	.if !Zero?
	   stosd
	.else
	   mov dword ptr [edi],edx
	.endif
	mov esi,eax
	mov edi,edx
	lea edx,[ecx + 1]	; Post'
	Call GpParse$SYM_CALLBACK
	mov edi,esi
	jmp Block
GpParse$SYM_CALLBACK::
	.if (ParseCallbackRoutine != NULL)
; Edx: Type(Pre/Post).
	   mov eax,JumpCount
	   mov ecx,InitialNL
	   add eax,CallCount
	   push ParseCallbackParameter
	   sub ecx,NestingLevel
	   push edx
	   lea eax,[esp + eax*4 + 3*4]	; * SP
	   push ecx
	   push eax
	   push edi
	   push GpBase
	   Call ParseCallbackRoutine
	   test eax,eax
	   jnz GpParse$SYM_EXIT
	.endif
	retn
GpParse$SYM_ERROR::
	mov eax,STATUS_UNSUCCESSFUL
GpParse$SYM_EXIT::
	mov esp,dword ptr fs:[0]
;	mov ebp,dword ptr [esp + 3*4]
	jmp @f
ParseEnd:
	xor eax,eax
	add esp,4		; EOL(ENTRY in GpParse$SYM_POP).
@@:
	mov ecx,Graph
	mov dword ptr [ecx],esi
;	mov edx,LastEntry
Exit:
	ret
GpKit endp