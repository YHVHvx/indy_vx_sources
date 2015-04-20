; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; Удаление(морфинг) ветвлений:
; o Jcxz
; o Jecxz
; o Loopw
; o Loopd
; o Loopwe
; o Loopde
; o Loopwne
; o Loopdne
;
Public CxMorferInitialize
Public CxMorphEntry
Public CxMorphGraph

.code
%PREGENHASH macro HashList:VARARG
Local Iter, PrevHash
   Iter = 0
   for Hash, <HashList>
      if Iter eq 0
         xor eax,eax
         sub eax,-Hash
      elseif (Iter eq 1) or (Iter eq 3)
         xor eax,(PrevHash xor Hash)
      elseif Iter eq 2
         add eax,dword ptr (Hash - PrevHash)
      elseif Iter eq 4
         sub eax,dword ptr (PrevHash - Hash)
      endif
      stosd
      Iter = Iter + 1
      PrevHash = Hash
      if Iter eq 5
         Iter = 1
      endif
   endm
endm

%POSTGENHASH macro FirstHash, HashList:VARARG
Local Iter, PrevHash
   Iter = 0
   PrevHash = FirstHash
   for Hash, <HashList>
      if (Iter eq 0) or (Iter eq 2)
         xor eax,(PrevHash xor Hash)
      elseif Iter eq 1
         add eax,dword ptr (Hash - PrevHash)
      elseif Iter eq 3
         sub eax,dword ptr (PrevHash - Hash)
      endif
      stosd
      Iter = Iter + 1
      PrevHash = Hash
      if Iter eq 4
         Iter = 0
      endif
   endm
endm

CX_REPLACE_TABLE_LENGTH	equ ((077H + 11B) and NOT(11B))
CX_REPLACE_GRAPH_LENGTH	equ 920H	; * GCBE_PARSE_SEPARATE

; +
; Загрузка таблиц и создание графа.
;
; Buffer:
;	REPLACE_TABLE[CX_REPLACE_TABLE_LENGTH]
;	REPLACE_GRAPH[CX_REPLACE_GRAPH_LENGTH]
;
; o x32_CxReplaceTable[JccType * ENTRY_SIZE * 2]
; o x16_CxReplaceTable = x32_CxReplaceTable + ENTRY_SIZE
; o JccHeader = JCC_ENTRY.BranchLink[CxReplaceTable]
;
CxMorferInitialize proc uses edi Buffer:PVOID
Local Graph:PVOID
	mov edi,Buffer
	cld
	lea edx,[edi + CX_REPLACE_TABLE_LENGTH]
	xor eax,eax
	sub eax,0E38BF08CH
	stosd
	xor eax,02B002500H
	stosd
	add eax,015001B00H
	stosd
	sub eax,0EFFFF100H
	stosd
	xor eax,015F9C8B7H
	stosd
	add eax,03B79D83CH
	stosd
	sub eax,0E8040036H
	stosd
	xor eax,05E9E9436H
	stosd
	add eax,0B0AB859DH
	stosd
	sub eax,050447093H
	stosd
	xor eax,0B9078249H
	stosd
	add eax,0269A6CBFH
	stosd
	sub eax,0C4545363H
	stosd
	xor eax,036CC8AE9H
	stosd
	add eax,03617FBFFH
	stosd
	sub eax,062D96594H
	stosd
	xor eax,095B7D486H
	stosd
	add eax,036AFBB90H
	stosd
	sub eax,040870181H
	stosd
	xor eax,0635E9E95H
	stosd
	add eax,0003FD669H
	stosd
	sub eax,0D965934AH
	stosd
	xor eax,0B7D48663H
	stosd
	add eax,06CB63667H
	stosd
	sub eax,05B62D966H
	stosd
	xor eax,0189FB654H
	stosd
	add eax,0269A6B36H
	stosd
	sub eax,0FA187A63H
	stosd
	xor eax,0361865E9H
	stosd
	add eax,091269A6BH
	stosd
	sub eax,908E0FE4H
	mov ecx,CX_REPLACE_GRAPH_LENGTH/4
	stosd
	xor eax,eax
	mov edi,edx
	mov Graph,edx
	rep stosd
	invoke GpKit, Buffer, addr Graph, NULL, GCBE_PARSE_SEPARATE or GCBE_PARSE_IPCOUNTING, Eax, Eax, Eax, Eax, Eax, Eax
	ret
CxMorferInitialize endp

; +
; Морфинг одного описателя.
;
; o AF сохраняется.
;
CxMorphEntry proc uses ebx esi edi CxTable:PVOID, JcxEntry:PVOID, GpLimit:PVOID
Local Delta:ULONG, SrcEntry:PVOID
Local JcxHeader:JCC_ENTRY
	mov esi,JcxEntry
	lea edi,JcxHeader
	mov ebx,dword ptr [esi + EhAccessFlag]
	mov ecx,ENTRY_SIZE/4
	mov eax,esi
	cld
	mov edx,CxTable
	rep movsd
	mov ecx,dword ptr [eax + EhEntryType]
	and ebx,ACCESSED_MASK_FLAG
	and cl,TYPE_MASK
	cmp cl,ENTRY_TYPE_JCC
	jne Exit
	test dword ptr [eax + EhJcxType],BRANCH_CX_FLAG
	jz Exit
	mov eax,dword ptr [eax + EhJccType]
	and eax,JCC_TYPE_MASK
	shl eax,5	; x ENTRY_SIZE
	lea eax,[edx + 2 * eax + CX_REPLACE_TABLE_LENGTH]
	test dword ptr [esi - ENTRY_SIZE + EhJccType],JCC_X16_MASK
	.if !Zero?
		add eax,ENTRY_SIZE
	.endif
	mov esi,dword ptr [eax + EhBranchLink]
	mov edi,JcxEntry
	and esi,NOT(TYPE_MASK)
	mov SrcEntry,esi
	mov edx,edi
	mov ecx,ENTRY_SIZE/4
	rep movsd
	and dword ptr [edx + EhFlink],TYPE_MASK
	and dword ptr [edx + EhBlink],TYPE_MASK and NOT(ACCESSED_MASK_FLAG)	; &Blink
	mov edi,GpLimit
	mov ecx,JcxHeader.Link.Blink
	mov edi,dword ptr [edi]
	and ecx,NOT(TYPE_MASK)
	mov eax,edi
	or dword ptr [edx + EhAccessFlag],ebx
	sub eax,esi
	or dword ptr [edx + EhFlink],edi
	mov Delta,eax
	or dword ptr [edx + EhBlink],ecx
Do:
	mov eax,dword ptr [esi + EhEntryType]
	mov ecx,dword ptr [esi + EhFlink]
	and eax,TYPE_MASK
	mov edx,Delta
	jnz NoLine
; Line
	and ecx,NOT(TYPE_MASK)
	jnz IsFlink
; %HALT
	mov eax,JcxHeader.Link.Flink
	sub edi,ENTRY_SIZE
	and eax,NOT(TYPE_MASK)
	and dword ptr [edi + EhFlink],TYPE_MASK
	and dword ptr [eax + EhBlink],TYPE_MASK
	or dword ptr [edi + EhFlink],eax
	or dword ptr [eax + EhBlink],edi
	lea eax,[edi + ENTRY_SIZE]
	mov ecx,GpLimit
	mov dword ptr [ecx],eax
Exit:
	xor eax,eax
	ret
IsFlink:
	mov ecx,ENTRY_SIZE/4
	rep movsd
	sub edi,ENTRY_SIZE
	add dword ptr [edi + EhFlink],edx
IsBlink:
	mov eax,dword ptr [edi + EhBlink]
	and dword ptr [edi + EhAccessFlag],NOT(ACCESSED_MASK_FLAG)
	and eax,NOT(TYPE_MASK)
	.if !Zero?
		mov ecx,JcxEntry
		.if SrcEntry == Eax
			and dword ptr [edi + EhBlink],TYPE_MASK
	      	mov dword ptr [edi + EhBlink],ecx
		.else
			add dword ptr [edi + EhBlink],edx
		.endif
	.endif
	or dword ptr [edi + EhAccessFlag],ebx
	add edi,ENTRY_SIZE
	jmp Do
NoLine:
	cmp al,ENTRY_TYPE_JMP
	jne JccEntry
	mov eax,JcxHeader.BranchLink
	mov ecx,ENTRY_SIZE/4
	and eax,NOT(TYPE_MASK)
	rep movsd
	mov ecx,JcxHeader.BranchAddress
	sub edi,ENTRY_SIZE
	mov dword ptr [edi + EhBranchLink],eax
	mov dword ptr [edi + EhBranchAddress],ecx
	or dword ptr [edi + EhBranchType],BRANCH_DEFINED_FLAG
	jmp IsBlink
JccEntry:
	; ENTRY_TYPE_JCC
	mov ecx,ENTRY_SIZE/4
	rep movsd
	sub edi,ENTRY_SIZE
	add dword ptr [edi + EhFlink],edx
	add dword ptr [edi + EhBranchLink],edx
	jmp IsBlink
CxMorphEntry endp

; +
; Морфинг всех описателей Jcx.
;
CxMorphGraph proc uses ebx esi edi CxTable:PVOID, GpBase:PVOID, GpLimit:PVOID
Local GraphLimit:PVOID
	mov esi,GpLimit
	mov ebx,GpBase
	mov edi,dword ptr [esi]
	invoke CxMorferInitialize, CxTable
	test eax,eax
	mov GraphLimit,edi
	jnz Exit
@@:
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	.if !Zero?
	   dec eax
	   .if !Zero?	; Jxx/Jcc
	      and dword ptr [ebx + EhBranchLink],NOT(TYPE_MASK)	; * Для оптимизатора Size & Idle.
	      dec eax
	      .if !Zero?	; Jcc
	         invoke CxMorphEntry, CxTable, Ebx, addr GraphLimit
	      .endif
	   .endif
	.endif
	add ebx,ENTRY_SIZE
	cmp ebx,edi
	jb @b
	mov ecx,GraphLimit
	xor eax,eax
	mov dword ptr [esi],ecx
Exit:
	ret
CxMorphGraph endp