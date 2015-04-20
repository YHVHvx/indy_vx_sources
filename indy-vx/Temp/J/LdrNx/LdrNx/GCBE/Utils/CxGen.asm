; Генерация таблиц для морфинга Jcx.
;
	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
.code
%HALT macro
	ret
endm

%LINK macro
	jmp eax
endm

; o x32_CxReplaceTable[JccType * HEADER_SIZE * 2]
; o x16_CxReplaceTable = x32_CxReplaceTable + HEADER_SIZE
; o JccHeader = XX_BRANCH_HEADER.BranchLink[CxReplaceTable]

ALIGN 4
CxReplaceTable proc C
; JCC_LOOPNE
	je $Loopdne
	je $Loopwne
; JCC_LOOPE
	je $Loopde
	je $Loopwe
; JCC_LOOP
	je $Loopd
	je $Loopw
; JCC_ECXZ
	je $Jecxz
	je $Jcxz
	%HALT
$Loopdne::
	pushfd
	lea ecx,[ecx - 1]
	jz @f
	test ecx,ecx
	jz @f
	popfd
	%LINK
@@:	popfd
	%HALT
$Loopwne::
	pushfd
	dec cx
	jz @f
	test byte ptr [esp],EFLAGS_ZF
	jz @f
	popfd
	%LINK
@@:	popfd
	%HALT
$Loopde::
	pushfd
	lea ecx,[ecx - 1]
	jnz @f
	test ecx,ecx
	jz @f
	popfd
	%LINK
@@:	popfd
	%HALT
$Loopwe::
	pushfd
	dec cx
	jz @f
	test byte ptr [esp],EFLAGS_ZF
	jnz @f
	popfd
	%LINK
@@:	popfd
	%HALT
$Loopd::
	pushfd
	dec ecx
	jz @f
	popfd
	%LINK
@@:	popfd
	%HALT
$Loopw::
	pushfd
	dec cx
	jz @f
	popfd
	%LINK
@@:	popfd
	%HALT
$Jecxz::
	pushfd
	test ecx,ecx
	jnz @f
	popfd
	%LINK
@@:	popfd
	%HALT
$Jcxz::
	pushfd
	test cx,cx
	jnz @f
	popfd
	%LINK
@@:	popfd
	%HALT
ALIGN 4
CxReplaceTableEnd::
CxReplaceTable endp

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

.data
; 0xB6
%PREGENHASH 01C740F74H, \
	037742A74H, \
	04C744574H, \
	05C745474H, \
	0498D9CC3H, \
	0850774FFH, \
	09D0374C9H, \
	0C39DE0FFH, \
	07449669CH, \
	02404F609H, \
	09D037440H, \
	0C39DE0FFH, \
	0FF498D9CH
%POSTGENHASH 0FF498D9CH, \
	0C9850775H, \
	0FF9D0374H, \
	09CC39DE0H, \
	009744966H, \
	0402404F6H, \
	0FF9D0375H, \
	09CC39DE0H, \
	09D037449H, \
	0C39DE0FFH, \
	07449669CH, \
	0E0FF9D03H, \
	0859CC39DH, \
	09D0375C9H
%POSTGENHASH 09D0375C9H, \
	0C39DE0FFH, \
	0C985669CH, \
	0FF9D0375H, \
	090C39DE0H

Buffer	BYTE 200 DUP (90H)

.code
CX_REPLACE_TABLE_LENGTH	equ (CxReplaceTableEnd - CxReplaceTable)

Generate:
	cld
	lea esi,CxReplaceTable
	lea edi,Buffer
	lodsd
	lea ebx,[esi + CX_REPLACE_TABLE_LENGTH]
	mov ecx,eax
	not eax
	mov word ptr [edi],0C033H
	inc eax
	mov byte ptr [edi + 2],2DH
	mov dword ptr [edi + 3],eax
	mov byte ptr [edi + 7],0ABH
	add edi,8
@@:
	mov eax,dword ptr [esi]
	mov byte ptr [edi],35H
	xor ecx,eax
	mov byte ptr [edi + 5],0ABH
	mov dword ptr [edi + 1],ecx

	mov ecx,dword ptr [esi + 4]
	mov edx,ecx
	mov byte ptr [edi + 6],5
	sub ecx,eax
	mov byte ptr [edi + 11],0ABH
	mov dword ptr [edi + 7],ecx
	
	mov ecx,dword ptr [esi + 2*4]
	mov byte ptr [edi + 12],2DH
	sub edx,ecx
	mov byte ptr [edi + 17],0ABH
	mov dword ptr [edi + 13],edx
	add esi,3*4
	add edi,3*(5 + 1)
	cmp esi,ebx
	jb @b
	int 3
end Generate