APIS struct
pRtlCreateUnicodeStringFromAsciiz	PVOID ?	; 0x059B88A67
pRtlFreeUnicodeString			PVOID ?	; 0x0DB164279
pLdrLoadDll					PVOID ?	; 0x09E1E35CE
pLdrUnloadDll					PVOID ?	; 0x0810815B0
pZwAllocateVirtualMemory			PVOID ?	; 0x024741E13
pZwProtectVirtualMemory			PVOID ?	; 0x039542311
pZwFreeVirtualMemory			PVOID ?	; 0x0DA44E712
pZwAreMappedFilesTheSame			PVOID ?	; 0x07CA4251F
pRtlInitUnicodeString			PVOID ?	; 0x0C9167C79
pZwSetInformationProcess			PVOID ?	; 0x034357463
pRtlLockHeap					PVOID ?	; 0x0B39A8F58
pDbgPrint						PVOID ?	; 0x05C0B45CC
pRtlAddVectoredExceptionHandler	PVOID ?	; 0x0815C378D
pKiUserExceptionDispatcher		PVOID ?	; 0x0C5713067
pZwCreateFile					PVOID ?	; 0x04AEBF61E
pRtlEnumProcessHeaps			PVOID ?	; 0x0A71ECBD4
pZwQueryVirtualMemory			PVOID ?	; 0x0EA7DF819
pZwQueryObject					PVOID ?	; 0x06E8164AF
pZwClose						PVOID ?	; 0x0DE02B845
pZwSetInformationObject			PVOID ?	; 0x08619D8AB
pZwDeviceIoControlFile			PVOID ?	; 0x02C0E8748
Eol							PVOID ?
APIS ends
PAPIS typedef ptr APIS

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

InitializeApis proc uses edi List:PAPIS
	mov edi,List
	cld
%PREGENHASH 59B88A67H, \
	0DB164279H, \
	09E1E35CEH, \
	0810815B0H, \
	024741E13H, \
	039542311H, \
	0DA44E712H, \
	07CA4251FH, \
	0C9167C79H, \
	034357463H, \
	0B39A8F58H, \
	05C0B45CCH, \
	0815C378DH, \
	0C5713067H, \
	04AEBF61EH, \
	0A71ECBD4H, \
	0EA7DF819H, \
	06E8164AFH
%POSTGENHASH 06E8164AFH, \
	0DE02B845H, \
	08619D8ABH, \
	02C0E8748H
	xor eax,eax
	stosd	; EOL
	invoke LdrEncodeEntriesList, Eax, Eax, List
	ret
InitializeApis endp

xLdrCalculateHash:
	%GET_CURRENT_GRAPH_ENTRY
LdrCalculateHash proc uses ebx esi PartialHash:ULONG, StrName:PCHAR, NameLength:ULONG
	xor eax,eax
	mov ecx,NameLength
	mov esi,StrName
	mov ebx,PartialHash
	cld
@@:
	lodsb
	xor ebx,eax
	xor ebx,ecx
	rol ebx,cl
	loop @b
	mov eax,ebx
	ret
LdrCalculateHash endp