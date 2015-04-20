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

; +
; Список опорных апи.
;	
APIS struct
pZwOpenFile 					PVOID ?	; 0x545B554F
pZwCreateSection				PVOID ?	; 0x5CC20C59
pZwMapViewOfSection				PVOID ?	; 0x08C1BF69
pZwUnmapViewOfSection			PVOID ?	; 0x3BF9E770
pKiUserExceptionDispatcher		PVOID ?	; 0xC5713067
pRtlAddVectoredExceptionHandler	PVOID ?	; 0x815C378D
pRtlRemoveVectoredExceptionHandler	PVOID ?	; 0x395537A4
pZwAllocateVirtualMemory			PVOID ?	; 0x24741E13
pZwProtectVirtualMemory			PVOID ?	; 0x39542311
pZwFreeVirtualMemory			PVOID ?	; 0xDA44E712
pZwQueryVirtualMemory			PVOID ?	; 0xEA7DF819
pZwQuerySystemInformation		PVOID ?	; 0x7085AB5A
pZwQueryInformationProcess		PVOID ?	; 0x34DF9700
pZwSetInformationProcess			PVOID ?	; 0x34357463
pZwClose						PVOID ?	; 0xDE02B845
Eol							DWORD ?	; End Of List.
APIS ends
PAPIS typedef ptr APIS

%APIGEN macro
%PREGENHASH 	034DF9700H, \
	034357463H, \
	0F12751C6H, \
	0EC22B3DBH, \
	0B16404DFH, \
	09655652EH, \
	082D0B25AH, \
	04C8016BBH, \
	0FB8F38C1H, \
	023A0F19FH, \
	0857CB89BH, \
	0ED209DAEH, \
	0A26477D6H, \
	0C6EFEDBFH, \
	0D360E7C3H, \
	0D360F3C3H, \
	02D62B51FH, \
	03BF9E770H
	
%POSTGENHASH 03BF9E770H, \
	06EC3CC0DH, \
	0C5E4F02FH, \
	06F660715H, \
	024741E13H, \
	039542311H, \
	0D97D7219H, \
	0DA44E712H, \
	0EA7DF819H, \
	0F644F212H, \
	0E27DFC19H, \
	0399E5A81H, \
	0FEB50331H, \
	0ABCA57D8H, \
	008C1BF69H, \
	08A8A23CEH, \
	02A06034CH, \
	0A2138A76H
	
%POSTGENHASH 0A2138A76H, \
	0BDD7BB7DH, \
	06E8164AFH, \
	0BCEEB97AH, \
	0023604FBH, \
	0C389BC89H, \
	02887B52FH, \
	054ECE9ADH, \
	047812AE0H, \
	0FEAFC765H, \
	01F4D4E2DH, \
	0A1080EDAH, \
	043F42FF9H, \
	01855E12EH, \
	02774C723H, \
	05AB999CFH, \
	048F54459H, \
	0B20C2C41H
	
%POSTGENHASH 0B20C2C41H, \
	0600E1441H, \
	00455A05FH, \
	06A6CCF95H, \
	0E2E8F14CH, \
	0E4692394H, \
	0A6C16DDEH, \
	0B3477A88H, \
	080680197H, \
	04BA03779H, \	; ZwNotifyChangeKey
	0C9419E41H, \
	08C8B23F1H, \
	038C5C033H, \
	0CB7E494FH, \
	0548112BBH, \
	0FBA7C19BH, \	; ZwOpenProcess & ZwOpenThread
	0B8EDE574H
	; * Последние два сервиса всегда в конце списка!
	xor eax,eax
	stosd	; EOL
endm