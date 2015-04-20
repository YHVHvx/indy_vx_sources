	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
%NTERR macro
	.if Eax
	Int 3
	.endif
endm

APIERR macro
	.if !Eax
	Int 3
	.endif
endm

.code
	include Gcbe.inc

%ALLOC macro vBase, vSize, vProtect, cSize, Reg32
	mov vBase,NULL
	mov vSize,cSize
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr vBase, 0, addr vSize, MEM_COMMIT, PAGE_READWRITE
	mov Reg32,vBase
	%NTERR
	add vBase,cSize - X86_PAGE_SIZE
	mov vSize,X86_PAGE_SIZE
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr vBase, addr vSize, PAGE_NOACCESS, addr vProtect
	%NTERR	
endm

%FREE macro vBase, vSize
	invoke ZwFreeVirtualMemory, NtCurrentProcess, addr vBase, addr vSize, MEM_RELEASE
endm

$Nt	CHAR "ntoskrnl.exe",0

; +
; Калбэк для поиска IDT.
;
PARSE_CALLBACK_ROUTINE proc Graph:PVOID,	; Ссылка на граф.
   GraphEntry:PVOID,	; Ссылка на описатель инструкции.
   SubsList:PVOID,	; Список описателей входов процедур в порядке вызова.
   SubsCount:ULONG,	; Число процедур в списке является уровнем вложенности(NL).
   PreOrPost:BOOLEAN,	; Тип вызова.
   pIdt:PULONG
	mov eax,GraphEntry
	test dword ptr [eax + EhEntryType],TYPE_MASK
	jnz Exit
	mov ecx,dword ptr [eax + EhAddress]
	cmp byte ptr [ecx],0B9H	; mov ecx,XXXX
	jne Exit
	mov edx,dword ptr [ecx + 1]
	cmp word ptr [ecx + 5],0A5F3H	; rep movsd
	jne IsShr
	cmp edx,256*8/4
	jne Exit
	jmp Idt
IsShr:
	cmp dword ptr [ecx + 5],0F302E9C1H	; shr ecx,2
	jne Exit
	cmp byte ptr [ecx + 9],0A5H
	jne Exit
	cmp edx,256*8
	jne Exit
Idt:
	mov eax,dword ptr [eax + EhBlink]
	and eax,NOT(TYPE_MASK)
	jz Exit
	test dword ptr [eax + EhEntryType],TYPE_MASK
	jnz Exit
	mov ecx,dword ptr [eax + EhAddress]
	cmp byte ptr [ecx],0BEH
	je @f
	mov eax,dword ptr [eax + EhBlink]
	and eax,NOT(TYPE_MASK)
	jz Exit
	test dword ptr [eax + EhEntryType],TYPE_MASK
	jnz Exit
	mov ecx,dword ptr [eax + EhAddress]
	cmp byte ptr [ecx],0BEH
	jne Exit
@@:
	mov eax,dword ptr [ecx + 1]	; _IDT
	mov edx,pIdt
	mov dword ptr [edx],eax
Exit:
	xor eax,eax
	ret
PARSE_CALLBACK_ROUTINE endp

IRET_ENTRIES_LIST struct
Count	ULONG ?
List		PBLOCK_HEADER 32 DUP (?)
IRET_ENTRIES_LIST ends
PIRET_ENTRIES_LIST typedef ptr IRET_ENTRIES_LIST

; +
; Калбэк для поиска Iret.
;
PARSE_CALLBACK_ROUTINE2 proc uses ebx Graph:PVOID,	; Ссылка на граф.
   GraphEntry:PVOID,	; Ссылка на описатель инструкции.
   SubsList:PVOID,	; Список описателей входов процедур в порядке вызова.
   SubsCount:ULONG,	; Число процедур в списке является уровнем вложенности(NL).
   PreOrPost:BOOLEAN,	; Тип вызова.
   IretList:PIRET_ENTRIES_LIST
	mov edx,GraphEntry
	test dword ptr [edx + EhEntryType],TYPE_MASK
	jnz Exit
	mov eax,dword ptr [edx + EhAddress]
	cmp byte ptr [eax],0CFH	; iretd
	jne Exit
	mov eax,IretList
	mov ecx,IRET_ENTRIES_LIST.Count[eax]
	.if Ecx > 32
	   Int 3
	.endif
	mov dword ptr IRET_ENTRIES_LIST.List[eax + 4*ecx],edx
	inc IRET_ENTRIES_LIST.Count[eax]
Exit:
	xor eax,eax
	ret
PARSE_CALLBACK_ROUTINE2 endp

IretStub:
	jmp dword ptr cs:[StubRef]

Public StubRef

StubRef:
	PVOID 12345H	; STUB()

Ep proc
Local GpSize:ULONG
Local Snapshot:GP_SNAPSHOT
Local Protect:ULONG
Local CsBase:PVOID, CsSize:ULONG
Local BiBase:PVOID, BiSize:ULONG
Local Idt:ULONG
Local IretList:IRET_ENTRIES_LIST
	invoke LoadLibraryEx, addr $Nt, 0, DONT_RESOLVE_DLL_REFERENCES
	mov ebx,eax
	invoke RtlImageNtHeader, Ebx
	%APIERR
	mov esi,eax
	assume esi:PIMAGE_NT_HEADERS
	%ALLOC Snapshot.GpBase, GpSize, Protect, 100H * X86_PAGE_SIZE, Edi
	mov Snapshot.GpLimit,edi
	mov Snapshot.GpBase,edi
	lea ecx,Snapshot.GpLimit
	lea edx,Idt
	mov Idt,eax
	push eax
	push eax
	push edx
	push offset PARSE_CALLBACK_ROUTINE
	mov edx,[esi].OptionalHeader.AddressOfEntryPoint
	push eax
	push eax
	add edx,ebx
	push GCBE_PARSE_SEPARATE
	push ecx
	push edx
	%GPCALL GP_PARSE
	%NTERR
	%FREE Snapshot.GpBase, GpSize
; 358 Ip's(NT 5.1.2600.5657)
; ~170k Ip's/sec(P4)
	mov eax,Idt
	%APIERR
	sub eax,[esi].OptionalHeader.ImageBase
	mov eax,dword ptr [eax + ebx + 8*0EH]	; _IDT[14]: KiTrap0E()
	sub eax,[esi].OptionalHeader.ImageBase
	lea esi,[eax + ebx]	; KiTrap0E()
	%ALLOC Snapshot.GpBase, GpSize, Protect, 100H * X86_PAGE_SIZE, Edi
	mov Snapshot.GpLimit,edi
	mov Snapshot.GpBase,edi
	lea ecx,Snapshot.GpLimit
	lea edx,IretList
	mov IretList.Count,eax
	push eax
	push eax
	push edx
	push offset PARSE_CALLBACK_ROUTINE2
	push eax
	push 0
	push GCBE_PARSE_SEPARATE or GCBE_PARSE_IPCOUNTING
	push ecx
	push esi
	%GPCALL GP_PARSE
	%NTERR
; 500 Ip's(NT 5.1.2600.5657)
; 5 Iretd's(NT 5.1.2600.5657)
	mov eax,IretList.Count
	%APIERR
	xor edx,edx
; Заменяем описатели линейных блоков для Iret на описатель ветвления на стаб(Jxx).
@@:
	mov ecx,IretList.List[eax*4 - 4]
	assume ecx:PBRANCH_HEADER
	mov [ecx].Link.Flink,HEADER_TYPE_JMP
	and [ecx].Link.Blink,NOT(TYPE_MASK)	; !BRANCH_DEFINED_FLAG
	mov [ecx].Address,offset IretStub
	mov [ecx].BranchAddress,edx
	mov [ecx].BranchLink,edx
	mov [ecx].KitFlags,edx
	mov [ecx].UserData,edx
	dec eax
	jnz @b
	%ALLOC CsBase, CsSize, Protect, 200H * X86_PAGE_SIZE, Esi
	%ALLOC BiBase, BiSize, Protect, 200H * X86_PAGE_SIZE, Edi
	push edi
	push esi
	push Snapshot.GpLimit
	push Snapshot.GpBase
	%GPCALL GP_BUILD_GRAPH
	%NTERR
	; Edi: ISR
	Int 3
	ret
Ep endp
end Ep