; Создание слепка для тела.
;
; (c) Indy, 2011.
;

.code

; +
; o Не используем расширяемый буфер.
;
BodyInitialize proc uses ebx esi edi Apis:PAPIS, Result:PGP_SNAPSHOT
Local Snapshot:GP_SNAPSHOT, GpSize:ULONG
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor eax,eax
	mov ebx,Apis
	assume ebx:PAPIS
	mov Snapshot.GpBase,eax
	mov GpSize,20H * X86_PAGE_SIZE
	lea ecx,GpSize
	lea edx,Snapshot.GpBase
	push PAGE_READWRITE
	push MEM_COMMIT
	push ecx
	push eax
	push edx
	push NtCurrentProcess
	Call [ebx].pZwAllocateVirtualMemory
	test eax,eax
	mov esi,Snapshot.GpBase
	jnz Exit
	add Snapshot.GpBase,01FH * X86_PAGE_SIZE	; ~ 13 pages, возможно больше так как тело морфится.
	mov GpSize,X86_PAGE_SIZE
	lea eax,Snapshot.GpLimit	; Old protect.
	lea ecx,GpSize
	lea edx,Snapshot.GpBase
	push eax
	push PAGE_NOACCESS
	push ecx
	push edx
	push NtCurrentProcess
	Call [ebx].pZwProtectVirtualMemory
	test eax,eax
	mov Snapshot.GpLimit,esi
	mov Snapshot.GpBase,esi
	jnz Free
	lea ecx,Snapshot.GpLimit
	push eax
	push eax
	push eax
	push eax
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push GCBE_PARSE_IPCOUNTING or GCBE_PARSE_SEPARATE
	%GET_GRAPH_ENTRY xBodyEntry
	push ecx
	push eax
	mov edi,eax
	%GPCALL GP_PARSE	; !OPT_EXTERN_SEH_MASK - расширяемый буфер не используем.
	test eax,eax
	mov ecx,Result
	jnz Free	; #AV etc.
	mov edx,Snapshot.GpLimit
	assume ecx:PGP_SNAPSHOT
	mov [ecx].Ip,edi
	mov [ecx].GpBase,esi
	mov [ecx].GpLimit,edx
	jmp Exit
Free:
	push eax
	mov GpSize,NULL
	lea eax,GpSize
	lea ecx,Snapshot.GpBase
	push MEM_RELEASE
	push eax
	push ecx
	push NtCurrentProcess
	Call [ebx].pZwFreeVirtualMemory
	pop eax
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
BodyInitialize endp