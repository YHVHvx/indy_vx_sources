
IMAGE_MASK equ 0FF000000H

	assume fs:nothing	
ApfnQuery proc uses ebx esi edi ApfnBase:PVOID, ApfnSize:PULONG
	mov ebx,fs:[TEB.Peb]
	mov edx,ApfnBase
	mov ebx,PEB.KernelCallbackTable[ebx]
	mov eax,STATUS_UNSUCCESSFUL	
	test ebx,ebx
	mov esi,ebx
	jz Exit
	mov dword ptr [edx],ebx
	cld
	and ebx,IMAGE_MASK
	mov edi,esi
@@:
	lodsd
	and eax,IMAGE_MASK
	cmp eax,ebx
	je @b
	sub esi,edi	; Размер таблицы в байтах.
	mov eax,STATUS_UNSUCCESSFUL
	sub esi,4
	mov edx,ApfnSize
	jz Exit
	mov dword ptr [edx],esi
	xor eax,eax
Exit:
	ret
ApfnQuery endp

; ApfnDispatch:
;	  ...
;	@Fn1		; (N)
;	@Fn2		; (N + 1)
;	  ...
;
; [(N), P]:
; 	push @Fn1	; x5
; 	jmp Stub	; x5
; [(N + 1), P + 10]:
; 	push @Fn2
; 	jmp Stub
;	  ...
;
; Stub:
;	  ...
;	  ret

APFN_INFORMATION struct
OldApfnBase	PVOID ?
ApfnBase		PVOID ?
OldApfnSize	ULONG ?
ApfnSize		ULONG ?	; ..Page
APFN_INFORMATION ends
PAPFN_INFORMATION typedef ptr APFN_INFORMATION

ApfnRedirect proc uses ebx esi edi Stub:PVOID, ApfnInformation:PAPFN_INFORMATION
Local Apfn:APFN_INFORMATION
	invoke ApfnQuery, addr Apfn.OldApfnBase, addr Apfn.OldApfnSize
	test eax,eax
	mov ecx,Apfn.OldApfnSize
;  s = n + n*2 + n/2
;  s = (n/2)*7
	jnz Exit
	shr ecx,1
	mov Apfn.ApfnBase,eax
	lea edx,[ecx*8]
	push PAGE_EXECUTE_READWRITE
	sub edx,ecx
	lea eax,Apfn.ApfnSize
	push MEM_COMMIT
	lea ecx,Apfn.ApfnBase
	mov Apfn.ApfnSize,edx
	push eax
	push 0
	push ecx
	push NtCurrentProcess
	Call ZwAllocateVirtualMemory
	test eax,eax
	mov ecx,Apfn.OldApfnSize
	jnz Exit
	mov edx,Apfn.ApfnBase
	mov ebx,Stub	; Disp.
	mov edi,edx
	mov esi,Apfn.OldApfnBase
	add edi,ecx
	cld
	sub ebx,edi
	shr ecx,2
	sub ebx,2*5
@@:
	lodsd
	mov byte ptr [edi],68H	; Push fnXX
	mov byte ptr [edi + 5],0E9H	; Jmp Stub
	mov dword ptr [edi + 1],eax
	mov dword ptr [edi + 6],ebx
	mov dword ptr [edx],edi
	sub ebx,10
	add edi,10
	add edx,4
	loop @b
	mov ecx,fs:[TEB.Peb]
	mov edx,Apfn.ApfnBase
	lea esi,Apfn
	mov edi,ApfnInformation
	xor eax,eax
	lock xchg PEB.KernelCallbackTable[ecx],edx
	movsd
	movsd
	movsd
	movsd
Exit:
	ret
ApfnRedirect endp