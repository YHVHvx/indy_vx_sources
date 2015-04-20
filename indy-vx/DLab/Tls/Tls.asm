	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.code
	include GCBE\Bin\Gcbe.inc
	
%NTERR macro
	.if Eax
		Int 3
	.endif
endm

_imp__LdrInitializeThunk proto :dword, :dword, :dword, :dword

OP_PUSH	equ 068H

LdrCalculateHash proc uses ebx esi StrName:PCHAR, NameLength:ULONG
	xor eax,eax
	mov ecx,NameLength
	mov esi,StrName
	xor ebx,ebx
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

TLS struct
LdrpInitializeTls	PVOID ?
LdrpAllocateTls	PVOID ?
TLS ends
PTLS typedef ptr TLS

ParseCallback proc uses ebx GpBase:PVOID, GpEntry:PVOID, SubsList:PVOID, SubsCount:ULONG, PreOrPost:BOOLEAN, Tls:PTLS
	mov eax,GpEntry
	test dword ptr [eax + EhEntryType],TYPE_MASK
	.if Zero?
	   ; Line
	   mov eax,dword ptr [eax + EhAddress]
	   .if byte ptr [Eax] == OP_PUSH
	      mov ebx,dword ptr [eax + 1]
	      invoke ZwAreMappedFilesTheSame, Eax, Ebx
	      .if !Eax
	         invoke LdrCalculateHash, Ebx, 11H	; ASCII 
	         .if SubsCount
	            mov ecx,SubsList
	            mov edx,Tls
	            mov ecx,dword ptr [ecx]
	            mov ecx,dword ptr [ecx + EhAddress]
	            assume edx:PTLS
	            .if (Eax == 3DC7123DH) || (Eax == 65CA1D48H)	; "LDR: Tls Found in" / "LdrpInitializeTls"
	               mov [edx].LdrpInitializeTls,ecx
	            .elseif (Eax == 0FDE90A41H) || (Eax == 0AA47C3C5H)	; "LDR: TlsVector %x" / "TlsVector %p Inde"(mb "RtlpAllocateTls")
	               mov [edx].LdrpAllocateTls,ecx
	               .if [edx].LdrpInitializeTls
	                  mov eax,STATUS_WAIT_1
	                  jmp Exit
	               .endif
	            .endif
	         .endif
	      .endif
	   .endif
	.endif
	xor eax,eax
Exit:
	ret
ParseCallback endp

TlsQueryInitialRoutine proc uses ebx esi edi Tls:PTLS
Local GpBase:PVOID, GpSize:ULONG, GpLimit:PVOID
Local OldProtect:ULONG
	mov GpBase,NULL
	mov GpSize,100H * X86_PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr GpBase, 0, addr GpSize, MEM_COMMIT, PAGE_READWRITE
	%NTERR
	mov eax,GpBase
	add GpBase,0FFH * X86_PAGE_SIZE
	mov GpSize,X86_PAGE_SIZE
	mov GpLimit,eax
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr GpBase, addr GpSize, PAGE_NOACCESS, addr OldProtect
	%NTERR
	mov edx,Tls
	lea ecx,GpLimit
	push eax
	push eax
	mov TLS.LdrpInitializeTls[edx],eax
	mov TLS.LdrpAllocateTls[edx],eax
	push edx
	push offset ParseCallback
	push eax	; Last Ip.
	push 3	; NL
	push GCBE_PARSE_IPCOUNTING or GCBE_PARSE_SEPARATE or GCBE_PARSE_OPENLIST
	push ecx
	push dword ptr [_imp__LdrInitializeThunk]
	%GPCALL GP_PARSE	; !OPT_EXTERN_SEH_MASK - расширяемый буфер не используем.
	.if !Eax
	   mov eax,STATUS_NOT_FOUND
	.elseif Eax == STATUS_WAIT_1
	   xor eax,eax
	.endif
	ret
TlsQueryInitialRoutine endp

$Msg	CHAR "LdrpInitializeTls: 0x%p, LdrpAllocateTls: 0x%p", 13, 10, 0

Entry proc
Local Tls:TLS
	invoke TlsQueryInitialRoutine, addr Tls
	.if !Eax
	   invoke DbgPrint, addr $Msg, Tls.LdrpInitializeTls, Tls.LdrpAllocateTls
	.endif
	ret
Entry endp
end Entry