	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

.code
	include Ldr.inc

%NTERR macro
	.if Eax
	Int 3
	.endif
endm

%APIERR macro
	.if !Eax
	Int 3
	.endif
endm

; +
; Поправка базы для GetModuleHandle(0).
;
%LDR_FIXUP_PEB macro DllHandle
	assume fs:nothing
	mov ecx,fs:[TEB.Peb]
	mov eax,DllHandle
	lock xchg PEB.ImageBaseAddress[ecx],eax
endm

ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID	equ 1
ACTCTX_FLAG_LANGID_VALID					equ 2
ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID		equ 4
ACTCTX_FLAG_RESOURCE_NAME_VALID			equ 8
ACTCTX_FLAG_SET_PROCESS_DEFAULT			equ 10H
ACTCTX_FLAG_APPLICATION_NAME_VALID			equ 20H
ACTCTX_FLAG_HMODULE_VALID				equ 80H

ACTCTX struct	; 0x20
cbSize				ULONG ?
dwFlags				DWORD ?
lpSource				PWSTR ?
wProcessorArchitecture	WORD ?
wLangId				WORD ?
lpAssemblyDirectory		PSTR ?
lpResourceName			PSTR ?
lpApplicationName		PSTR ?
hModule				HANDLE ?
ACTCTX ends
PACTCTX typedef ptr ACTCTX

; +
;
LdrImageNtHeader proc ImageBase:PVOID, ImageHeader:PIMAGE_NT_HEADERS
	mov edx,ImageBase
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	assume edx:PIMAGE_DOS_HEADER
	cmp [edx].e_magic,'ZM'
	jne @f
	add edx,[edx].e_lfanew
	assume edx:PIMAGE_NT_HEADERS
	cmp [edx].Signature,'EP'
	jne @f
	cmp [edx].FileHeader.SizeOfOptionalHeader,sizeof(IMAGE_OPTIONAL_HEADER32)
	jne @f
	cmp [edx].FileHeader.Machine,IMAGE_FILE_MACHINE_I386	
	jne @f
	test [edx].FileHeader.Characteristics,IMAGE_FILE_32BIT_MACHINE
	je @f
	mov ecx,ImageHeader
	xor eax,eax
	mov dword ptr [ecx],edx
@@:
	ret
LdrImageNtHeader endp

.data
Entries		PVOID 4 DUP (?)
SxsEntries	PVOID 3 DUP (?)

$ExeName	CHAR "calc.exe",0
align 4

include Map.inc

.code
comment '
Stub proc DllHandle:HANDLE, Reason:ULONG, Context:PVOID
	.if Reason == DLL_PROCESS_ATTACH
	push DllHandle
	Call Entries[4]	; LdrDisableThreadCalloutsForDll()
	mov eax,TRUE
	.endif
	ret
Stub Endp'

$KernelNameW	WCHAR "k", "e", "r", "n", "e", "l", "3", "2", ".", "d", "l", "l"
			WCHAR 0
$KernelNameU	UNICODE_STRING <sizeof $KernelNameW, sizeof $KernelNameW + 2, offset $KernelNameW>

; * Don't use ntdll!LdrpImageEntry.
;	
Entry proc
Local ExeHandle:HANDLE, KernelHandle:HANDLE
Local ImageHeader:PIMAGE_NT_HEADERS
Local LdrEntry:PLDR_DATA_TABLE_ENTRY
Local ActCtx:ACTCTX, Cookie:ULONG
Local CtxHandle:HANDLE
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],0CB096353H	; CRC32("LdrFindEntryForAddress")
	mov Entries[4],21F56BC4H		; CRC32("LdrDisableThreadCalloutsForDll")
	mov Entries[2*4],0E21C1C46H	; CRC32("LdrGetDllHandle")
	mov eax,LDR_QUERY_ENTRIES
;	mov Entries[3*4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	%NTERR
; kernel32.dll
	lea ecx,KernelHandle
	push ecx
	push offset $KernelNameU
	push eax
	push eax
	Call Entries[2*4]	; LdrGetDllHandle()
	%NTERR
; SXS
	lea edx,SxsEntries
	mov SxsEntries[0],0B18A3D2FH	; CRC32("CreateActCtxA")
	mov SxsEntries[4],06AA0C20CH	; CRC32("ActivateActCtx")	
;	mov Entries[2*4],eax
	push edx
	push eax
	push KernelHandle
	mov eax,LDR_QUERY_ENTRIES
	Call LDR
	%NTERR
; PE
	invoke LdrImageNtHeader, addr gMap, addr ImageHeader
	%NTERR
; IP
	xor esi,esi
	mov ebx,ImageHeader
	assume ebx:PIMAGE_NT_HEADERS
	xchg [ebx].OptionalHeader.AddressOfEntryPoint,esi	; may by stub.
; for LdrpWalkImportDescriptor().
	or [ebx].FileHeader.Characteristics,IMAGE_FILE_DLL
; #LDR_LOAD_DLL
	lea ecx,ExeHandle
	push ecx
	push 0
	push offset $ExeName
	push offset gMap
	Call LDR
	%NTERR
	
	push ExeHandle
	Call Entries[4]	; LdrDisableThreadCalloutsForDll()
	%NTERR
; PEB.ImageBase
	%LDR_FIXUP_PEB ExeHandle
; LDR_DATA_TABLE_ENTRY.EntryPoint
	lea eax,LdrEntry
	push eax
	push ExeHandle
	Call Entries[0]	; LdrFindEntryForAddress()
	%NTERR
; IP
	add esi,ExeHandle
	mov eax,LdrEntry
	mov LDR_DATA_TABLE_ENTRY.EntryPoint[eax],esi
; SXS
	mov ecx,ExeHandle
	lea edx,ActCtx
	mov ActCtx.cbSize,sizeof(ACTCTX)
	mov ActCtx.dwFlags,ACTCTX_FLAG_HMODULE_VALID or ACTCTX_FLAG_RESOURCE_NAME_VALID
	mov ActCtx.lpResourceName,1
	mov ActCtx.lpSource,offset $ExeName
	mov dword ptr [ActCtx.wProcessorArchitecture],eax
	mov ActCtx.lpAssemblyDirectory,eax
	mov ActCtx.lpApplicationName,eax
	mov ActCtx.hModule,ecx
	push edx
	Call SxsEntries[0]	; CreateActCtxA()
	mov CtxHandle,eax
	.if Eax == INVALID_HANDLE_VALUE
	Int 3
	.endif
	lea ecx,Cookie
	push ecx
	push eax
	Call SxsEntries[4]	; ActivateActCtx()
	%APIERR
; Run
	Call Esi
	
	invoke ExitProcess, STATUS_SUCCESS
	ret
Entry endp
end Entry