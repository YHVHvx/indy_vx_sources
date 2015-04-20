	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	OPT_ENABLE_DBG_LOG	equ TRUE
.code
MIENTRY:
	test eax,eax
	jz IdpAddReference
	dec eax
	jz IdpAddVEH
	dec eax
	jz IdpRemoveVEH
	dec eax
	jz IdpGetReference
	dec eax
	jz LdrImageQueryEntryFromHash
	dec eax
	jz LdrEncodeEntriesListEx
	mov eax,STATUS_INVALID_PARAMETER
	ret
	
	include Hdr.inc
	include Img.asm
	include Env.asm
	include Tls.asm
	include Idp.asm
	include Trap.asm

; end MIENTRY

%IDPCALL macro Service
	mov eax,Service
	Call MIENTRY
endm

IDP_ADD_REFERENCE		equ 0
; typedef NTSTATUS (*PENTRY)(
;    IN OUT PVOID *Reference
;	IN ULONG SpaceSize
;    );

; typedef LONG (*PVECTORED_EXCEPTION_HANDLER)(
;    IN OUT PEXCEPTION_POINTERS *ExceptionInformation
;    );

IDP_ADD_VEH			equ 1
; typedef PVOID (*PENTRY)(
;    IN ULONG First,
;    IN PVECTORED_EXCEPTION_HANDLER Handler
;    );

IDP_REMOVE_VEH			equ 2
; typedef ULONG (*PENTRY)(
;	IN PVOID Handle
;	);

IDP_GET_REFERENCE		equ 3
;typedef NTSTATUS (*PENTRY)(
;	IN PVOID Reference,
;	IN OUT *PSEGMENT_ENTRY Entry
;	);

IDP_QUERY_ENTRY		equ 4
;typedef NTSTATUS (*PENTRY)(
;	IN PVOID ImageBase OPTIONAL,
;	IN PVOID HashOrFunctionName,
;	IN PCOMPUTE_HASH_ROUTINE HashRoutine OPTIONAL,
;	IN ULONG PartialHash,
;	OUT *PVOID Entry
;	);

;typedef ULONG (*PCOMPUTE_HASH_ROUTINE)(
;	IN ULONG PartialHash,
;	IN PVOID Buffer,
;	IN ULONG Length
;	);

IDP_QUERY_ENTRIES		equ 5
; typedef NTSTATUS (*PENTRY)(
;	IN PVOID ImageBase OPTIONAL,
;	IN ULONG PartialHash,
;	IN OUT *PVOID List
;	);

VEH2NDF proc uses ebx ExceptionPointers:PEXCEPTION_POINTERS
	mov eax,ExceptionPointers
	mov ebx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume ebx:PEXCEPTION_RECORD
	cmp [ebx].ExceptionFlags,NULL
	jnz Chain
	.if [Ebx].ExceptionCode == IDP_BREAKPOINT
		inc BreakCount
		%DBG "IDP_BREAKPOINT: Ip = 0x%X, Ref = 0x%X", [Ebx].ExceptionInformation + 4, [Ebx].ExceptionAddress
		jmp Load
	.elseif [Ebx].ExceptionCode == IDP_SINGLE_STEP
		%DBG "IDP_SINGLE_STEP: Ip = 0x%X", [Ebx].ExceptionAddress
		jmp Load
	.endif
Chain:
	xor eax,eax
Exit:
	ret
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp Exit
VEH2NDF endp

.data
BreakCount	ULONG ?
Buffer		CHAR 12 DUP (?)
$MsgCall		CHAR "Breaks: ",0

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
	includelib \masm32\lib\masm32.lib

udw2str proto :ULONG, :PVOID
StdOut proto :PSTR


.code
Entry proc
	mov ecx,fs:[TEB.Peb]
	lea ecx,PEB.ProcessParameters[ecx]
	push sizeof(RTL_USER_PROCESS_PARAMETERS)
	push ecx
	%IDPCALL IDP_ADD_REFERENCE

	push offset VEH2NDF
	push FALSE
	%IDPCALL IDP_ADD_VEH
	
; AllocConsole -> SetUpConsoleInfo -> GetStartupInfoW ..
	invoke AllocConsole
	invoke StdOut, addr $MsgCall
	invoke udw2str, BreakCount, addr Buffer
	invoke StdOut, addr Buffer
	invoke Sleep, INFINITE
	ret
Entry endp
end Entry