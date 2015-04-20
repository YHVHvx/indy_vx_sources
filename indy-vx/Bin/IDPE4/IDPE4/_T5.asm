; IDP' захват кс менеджера хипа(HEAP_LOCK).
;
; o Если при аллокации хипа не установлен флаг HEAP_NO_SERIALIZE, выполняется синхронизация на кс.
;
; (c) Indy, 2012.
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

	OPT_ENABLE_DBG_LOG	equ TRUE
.code
IDPE:
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
	
; o !OPT_DISABLE_TEB, TLS_SLOTS_NUMBER = 1.

	include Hdr.inc
	include Img.asm
	include Env.asm
	include Tls.asm
	include Idp.asm
	include Trap.asm
	include Snap.asm

%IDPCALL macro Service
	mov eax,Service
	Call IDPE
endm

IDP_ADD_REFERENCE		equ 0
IDP_ADD_VEH			equ 1

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

STACK_FRAME struct
Next		PVOID ?
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

.code
%IDPSETVEH macro PVEH
	%GET_GRAPH_ENTRY PVEH
	push eax
	push 0	; !First
	%IDPCALL IDP_ADD_VEH
endm

	assume fs:nothing
.code
OP_RETX	equ 0C2H
OP_CALL	equ 0E8H

OP_RM_MASK	equ 111B	; ModR/M

; +
; Определение смещения на кс.
;
; push dword ptr ds:[esi + Reg32(HEAP.LockVariable:PHEAP_LOCK)]
; call RtlEnterCriticalSection
;
HmgrQueryLockOffset proc uses ebx esi edi pRtlLockHeap:PVOID, pRtlEnterCriticalSection:PVOID, pOffset:PVOID
	mov esi,pRtlLockHeap
	lea edi,[esi + 80H]	; Limit
Step:
	mov ebx,esi
	Call VirXasm32
	add esi,eax
	cmp byte ptr [esi],OP_RETX
	je Error
	cmp byte ptr [esi],OP_CALL
	jne IsLimit
	mov eax,dword ptr [esi + 1]
	mov ecx,dword ptr [ebx]
	lea eax,dword ptr [eax + esi + 5]
	mov edx,ecx
	cmp pRtlEnterCriticalSection,eax
	jne IsLimit
	and ch,NOT(OP_RM_MASK)
	cmp cl,0FFH	; Grp. 5
	jne IsLimit
	cmp ch,10110000B	; 10(Mod:Mem) - 110(PUSH Ev) - Reg
	jne IsLimit
	and dh,OP_RM_MASK	; Reg32
	sub dh,100B
	je IsLimit
	jb @f
	dec dh
	jz IsLimit	; Ebp
@@:
	mov ecx,dword ptr [ebx + 2]	; Disp32
	xor eax,eax
	cmp ecx,800H
	mov edx,pOffset
	jnb IsLimit
	mov dword ptr [edx],ecx
Exit:
	ret
IsLimit:
	cmp esi,edi
	jb Step
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
HmgrQueryLockOffset endp

; +
;
xVEH2NDF:
	%GET_CURRENT_GRAPH_ENTRY
VEH2NDF proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
	mov eax,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[eax]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	jnz Chain
	.if [Esi].ExceptionCode == IDP_BREAKPOINT
		%DBG "VEH2NDF.IDP_BREAKPOINT: Ip = 0x%X, Ref = 0x%X", [Esi].ExceptionInformation + 4, [Esi].ExceptionAddress
Load:
		mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
		ret
	.endif
	cmp [esi].ExceptionCode,IDP_SINGLE_STEP
	jne Chain
	%DBG "VEH2NDF.IDP_SINGLE_STEP: Ip = 0x%X", [Esi].ExceptionAddress
	mov ebx,[edi].rEbp
; BTR
	assume ebx:PSTACK_FRAME
@@:
	cmp fs:[TEB.Tib.StackBase],ebx
	jna Load
	cmp fs:[TEB.Tib.StackLimit],ebx
	ja Load
	mov eax,[ebx].Ip
	mov ecx,Snaps
	.repeat
		cmp dword ptr [offset ApiSnap + ecx*4 - 4],eax
		je Route
		dec ecx
	.until Zero?
	mov ebx,[ebx].Next
	jmp @b
Chain:
	xor eax,eax
	jmp Exit
Route:
; S-routing.
	%DBG "VEH2NDF.CreateFileW().Route: Ip = 0x%X", Eax
	mov ecx,[esi].ExceptionRecord	; PTLS_ENTRY
	mov TLS_ENTRY.Exts[ecx],eax
	mov [ebx].Ip,offset Post2ndDispatch
	jmp Load
VEH2NDF endp

CREATEFILE struct
lpFileName			PSTR ?
dwDesiredAccess		DWORD ?
dwShareMode			DWORD ?
lpSecurityAttributes	PSECURITY_ATTRIBUTES ?
dwCreationDisposition	DWORD ?
dwFlagsAndAttributes	DWORD ?
hTemplateFile			HANDLE ?
CREATEFILE ends
PCREATEFILE typedef ptr CREATEFILE

; +
; Payload.
;
Post2ndDispatch proc C
	%TLSGET Ecx
	bts TLS_ENTRY.Flags[ecx],2
	.if !Carry?
		mov edx,dword ptr [ebp + sizeof(STACK_FRAME) + CREATEFILE.lpFileName]
		%DBG "Post2ndDispatch: %ws", Edx
	.endif
	jmp TLS_ENTRY.Exts[ecx]
Post2ndDispatch endp

_imp__RtlLockHeap proto :HANDLE
_imp__RtlEnterCriticalSection proto :PRTL_CRITICAL_SECTION

_imp__CreateFileA proto :dword, :dword, :dword, :dword, :dword, :dword, :dword
_imp__CreateFileW proto :dword, :dword, :dword, :dword, :dword, :dword, :dword

$FileName	CHAR "_T5.exe",0

.data?
SBuffer		DWORD 100H DUP (?)
ApiSnap		DWORD 100H DUP (?)
Snaps		ULONG ?

.code
EP proc
Local LockOffset:ULONG
	invoke HmgrQueryLockOffset, dword ptr [_imp__RtlLockHeap], dword ptr [_imp__RtlEnterCriticalSection], addr LockOffset
	%NTERR
	
	invoke Snapshot, dword ptr [_imp__CreateFileW], addr SBuffer, addr ApiSnap, TRUE
	%APIERR
	mov Snaps,eax
	
	%IDPSETVEH xVEH2NDF
	%APIERR
	
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.ProcessHeap[eax]
	add eax,LockOffset
	push sizeof(RTL_CRITICAL_SECTION)
	push eax
	%IDPCALL IDP_ADD_REFERENCE
	%NTERR
	
	invoke CreateFile, addr $FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	ret
EP endp
end EP