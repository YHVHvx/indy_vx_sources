	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
LDR_LOAD_DLL		equ 0
LDR_QUERY_ENTRY	equ 1
LDR_QUERY_ENTRIES	equ 2

.code
PI_START:

	include Ldr.inc
	include Map.inc

BREAKER macro
	.if Eax
	Int 3
	.endif
endm

; o Picode
;
LoadAndCallLibrary proc C
	push 0
	pushad
	push 0	; ImageBase
	mov eax,esp
	Call Delta
Delta:
	xchg dword ptr [esp],eax
	push 0
	Call @f
	CHAR "12345.dll", 0
@@:
	lea ecx,[eax + (offset gMap - offset Delta)]
	xor eax,eax	; #LDR_LOAD_DLL
	push ecx
	Call LDR
	BREAKER
	push eax
	push 0D5223A7CH	; CRC32("MsgBox")
	push esp
	push 0
	push dword ptr [esp + 4*4]
	mov eax,LDR_QUERY_ENTRIES
	Call LDR
	pop edx	; @MsgBox
	pop ecx
	BREAKER
	Call @f
	CHAR "Test..", 0
@@:
	Call Edx
	db 0B8H	; mov eax,#
Ip	PVOID (-1)
	mov dword ptr [esp + 4*8 + 4],eax
	pop ecx
	popad
	retn
LoadAndCallLibrary endp
PI_END:

APIERR macro
	.if !Eax
	Int 3
	.endif
endm

$PsName	CHAR "d:\windows\system32\calc.exe",0

Entry proc
Local StartupInfo:STARTUPINFO
Local ProcessInfo:PROCESS_INFORMATION
Local Context:CONTEXT
	invoke GetStartupInfo, addr StartupInfo
	invoke CreateProcess, addr $PsName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, addr StartupInfo, addr ProcessInfo
	APIERR
	mov Context.ContextFlags,CONTEXT_INTEGER
	invoke GetThreadContext, ProcessInfo.ThreadHandle, addr Context
	APIERR
	lea esi,offset PI_END	; Кривой компиль :(
	mov ecx,Context.regEax
	sub esi,offset PI_START
	mov Ip,ecx
	invoke VirtualAllocEx, ProcessInfo.ProcessHandle, 0, Esi, MEM_COMMIT, PAGE_EXECUTE_READWRITE
	mov ebx,eax
	APIERR
	invoke WriteProcessMemory, ProcessInfo.ProcessHandle, Ebx, addr PI_START, Esi, NULL
	APIERR
	add ebx,(offset LoadAndCallLibrary - offset PI_START)
	mov Context.regEax,ebx
	invoke SetThreadContext, ProcessInfo.ThreadHandle, addr Context
	APIERR
	invoke ResumeThread, ProcessInfo.ThreadHandle
	.if Eax == -1
	Int 3
	.endif
	ret
Entry endp
end Entry