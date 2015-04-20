	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

%GET_CURRENT_GRAPH_ENTRY macro
	Call GetGraphReference
endm

%GET_GRAPH_ENTRY macro PGET_CURRENT_GRAPH_ENTRY
	Call PGET_CURRENT_GRAPH_ENTRY
endm

%GET_GRAPH_REFERENCE macro
GetGraphReference::
	pop eax
	ret
endm

KernelMode	equ 0
UserMode		equ 1

MODE_MASK		equ 1

.code
	jmp MiEntry
	
	%GET_GRAPH_REFERENCE

	assume fs:nothing
SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	push ecx
	ret
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 2*4]
	pop ebp
	push ecx
	ret
SEH_Epilog endp

SEH_GetRef proc C
	%GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov ecx,dword ptr [esp + 3*4]	; Ctx.
	mov edx,dword ptr [esp]	; ~ nt!ExecuteHandler2().
	mov ebx,CONTEXT.regEbx[ecx]
	mov esi,CONTEXT.regEsi[ecx]
	mov edi,CONTEXT.regEdi[ecx]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov ecx,EXCEPTION_RECORD.ExceptionAddress[eax]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	push dword ptr [esp + 2*4]
	ret
SEH_GetRef endp

FLG_ENABLE_SEH	equ TRUE

%SEHPROLOG macro EpilogLabel
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog_Reference
		Call SEH_Prolog
	endif
endm

%SEHEPILOG macro ExitLabel
	ifdef FLG_ENABLE_SEH
		jmp Exit
  	SEH_Epilog_Reference:
		%GET_CURRENT_GRAPH_ENTRY
	endif
	ifndef ExitLabel
  Exit:
  	else
  ExitLabel:
  	endif
	ifdef FLG_ENABLE_SEH
		Call SEH_Epilog
	endif
endm

	include VirXasm32b.asm
	include Image.asm
	include DrParse.asm
	include KiTrap.asm
	
XCPT_UD_MAGIC	equ 2FEA0CABH
XCPT_TSC_MAGIC	equ 7FEA0CABH

MiEntry proc NtBase:PVOID
Local DbgEnv:KDEBUG_ENVIRONMENT
	invoke xQueryDebugEnvironment, NtBase, addr DbgEnv
	test eax,eax
	jnz Exit
	%GET_GRAPH_ENTRY xKiDebugRoutineInternal
	mov ecx,DbgEnv.pKiDebugRoutine
; Post-хэндлер не используем.
	lock xchg dword ptr [ecx],eax
	xor eax,eax
Exit:
	ret
MiEntry endp
end MiEntry