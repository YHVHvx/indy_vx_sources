	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\user32.inc	
	includelib \masm32\lib\user32.lib
	
.data
Ready	BOOLEAN FALSE

.code
	include Ts.inc	
	include Vm.asm

QueryThreadCallbackStack proc ProcessHandle:HANDLE, ThreadHandle:HANDLE, CallbackStack:PVOID
Local ThreadObject:PVOID	; PETHREAD
;	invoke ZwSuspendThread, ThreadHandle, NULL
;	test eax,eax
;	jnz Exit
	invoke QueryObject, ThreadHandle, addr ThreadObject
	mov ecx,ThreadObject
	test eax,eax
	lea ecx,[ecx + ThCallbackStack]
	jnz Resume
	VIRTUAL_TO_PHYSICAL Ecx
	invoke KdReadPhysicalMemory, Ecx, addr ThreadObject, sizeof(PVOID)
	test eax,eax
	mov ecx,ThreadObject
	jnz Resume
	test ecx,ecx
	mov edx,CallbackStack
	.if Zero?
	mov eax,STATUS_NO_CALLBACK_ACTIVE
	.else
	mov dword ptr [edx],ecx
	.endif
Resume:
;	push eax
;	invoke ZwResumeThread, ThreadHandle, NULL
;	pop eax
Exit:
	ret
QueryThreadCallbackStack endp

QueryThreadCallbackStackEx proc ThreadHandle:HANDLE, CallbackStack:PVOID
Local ThreadInformation:THREAD_BASIC_INFORMATION
Local ObjAttr:OBJECT_ATTRIBUTES
Local ProcessHandle:HANDLE
	invoke ZwQueryInformationThread, ThreadHandle, ThreadBasicInformation, addr ThreadInformation, sizeof(THREAD_BASIC_INFORMATION), NULL
	test eax,eax
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	jnz Exit
	mov ObjAttr.hRootDirectory,eax
	mov ObjAttr.pSecurityDescriptor,eax
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.pObjectName,eax
	mov ObjAttr.uAttributes,eax
	invoke ZwOpenProcess, addr ProcessHandle, PROCESS_QUERY_INFORMATION, addr ObjAttr, addr ThreadInformation.ClientId
	test eax,eax
	jnz Exit
	invoke QueryThreadCallbackStack, ProcessHandle, ThreadHandle, CallbackStack
	push eax
	invoke ZwClose, ProcessHandle
	pop eax
Exit:
	ret
QueryThreadCallbackStackEx endp

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

	include Ts.asm

ThreadRoutine proc StartupParameter:DWORD
	invoke MessageBeep, 0
	SAVE_TASK_STATE cbRet1
	SAVE_TASK_STATE cbRet2
	SAVE_TASK_STATE cbRet3
	mov Ready,TRUE
cbRet1:
	nop
cbRet2:
	nop
cbRet3:
	nop
	jmp $
ThreadRoutine endp

$Msg	CHAR "Frame: %x, Eip: 0x%p", 13, 10, 0

	assume fs:nothing
Entry proc
Local ClientId:CLIENT_ID, ThreadHandle:HANDLE
Local TrapFrame:KTRAP_FRAME
Local CalloutFrame:CALLOUT_FRAME
Local Privilege:ULONG
	invoke RtlAdjustPrivilege, SE_DEBUG_PRIVILEGE, TRUE, FALSE, addr Privilege
	BREAKERR
	invoke RtlCreateUserThread, NtCurrentProcess, NULL, FALSE, 0, 0, 0, ThreadRoutine, 0, addr ThreadHandle, addr ClientId
	BREAKERR
@@:
	cmp Ready,FALSE
	je @b
	invoke ZwSuspendThread, ThreadHandle, NULL
	BREAKERR
	invoke QueryThreadCallbackStackEx, ThreadHandle, addr CalloutFrame.CallbackStack
	BREAKERR
	xor ebx,ebx
	.if CalloutFrame.CallbackStack == Eax
		Int 3
	.endif
	inc ebx
@@:
	invoke KdReadVirtualMemoryEx, addr ClientId, CalloutFrame.CallbackStack, addr CalloutFrame, sizeof(CALLOUT_FRAME)
	BREAKERR
	invoke KdReadVirtualMemoryEx, addr ClientId, CalloutFrame.TrapFrame, addr TrapFrame, sizeof(KTRAP_FRAME)
	BREAKERR
	invoke DbgPrint, addr $Msg, Ebx, TrapFrame.rEip
	inc ebx
	cmp CalloutFrame.CallbackStack,eax
	jne @b
	ret
Entry endp
end Entry