	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.data
TestVar	ULONG 121314H
	
.code
	include Vm.asm	
	
	assume fs:nothing
Entry proc
Local Buffer:ULONG
Local Privilege:ULONG
	invoke RtlAdjustPrivilege, SE_DEBUG_PRIVILEGE, TRUE, FALSE, addr Privilege
	mov eax,fs:[TEB.Tib.Self]
	mov Buffer,12345678H
	lea ebx,[eax + TEB.Cid]
	invoke KdVirtualMemoryOperationEx, Ebx, addr TestVar, addr Buffer, 4, KD_READ
	ret
Entry endp
end Entry