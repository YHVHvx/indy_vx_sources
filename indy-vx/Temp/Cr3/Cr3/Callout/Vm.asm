
BASE_REGION_SIZE	equ 10000H

; +
; Опредедяет адрес описателя обьекта(KPROCESS, KTIMER etc).
;
QueryObject proc uses ebx ObjectHandle:HANDLE, Object:PVOID
Local SystemInformation:PVOID, SystemInformationLength:ULONG
Local ProcessInformation:PROCESS_BASIC_INFORMATION
	invoke ZwQueryInformationProcess, NtCurrentProcess, ProcessBasicInformation, addr ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), NULL
	test eax,eax
	mov ebx,BASE_REGION_SIZE
	jnz Exit
NextRegion:
	mov SystemInformationLength,ebx
	mov SystemInformation,NULL
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr SystemInformation, 0, addr SystemInformationLength, MEM_COMMIT, PAGE_READWRITE
	test eax,eax
	jnz Exit
	invoke ZwQuerySystemInformation, SystemHandleInformation, SystemInformation, SystemInformationLength, Eax
	test eax,eax
	jz ParseInfo
	push eax
	invoke ZwFreeVirtualMemory, NtCurrentProcess, addr SystemInformation, addr SystemInformationLength, MEM_RELEASE
	pop eax
	cmp eax,STATUS_INFO_LENGTH_MISMATCH
	jnz Exit
	add ebx,BASE_REGION_SIZE
	cmp ebx,32*BASE_REGION_SIZE
	jb NextRegion
	jmp Exit
ParseInfo:
	mov edx,SystemInformation
	mov ebx,ProcessInformation.UniqueProcessId
	mov ecx,dword ptr [edx]
	mov eax,ObjectHandle
	add edx,4
NextEntry:
	assume edx:PSYSTEM_HANDLE_INFORMATION
	cmp [edx].ProcessId,ebx
	jne @f
	cmp [edx].Handle,ax
	je GetObject
@@:
	add edx,sizeof(SYSTEM_HANDLE_INFORMATION)
	loop NextEntry
	mov eax,STATUS_NOT_FOUND
	jmp ParseError
GetObject:
	mov edx,[edx].Object
	mov ebx,Object
	xor eax,eax
	mov dword ptr [ebx],edx
ParseError:
	push eax
	invoke ZwFreeVirtualMemory, NtCurrentProcess, addr SystemInformation, addr SystemInformationLength, MEM_RELEASE
	pop eax
Exit:
	ret
QueryObject endp

SYSDBG_PHYSICAL struct
Address	QWORD ?
Buffer	PVOID ?
Request	ULONG ?
SYSDBG_PHYSICAL ends
PSYSDBG_PHYSICAL typedef ptr SYSDBG_PHYSICAL

SysDbgReadPhysical	equ 10	; XP

KdReadPhysicalMemory proc PhysicalAddress:PVOID, BufferAddress:PVOID, BytesToRead:ULONG
Local InputBuffer:SYSDBG_PHYSICAL
	xor eax,eax
	mov ecx,PhysicalAddress
	mov edx,BufferAddress
	mov dword ptr [InputBuffer.Address],ecx
	mov dword ptr [InputBuffer.Address + 4],eax
	mov InputBuffer.Buffer,edx
	push eax
	mov ecx,BytesToRead
	push eax
	push eax
	lea edx,InputBuffer
	mov InputBuffer.Request,ecx
	push sizeof(SYSDBG_PHYSICAL)
	push edx
	push SysDbgReadPhysical
	Call ZwSystemDebugControl
	ret	
KdReadPhysicalMemory endp

; +
; Для системного адресного пространства.
;
VIRTUAL_TO_PHYSICAL macro Ptr32
	.if (Ptr32 > 080000000H)  && (Ptr32 < 0A0000000h)
	and Ptr32,1FFFFFFFH
	.else
	and Ptr32,0FFFFFFH
	.endif
endm	

PsDirectoryTableBase	equ 18H	; EPROCESS.Pcb.DirectoryTableBase

; +
; Определяет адрес каталога страниц.
;
KdQueryProcessPageDirectoryTableBase proc ProcessHandle:HANDLE, DirectoryTableBase:PVOID
Local Object:DWORD
	invoke QueryObject, ProcessHandle, addr Object
	test eax,eax
	mov ecx,Object
	.if Zero?
	lea ecx,[ecx + PsDirectoryTableBase]
	VIRTUAL_TO_PHYSICAL Ecx	; System space.
	invoke KdReadPhysicalMemory, Ecx, DirectoryTableBase, sizeof(PVOID)
	.endif
	ret
KdQueryProcessPageDirectoryTableBase endp

PDE_P	equ 1B
PDE_PS	equ 10000000B
PTE_P	equ 1B

; +
; Чтение виртуальной памяти.
;
KdReadVirtualMemory proc uses ebx ProcessHandle:HANDLE, Address:PVOID, Buffer:PVOID, Request:ULONG
Local DirectoryTableBase:PVOID
Local TableEntry:PVOID
	invoke KdQueryProcessPageDirectoryTableBase, ProcessHandle, addr DirectoryTableBase	; PD
	test eax,eax
	jnz Exit
Portion:
	mov ecx,Address
	shr ecx,20
	and ecx,111111111100B
	add ecx,DirectoryTableBase
	invoke KdReadPhysicalMemory, Ecx, addr TableEntry, 4	; PDE
	test eax,eax
	mov ecx,TableEntry
	jnz Exit
	test ecx,PDE_P
	mov eax,STATUS_MEMORY_NOT_ALLOCATED
	jz Exit
	test ecx,PDE_PS
	jz @f
; 4M
	mov ebx,NOT(LARGE_PAGE_SIZE - 1)
	jmp Copy		
@@:
; 4K
	mov ebx,NOT(PAGE_SIZE - 1)
	mov eax,Address
	and ecx,ebx	; NOT(PAGE_SIZE - 1)
	shr eax,10
	and eax,111111111100B
	add ecx,eax
	invoke KdReadPhysicalMemory, Ecx, addr TableEntry, 4	; PTE
	test eax,eax
	mov ecx,TableEntry
	jnz Exit
	test ecx,PTE_P
	mov eax,STATUS_MEMORY_NOT_ALLOCATED
	jz Exit
Copy:
	mov eax,Address
	and ecx,ebx	; NOT(LARGE_PAGE_SIZE - 1)
	not ebx
	and eax,ebx	; (LARGE_PAGE_SIZE - 1)
	add ecx,eax
	not eax
	lea eax,[eax + ebx + 2]
	.if Request > Eax
	push eax
	sub Request,Eax
	push Buffer
	push ecx
	add Buffer,eax
	invoke KdReadPhysicalMemory, Ecx, Buffer, Eax	; P
	test eax,eax
	not ebx
	jnz Exit
	and Address,ebx	; NOT(LARGE_PAGE_SIZE - 1)
	not ebx
	add Address,ebx	; (LARGE_PAGE_SIZE - 1)
	inc Address
	jmp Portion
	.else
	invoke KdReadPhysicalMemory, Ecx, Buffer, Request	; P
	.endif
Exit:
	ret
KdReadVirtualMemory endp

KdReadVirtualMemoryEx proc ClientId:PCLIENT_ID, Address:PVOID, Buffer:PVOID, Request:ULONG
Local ObjAttr:OBJECT_ATTRIBUTES
Local ProcessHandle:HANDLE
	xor eax,eax
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	mov ObjAttr.hRootDirectory,eax
	mov ObjAttr.pSecurityDescriptor,eax
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.pObjectName,eax
	mov ObjAttr.uAttributes,eax
	invoke ZwOpenProcess, addr ProcessHandle, PROCESS_QUERY_INFORMATION, addr ObjAttr, ClientId
	.if !Eax
	invoke KdReadVirtualMemory, ProcessHandle, Address, Buffer, Request
	push eax
	invoke ZwClose, ProcessHandle
	pop eax
	.endif
	ret
KdReadVirtualMemoryEx endp