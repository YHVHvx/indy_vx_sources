
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
SysDbgWritePhysical	equ 11	; XP

KD_READ	equ 0
KD_WRITE	equ 1

; +
; Чтение/запись физической памяти.
;
KdPhysicalMemoryOperation proc PhysicalAddress:PVOID, BufferAddress:PVOID, BytesToRead:ULONG, ReadOrWrite:ULONG
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
	mov eax,ReadOrWrite
	mov InputBuffer.Request,ecx
	and eax,1
	push sizeof(SYSDBG_PHYSICAL)
	add eax,SysDbgReadPhysical
	push edx
	push eax
	Call ZwSystemDebugControl
	ret	
KdPhysicalMemoryOperation endp

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
	invoke KdPhysicalMemoryOperation, Ecx, DirectoryTableBase, sizeof(PVOID), KD_READ
	.endif
	ret
KdQueryProcessPageDirectoryTableBase endp

PDE_P	equ 1B
PDE_PS	equ 10000000B
PTE_P	equ 1B

; +
; Чтение/запись виртуальной памяти.
;
KdVirtualMemoryOperation proc uses ebx ProcessHandle:HANDLE, Address:PVOID, Buffer:PVOID, Request:ULONG, ReadOrWrite:ULONG
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
	invoke KdPhysicalMemoryOperation, Ecx, addr TableEntry, 4, KD_READ	; PDE
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
	invoke KdPhysicalMemoryOperation, Ecx, addr TableEntry, 4, KD_READ	; PTE
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
	invoke KdPhysicalMemoryOperation, Ecx, Buffer, Eax, ReadOrWrite	; P
	test eax,eax
	not ebx
	jnz Exit
	and Address,ebx	; NOT(LARGE_PAGE_SIZE - 1)
	not ebx
	add Address,ebx	; (LARGE_PAGE_SIZE - 1)
	inc Address
	jmp Portion
	.else
	invoke KdPhysicalMemoryOperation, Ecx, Buffer, Request, ReadOrWrite	; P
	.endif
Exit:
	ret
KdVirtualMemoryOperation endp

; +
;
KdVirtualMemoryOperationEx proc ClientId:PCLIENT_ID, Address:PVOID, Buffer:PVOID, Request:ULONG, ReadOrWrite:ULONG
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
	invoke KdVirtualMemoryOperation, ProcessHandle, Address, Buffer, Request, ReadOrWrite
	push eax
	invoke ZwClose, ProcessHandle
	pop eax
	.endif
	ret
KdVirtualMemoryOperationEx endp