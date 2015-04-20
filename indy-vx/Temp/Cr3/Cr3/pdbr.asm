	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib	
;-------------------------------------------------------------------------------	
.code
$SectionName	CHAR "\Device\PhysicalMemory",0

OpenPhysicalMemorySection proc SectionHandle:PHANDLE
Local ObjAttr:OBJECT_ATTRIBUTES
Local SectionNameU:UNICODE_STRING
	invoke RtlCreateUnicodeStringFromAsciiz, addr SectionNameU, addr $SectionName
	xor eax,eax
	lea edx,SectionNameU
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	mov ObjAttr.hRootDirectory,eax
	mov ObjAttr.uAttributes,OBJ_CASE_INSENSITIVE
	mov ObjAttr.pSecurityDescriptor,eax
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.pObjectName,edx
	invoke ZwOpenSection, SectionHandle, SECTION_MAP_READ or SECTION_MAP_WRITE, addr ObjAttr
	push eax
	invoke RtlFreeUnicodeString, addr SectionNameU
	pop eax
	ret
OpenPhysicalMemorySection endp

MapViewOfPhysicalMemorySection proc SectionHandle:HANDLE, PhysicalAddress:DWORD, ViewBase:PVOID, ViewSize:PULONG, Protect:ULONG
Local SectionOffset:LARGE_INTEGER
	xor edx,edx
	mov eax,PhysicalAddress
	mov dword ptr [SectionOffset + 4],edx
	mov dword ptr [SectionOffset],eax
	invoke ZwMapViewOfSection, SectionHandle, NtCurrentProcess, ViewBase, Edx, Edx, addr SectionOffset, ViewSize, ViewShare, Edx, Protect
	ret
MapViewOfPhysicalMemorySection endp

BASE_REGION_SIZE	equ 10000H

; +
; Опредедяет указатель на EPROCESS.
;
QueryProcessObject proc uses ebx ProcessHandle:HANDLE, Object:PVOID
Local SystemInformation:PVOID, SystemInformationLength:ULONG
Local ProcessInformation:PROCESS_BASIC_INFORMATION
	invoke ZwQueryInformationProcess, NtCurrentProcess, ProcessBasicInformation, addr ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), NULL
	test eax,eax
	mov ebx,BASE_REGION_SIZE
	jnz exit_
next_region_:
	mov SystemInformationLength,ebx
	mov SystemInformation,NULL
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr SystemInformation, 0, addr SystemInformationLength, MEM_COMMIT, PAGE_READWRITE
	test eax,eax
	jnz exit_
	invoke ZwQuerySystemInformation, SystemHandleInformation, SystemInformation, SystemInformationLength, Eax
	test eax,eax
	jz parse_info_
	push eax
	invoke ZwFreeVirtualMemory, NtCurrentProcess, addr SystemInformation, addr SystemInformationLength, MEM_RELEASE
	pop eax
	cmp eax,STATUS_INFO_LENGTH_MISMATCH
	jnz exit_
	add ebx,BASE_REGION_SIZE
	cmp ebx,32*BASE_REGION_SIZE
	jb next_region_
	jmp exit_
parse_info_:
	mov edx,SystemInformation
	mov ebx,ProcessInformation.UniqueProcessId
	mov ecx,dword ptr [edx]
	mov eax,ProcessHandle
	add edx,4
next_entry_:
	assume edx:PSYSTEM_HANDLE_INFORMATION
	cmp [edx].ProcessId,ebx
	jne @f
	cmp [edx].Handle,ax
	je get_object_
@@:
	add edx,sizeof(SYSTEM_HANDLE_INFORMATION)
	loop next_entry_
	mov eax,STATUS_NOT_FOUND
	jmp err_parse_
get_object_:
	mov edx,[edx].Object
	mov ebx,Object
	xor eax,eax
	mov dword ptr [ebx],edx
err_parse_:
	push eax
	invoke ZwFreeVirtualMemory, NtCurrentProcess, addr SystemInformation, addr SystemInformationLength, MEM_RELEASE
	pop eax
exit_:
	ret
QueryProcessObject endp

; +
; Для системного адресного пространства.
;
VIRTUAL_TO_PHYSICAL macro Reg32
	.if (Reg32 > 080000000H)  && (Reg32 < 0A0000000h)
	and Reg32,1FFFFFFFH
	.else
	and Reg32,0FFFFFFH
	.endif
endm	

PsDirectoryTableBase	equ 18H	; EPROCESS.Pcb.DirectoryTableBase

; +
; Определяет указатель на каталог страниц(это значение загружается в Cr3(PDBR) при переключении на новый процесс).
;
QueryProcessPageDirectoryTableBase proc uses ebx SectionHandle:HANDLE, ProcessHandle:HANDLE, DirectoryTableBase:PVOID
Local Object:DWORD
Local ViewBase:PVOID, ViewSize:ULONG
	invoke QueryProcessObject, ProcessHandle, addr Object
	test eax,eax
	jnz Exit
	mov ebx,Object
	mov ViewBase,eax
	VIRTUAL_TO_PHYSICAL Ebx
	lea ecx,ViewSize
	lea edx,ViewBase
	push PAGE_READONLY
	push ecx
	push edx
	push ebx
	mov ViewSize,PAGE_SIZE	; Size of object.
	and dword ptr [esp],NOT(PAGE_SIZE - 1)
	push SectionHandle
	and ebx,(PAGE_SIZE - 1)	; Offset in page.
	Call MapViewOfPhysicalMemorySection
	test eax,eax
	jnz Exit
	add ebx,ViewBase	; PEPROCESS
	mov ebx,dword ptr [ebx + PsDirectoryTableBase]
	invoke ZwUnmapViewOfSection, NtCurrentProcess, ViewBase
	mov edx,DirectoryTableBase
	xor eax,eax
	mov dword ptr [edx],ebx
Exit:
	ret
QueryProcessPageDirectoryTableBase endp

; +
; Проецирует страницу с каталагом страниц(DT).
;
MapViewOfPageDirectoryTable proc SectionHandle:HANDLE, ProcessHandle:HANDLE, ViewBase:PVOID
Local DirectoryTableBase:DWORD
Local ViewSize:ULONG
	invoke QueryProcessPageDirectoryTableBase, SectionHandle, ProcessHandle, addr DirectoryTableBase
	test eax,eax
	mov ViewSize,PAGE_SIZE
	jnz @f
	invoke MapViewOfPhysicalMemorySection, SectionHandle, DirectoryTableBase, ViewBase, addr ViewSize, PAGE_READONLY
@@:
	ret
MapViewOfPageDirectoryTable endp

PDE_P	equ 1B
PDE_PS	equ 10000000B
PTE_P	equ 1B

; +
; Проецирует страницу. Адрес выравнивается на границу страницы.
;
MapViewOfPage proc uses ebx SectionHandle:HANDLE, ProcessHandle:HANDLE, PageAddress:PVOID, PageViewBase:PVOID
Local ViewBase:PVOID, ViewSize:ULONG
	mov ViewBase,0
	and PageAddress,NOT(PAGE_SIZE - 1)
	invoke MapViewOfPageDirectoryTable, SectionHandle, ProcessHandle, addr ViewBase
	test eax,eax
	mov ebx,PageAddress
	jnz Exit
	shr ebx,20
	mov ecx,ViewBase
	and ebx,111111111100B
	mov ebx,dword ptr [ebx + ecx]	; PDE
	invoke ZwUnmapViewOfSection, NtCurrentProcess, ViewBase
	test ebx,PDE_P
	mov eax,STATUS_MEMORY_NOT_ALLOCATED
	jz Exit
	test ebx,PDE_PS
	mov ViewSize,PAGE_SIZE
	jz @f
; 4M
	and ebx,NOT(LARGE_PAGE_SIZE - 1)
	mov ViewSize,LARGE_PAGE_SIZE
	jmp MapPage	
@@:
	and ebx,NOT(PAGE_SIZE - 1)
	mov ViewBase,0
; Проецируем таблицу страниц.
	invoke MapViewOfPhysicalMemorySection, SectionHandle, Ebx, addr ViewBase, addr ViewSize, PAGE_READWRITE
	test eax,eax
	mov ebx,PageAddress
	jnz Exit
	shr ebx,10
	mov ecx,ViewBase
	and ebx,111111111100B
	mov ebx,dword ptr [ebx + ecx]	; PTE
	invoke ZwUnmapViewOfSection, NtCurrentProcess, ViewBase
	test ebx,PTE_P
	mov eax,STATUS_MEMORY_NOT_ALLOCATED
	jz Exit
	and ebx,NOT(PAGE_SIZE - 1)
	mov ViewSize,PAGE_SIZE
MapPage:
; Проецируем страницу.
	invoke MapViewOfPhysicalMemorySection, SectionHandle, Ebx, PageViewBase, addr ViewSize, PAGE_READWRITE
Exit:
	ret
MapViewOfPage endp

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

$Msg	CHAR "CmdLine: %ws", 13, 10, 0

gProcessID	HANDLE 4084

	assume fs:nothing
Entry proc
Local SectionHandle:HANDLE
Local ProcessHandle:HANDLE, ClientId:CLIENT_ID
Local ProcessInformation:PROCESS_BASIC_INFORMATION
Local ObjAttr:OBJECT_ATTRIBUTES
Local ViewBase:PVOID
Local ViewSize:ULONG
Local Privilege:ULONG
	invoke RtlAdjustPrivilege, SE_DEBUG_PRIVILEGE, TRUE, FALSE, addr Privilege
	BREAKERR

	invoke OpenPhysicalMemorySection, addr SectionHandle
	BREAKERR
	mov ecx,gProcessID
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	test ecx,ecx
	mov ObjAttr.hRootDirectory,eax
	.if Zero?
	mov ecx,fs:[TEB.Cid.UniqueProcess]
	.endif
	mov ObjAttr.pSecurityDescriptor,eax
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.pObjectName,eax
	mov ObjAttr.uAttributes,eax
	mov ClientId.UniqueThread,eax
	mov ClientId.UniqueProcess,ecx
	invoke ZwOpenProcess, addr ProcessHandle, PROCESS_ALL_ACCESS, addr ObjAttr, addr ClientId	; PROCES
	BREAKERR
	mov ViewBase,eax
	invoke MapViewOfPage, SectionHandle, ProcessHandle, 7D0000H, addr ViewBase
	BREAKERR



	and ebx,(PAGE_SIZE - 1)
	add ebx,ViewBase
	invoke DbgPrint, addr $Msg, Ebx
	invoke ZwUnmapViewOfSection, NtCurrentProcess, ViewBase
	ret
Entry endp
end Entry