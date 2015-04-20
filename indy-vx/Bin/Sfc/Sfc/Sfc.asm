	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
.code
PROCESS_HANDLE_TRACING_ENABLE struct
Flags		ULONG ?
PROCESS_HANDLE_TRACING_ENABLE ends

PROCESS_HANDLE_TRACING_MAX_STACKS	equ 16

HANDLE_TRACE_DB_OPEN	equ 1
HANDLE_TRACE_DB_CLOSE	equ 2
HANDLE_TRACE_DB_BADREF	equ 3

PROCESS_HANDLE_TRACING_ENTRY struct
Handle		HANDLE ?
ClientId		CLIENT_ID <>
_Type		ULONG ?	; HANDLE_TRACE_DB_*
Stacks		PVOID PROCESS_HANDLE_TRACING_MAX_STACKS DUP (?)
PROCESS_HANDLE_TRACING_ENTRY ends

PROCESS_HANDLE_TRACING_QUERY struct
Handle		HANDLE ?
TotalTraces	ULONG ?
HandleTrace	PROCESS_HANDLE_TRACING_ENTRY 1 DUP (<>)
PROCESS_HANDLE_TRACING_QUERY ends

ProcessHandleTracing	equ 32

RTL_PROCESS_MODULE_INFORMATION struct
Section			HANDLE ?
MappedBase		PVOID ?
ImageBase			PVOID ?
ImageSize			ULONG ?
Flags			ULONG ?
LoadOrderIndex		USHORT ?
InitOrderIndex		USHORT ?
LoadCount			USHORT ?
OffsetToFileName	USHORT ?
FullPathName		UCHAR 256 DUP (?)
RTL_PROCESS_MODULE_INFORMATION ends
PRTL_PROCESS_MODULE_INFORMATION typedef ptr RTL_PROCESS_MODULE_INFORMATION

SYSTEM_BASIC_INFORMATION struct
Reserved					ULONG ?
TimerResolution			ULONG ?
PageSize					ULONG ?
NumberOfPhysicalPages		ULONG ?
LowestPhysicalPageNumber		ULONG ?
HighestPhysicalPageNumber	ULONG ?
AllocationGranularity		ULONG ?
MinimumUserModeAddress		ULONG ?
MaximumUserModeAddress		ULONG ?
ActiveProcessorsAffinityMask	ULONG ?
NumberOfProcessors			BYTE ?
_align					byte 3 dup (?)
SYSTEM_BASIC_INFORMATION ends
PSYSTEM_BASIC_INFORMATION typedef ptr SYSTEM_BASIC_INFORMATION

; * SFC:
; 	RtlWalkFrameChain
; 	ExCreateHandle
; 	ObpCreateHandle
; 	ObOpenObjectByPointer
; 	NtOpenProcess
;	[User]
;
	assume fs:nothing
xValidateKernelSfc proc uses ebx esi edi ResultInformation:PRTL_PROCESS_MODULE_INFORMATION
Local Tracing:PROCESS_HANDLE_TRACING_ENABLE
Local TraceInformation:PROCESS_HANDLE_TRACING_QUERY
Local ObjAttr:OBJECT_ATTRIBUTES, ProcessHandle:HANDLE
Local ModuleInformation:PVOID, InformationLength:ULONG
Local SystemInformation:SYSTEM_BASIC_INFORMATION
	invoke ZwQuerySystemInformation, SystemBasicInformation, addr SystemInformation, sizeof(SYSTEM_BASIC_INFORMATION), NULL
	test eax,eax
	jnz Exit
	mov Tracing,eax
	invoke ZwSetInformationProcess, NtCurrentProcess, ProcessHandleTracing, addr Tracing, sizeof(PROCESS_HANDLE_TRACING_ENABLE)
	test eax,eax
	jnz Exit
	mov ecx,fs:[TEB.Tib.Self]
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	mov ObjAttr.hRootDirectory,eax
	mov ObjAttr.pSecurityDescriptor,eax
	lea ecx,TEB.Cid[ecx]
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.pObjectName,eax
	mov ObjAttr.uAttributes,eax
	invoke ZwOpenProcess, addr ProcessHandle, PROCESS_ALL_ACCESS, addr ObjAttr, Ecx
	test eax,eax
	mov ecx,ProcessHandle
	jnz Exit
	mov TraceInformation.Handle,ecx
	invoke ZwQueryInformationProcess, NtCurrentProcess, ProcessHandleTracing, addr TraceInformation, sizeof(PROCESS_HANDLE_TRACING_QUERY), addr InformationLength
	test eax,eax
	jnz Close
	mov ModuleInformation,eax
	cmp InformationLength,sizeof(PROCESS_HANDLE_TRACING_QUERY)
	mov eax,STATUS_UNSUCCESSFUL
	jne Close
	cmp TraceInformation.TotalTraces,1
	jne Close
	cmp TraceInformation.HandleTrace._Type,HANDLE_TRACE_DB_OPEN
	jne Close
	invoke ZwQuerySystemInformation, SystemModuleInformation, NULL, NULL, addr InformationLength
	cmp eax,STATUS_INFO_LENGTH_MISMATCH
	jne Close
	add InformationLength,PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr ModuleInformation, 0, addr InformationLength, MEM_COMMIT, PAGE_READWRITE
	test eax,eax
	jnz Close
	invoke ZwQuerySystemInformation, SystemModuleInformation, ModuleInformation, InformationLength, Eax
	test eax,eax
	mov edi,ModuleInformation
	jnz Free
	lea esi,[edi + 4]
	xor ebx,ebx
	mov edi,dword ptr [edi]	; Count.
	assume esi:PRTL_PROCESS_MODULE_INFORMATION	; NT
	mov ecx,[esi].ImageBase
	mov edx,[esi].ImageSize
	add edx,ecx
@@:
	mov eax,TraceInformation.HandleTrace.Stacks[ebx*4]
	test eax,eax
	jz Success
	cmp SystemInformation.MaximumUserModeAddress,eax
	ja Success
	cmp eax,ecx
	jb Grab
	cmp eax,edx
	jnb Grab
	inc ebx
	cmp ebx,PROCESS_HANDLE_TRACING_MAX_STACKS
	jb @b
Success:
	mov eax,STATUS_NOT_FOUND
	jmp Free
Grab:
	add esi,sizeof(RTL_PROCESS_MODULE_INFORMATION)
	mov ecx,[esi].ImageBase
	cmp eax,ecx
	jb @f
	add ecx,[esi].ImageSize
	cmp eax,ecx
	jnb @f
	mov edi,ResultInformation
	mov ecx,sizeof(RTL_PROCESS_MODULE_INFORMATION)/4
	cld
	xor eax,eax
	rep movsd
	jmp Free	
@@:
	dec edi
	jnz Grab
	mov eax,STATUS_WAIT_1
Free:
	push eax
	invoke ZwFreeVirtualMemory, NtCurrentProcess, addr ModuleInformation, addr InformationLength, MEM_RELEASE
	pop eax
Close:
	push eax
	invoke ZwClose, ProcessHandle
	pop eax
Exit:
	ret
xValidateKernelSfc endp

$Found		CHAR "Found %s", 13, 10, 0
$GrabNotFound	CHAR "Grab not found", 13, 10, 0
$ImageNotFound	CHAR "Image not found", 13, 10, 0
$Error		CHAR "Status: 0x%p", 13, 10, 0

Entry proc
Local Information:RTL_PROCESS_MODULE_INFORMATION
	invoke xValidateKernelSfc, addr Information
	.if !Eax
	invoke DbgPrint, addr $Found, addr Information.FullPathName
	.elseif Eax == STATUS_NOT_FOUND
	invoke DbgPrint, addr $GrabNotFound
	.elseif Eax == STATUS_WAIT_1
	invoke DbgPrint, addr $ImageNotFound
	.else
	invoke DbgPrint, addr $Error, Eax
	.endif
	ret
Entry endp
end Entry