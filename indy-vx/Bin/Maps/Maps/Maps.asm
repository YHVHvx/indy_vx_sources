	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
		
.code ENUMSECT
	jmp PsEnumerateMappedSections
	
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
	jmp ecx
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 3*4]
	jmp ecx
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
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

	include Stubs.inc
	include Img.asm

CompareUnicodeString proc uses esi edi String1:PUNICODE_STRING, String2:PUNICODE_STRING
	mov esi,String1
	mov edi,String2
	cld
	movzx ecx,UNICODE_STRING._Length[esi]
	cmp UNICODE_STRING._Length[edi],cx
	jne not_equ_
	mov esi,UNICODE_STRING.Buffer[esi]
	mov edi,UNICODE_STRING.Buffer[edi]
	shr ecx,1
	; Длину не проверяем на ноль.
@@:
	lodsw
	mov dx,word ptr [edi]
	and ax,NOT(20H)
	inc edi
	and dx,NOT(20H)
	inc edi
	cmp ax,dx
	jne not_equ_
	loop @b
	xor eax,eax
	jmp @f
not_equ_:
	xor eax,eax
	inc eax
@@:
	ret
CompareUnicodeString endp

; +
;
ConvertVolumeNameToDosName proc uses ebx esi ServicesList:PSERVICES_LIST, VolumeName:PUNICODE_STRING, ResultDosName:PULONG
Local SymbolicLinkHandle:HANDLE
Local ObjAttr:OBJECT_ATTRIBUTES
Local DosNameU:UNICODE_STRING
Local DosNameW[4]:WCHAR
Local LinkNameU:UNICODE_STRING
Local LinkNameW[MAX_PATH]:WCHAR
	lea ecx,LinkNameW
	mov ebx,ServicesList
	mov dword ptr [LinkNameW],'\' + '?' * 10000H
	mov dword ptr [LinkNameW + 4],'?'
	xor eax,eax
	lea edx,LinkNameU
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)	
	mov LinkNameU.Buffer,ecx
	mov dword ptr [LinkNameU],0080006H
	mov ObjAttr.hRootDirectory,eax	
	mov ObjAttr.pSecurityDescriptor,eax
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.uAttributes,eax
	mov ObjAttr.pObjectName,edx
	lea eax,ObjAttr
	lea ecx,ObjAttr.hRootDirectory
	$NtOpenDirectoryObject Ecx, DIRECTORY_QUERY, Eax
	lea ecx,DosNameU
	test eax,eax
	lea edx,DosNameW
	jnz Exit
	lea eax,LinkNameW
	mov ObjAttr.pObjectName,ecx
	mov DosNameU.Buffer,edx
	mov LinkNameU.Buffer,eax
	mov dword ptr [DosNameU],10000H*4 + 4
	mov LinkNameU.MaximumLength,MAX_PATH*2
; ProcessDeviceMap не используем, информация может быть изменена.
; Используем полный перебор имён.
	xor esi,esi	
Query:		
	lea eax,[esi + 'A' + ':' * 10000H]
	lea ecx,ObjAttr
	lea edx,SymbolicLinkHandle
	mov dword ptr [DosNameW],eax
	$NtOpenSymbolicLinkObject Edx, SYMBOLIC_LINK_QUERY, Ecx
	test eax,eax
	lea ecx,LinkNameU
	jnz Next
	$NtQuerySymbolicLinkObject SymbolicLinkHandle, Ecx, Eax
	push eax
	$NtClose SymbolicLinkHandle
	pop eax
	test eax,eax
	jnz Next
	invoke CompareUnicodeString, VolumeName, addr LinkNameU	; -> ZF
	je Error
Next:
	inc esi
	cmp esi,('Z' - 'A')
	jc Query
	mov eax,STATUS_OBJECT_NAME_NOT_FOUND
Error:
	push eax
	$NtClose ObjAttr.hRootDirectory
	pop eax
	.if !Eax	
	mov edx,ResultDosName
	mov dword ptr [edx],esi
	.endif
Exit:
	ret
ConvertVolumeNameToDosName endp

; +
;
ConvertVolumeToDosFileName proc uses ebx esi edi ServicesList:PSERVICES_LIST, VolumeFileName:PUNICODE_STRING, DosFileName:PUNICODE_STRING
Local LocalVolumeName:UNICODE_STRING
Local DosName:ULONG
	mov edi,VolumeFileName
	mov ax,'\'
	mov edi,UNICODE_STRING.Buffer[edi]
	cld
	mov LocalVolumeName.Buffer,edi
	mov ecx,MAX_PATH*2
	lea edi,[edi + 8*2]		; \Device\*
	mov edx,edi
	repne scasw	; \Device\Floppy0\*
	mov ecx,edi
	sub ecx,edx	; Length
	add ecx,8*2 - 2
	mov esi,edi
	mov LocalVolumeName._Length,cx
	mov LocalVolumeName.MaximumLength,cx
	invoke ConvertVolumeNameToDosName, ServicesList, addr LocalVolumeName, addr DosName
	test eax,eax
	cld
	jnz @f
	xor eax,eax
	mov ecx,MAX_PATH
	repne scasw
	mov eax,STATUS_INVALID_PARAMETER
	jne @f
	mov eax,MAX_PATH
	mov edx,DosFileName
	assume edx:PUNICODE_STRING
	sub eax,ecx
	dec eax
	mov ebx,eax
	lea ecx,[eax*2 + 2*3 + 2]
	cmp UNICODE_STRING.MaximumLength[edx],cx
	mov eax,STATUS_BUFFER_TOO_SMALL
	jc @f
	sub ecx,2
	mov edi,[edx].Buffer
	mov eax,DosName
	mov [edx]._Length,cx
	add eax,'A'
	mov word ptr [edi + 4],'\'
	or eax,':' * 10000H
	mov ecx,ebx
	mov dword ptr [edi],eax
	lea edi,[edi + 6]
	rep movsw
	mov word ptr [edi],cx
	xor eax,eax
@@:	
	ret
ConvertVolumeToDosFileName endp

; +
; o Динамическое определение ID сервисов из стабов.
; 
PsEnumerateMappedSections proc uses ebx esi edi ProcessHandle:HANDLE, CallbackRoutine:PVOID, UserParameter:DWORD
Local ServicesList:SERVICES_LIST
Local SystemInformation:SYSTEM_BASIC_INFORMATION
Local MemoryInformation:MEMORY_BASIC_INFORMATION
Local AllocationBase:PVOID, AllocationSize:ULONG
Local ImageBase:PVOID, ExitFlag:BOOLEAN
	lea edi,ServicesList
	xor eax,eax
	cld
	mov ebx,edi
	add eax,45341E13H	; NtAllocateVirtualMemory
	stosd
	xor eax,(9E62B844H xor 45341E13H)	; NtClose
	stosd
	xor eax,(0DA44FF17H xor 9E62B844H)	; NtFreeVirtualMemory
	stosd
	xor eax,(8C8729F1H xor 0DA44FF17H)	; NtOpenDirectoryObject
	stosd
	xor eax,(38F48033H xor 8C8729F1H)	; NtOpenSymbolicLinkObject
	stosd
	xor eax,(0BAFB2051H xor 38F48033H)	; NtQuerySymbolicLinkObject
	stosd
	xor eax,(70B4EB5AH	xor 0BAFB2051H)	; NtQuerySystemInformation
	stosd
	xor eax,(2A2DF819H	xor 70B4EB5AH)	; NtQueryVirtualMemory
	stosd
	xor eax,eax
	push ebx
	push eax
	stosd
	push eax
	Call LdrEncodeEntriesList
	test eax,eax
	jnz Exit
	mov esi,ebx
	mov edi,ebx
@@:
	lodsd
	test eax,eax
	jz @f
	cmp byte ptr [eax],0B8H	; mov eax,#
	jne Error
	mov eax,dword ptr [eax + 1]
	cmp eax,1000H
	jnb Error
	stosd
	loop @b
@@:
	lea edx,SystemInformation
; Последняя страница 0x7FFE0000, можно задать константой.
	$NtQuerySystemInformation SystemBasicInformation, Edx, sizeof(SYSTEM_BASIC_INFORMATION), Eax
	test eax,eax
	mov AllocationSize,MAX_PATH*4
	jnz Exit
	lea ecx,AllocationSize
	lea edx,AllocationBase
	mov AllocationBase,eax
	$NtAllocateVirtualMemory NtCurrentProcess, Edx, Eax, Ecx, MEM_COMMIT, PAGE_READWRITE
	test eax,eax
	mov edi,AllocationBase
	jnz Exit
	lea esi,[edi + MAX_PATH*2]
	lea eax,[esi + sizeof(UNICODE_STRING)]
	mov ImageBase,-1
	assume esi:PUNICODE_STRING
	mov [esi].Buffer,eax
Query:
	lea ecx,MemoryInformation
	$NtQueryVirtualMemory ProcessHandle, SystemInformation.MinimumUserModeAddress, MemoryBasicInformation, Ecx, sizeof(MEMORY_BASIC_INFORMATION), NULL
	test eax,eax
	jnz Free
	test MemoryInformation._Type,MEM_MAPPED or MEM_IMAGE
	jz Next
	$NtQueryVirtualMemory ProcessHandle, MemoryInformation.BaseAddress, MemorySectionName, Edi, MAX_PATH*2, Eax
	test eax,eax
	mov edx,MemoryInformation.AllocationBase
	jnz Next
	cmp ImageBase,edx
	je Next
	mov ImageBase,edx
	mov UNICODE_STRING.MaximumLength[esi],MAX_PATH*2
	invoke ConvertVolumeToDosFileName, Ebx, Edi, Esi
	test eax,eax
	jne Next
	lea edx,ExitFlag
	lea ecx,MemoryInformation
	mov ExitFlag,eax
	push edx
	push UserParameter
	push esi
	push edi
	push ecx
	push ProcessHandle
	Call CallbackRoutine
	test eax,eax
	jnz Free
	cmp ExitFlag,eax
	jne Free
Next:
	mov eax,MemoryInformation.BaseAddress
	add eax,MemoryInformation.RegionSize
	cmp eax,SystemInformation.MaximumUserModeAddress
	mov SystemInformation.MinimumUserModeAddress,eax
	jc Query
	xor eax,eax
Free:
	lea ecx,AllocationSize
	push eax
	lea edx,AllocationBase
	$NtFreeVirtualMemory NtCurrentProcess, Edx, Ecx, MEM_RELEASE
	pop eax
Exit:
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
PsEnumerateMappedSections endp

.code
CR	equ 13
LF	equ 10

$Msg	CHAR "BaseAddress: %p", CR, LF
	CHAR "%wZ", CR, LF
	CHAR "%wZ", CR, LF
	CHAR "-", CR, LF
	CHAR 0

xxxCallbackRoutine::
	%GET_CURRENT_GRAPH_ENTRY
xxxCallbackRoutineInternal proc ProcessHandle:HANDLE, MemoryInformation:PMEMORY_BASIC_INFORMATION, NtImageName:PUNICODE_STRING, DosImageName:PUNICODE_STRING, UserParameter:PVOID, ExitFlag:PBOOLEAN
	mov edx,MemoryInformation
	assume edx:PMEMORY_BASIC_INFORMATION
	invoke DbgPrint, addr $Msg, [edx].BaseAddress, NtImageName, DosImageName
	xor eax,eax
	ret
xxxCallbackRoutineInternal endp
	
Entry proc
	%GET_GRAPH_ENTRY xxxCallbackRoutine
	invoke PsEnumerateMappedSections, NtCurrentProcess, Eax, 0
	ret
Entry endp
end Entry