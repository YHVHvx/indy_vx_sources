	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	include \masm32\include\user32.inc	
	includelib \masm32\lib\user32.lib	
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
	invoke ZwOpenSection, SectionHandle, SECTION_MAP_READ, addr ObjAttr
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
; Опредедяет адрес описателя обьекта(KPROCESS, KTIMER etc).
;
QueryObject proc uses ebx ObjectHandle:HANDLE, Object:PVOID
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
	mov eax,ObjectHandle
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
QueryObject endp

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
	invoke QueryObject, ProcessHandle, addr Object
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
	invoke MapViewOfPhysicalMemorySection, SectionHandle, Ebx, addr ViewBase, addr ViewSize, PAGE_READONLY
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
	invoke MapViewOfPhysicalMemorySection, SectionHandle, Ebx, PageViewBase, addr ViewSize, PAGE_READONLY
Exit:
	ret
MapViewOfPage endp

comment '
KTHREAD.InitialStack:
	FX_SAVE_AREA <>	; Npx frame.
KTSS.Esp0:
	KTRAP_FRAME <>		; Trap frame.
KTHREAD.TrapFrame:		; Текущий фрейм.
CONTEXT.rEbp:			; Последний в цепочке стековых фреймов(SFC).
	...
CONTEXT.rEsp:			; Текущий ядерный стек.
	...
	'
NPX_FRAME_LENGTH equ 00210H
KTRAP_FRAME_LENGTH equ 0008CH

; Trap Frame Offset Definitions
;
TsDr0	equ 00018H
TsDr1	equ 0001CH
TsDr2	equ 00020H
TsDr3	equ 00024H
TsDr6	equ 00028H
TsDr7	equ 0002CH
TsSegGs	equ 00030H
TsSegEs	equ 00034H
TsSegDs	equ 00038H
TsEdx	equ 0003CH
TsEcx	equ 00040H
TsEax	equ 00044H
TsSegFs	equ 00050H
TsEdi	equ 00054H
TsEsi	equ 00058H
TsEbx	equ 0005CH
TsEbp	equ 00060H
; IRET-frame.
TsEip	equ 00068H
TsSegCs	equ 0006CH
TsEflags	equ 00070H
TsHardwareEsp		equ 00074H
TsHardwareSegSs	equ 00078H

KTRAP_FRAME struct
DbgEbp		ULONG ?
DbgEip		ULONG ?
DbgArgMark	ULONG ?
DbgArgPointer	ULONG ?

TempSegCs		ULONG ?
TempEsp		ULONG ?

rDr0			ULONG ?
rDr1			ULONG ?
rDr2			ULONG ?
rDr3			ULONG ?
rDr6			ULONG ?
rDr7			ULONG ?

SegGs		ULONG ?
SegEs		ULONG ?
SegDs		ULONG ?

rEdx			ULONG ?
rEcx			ULONG ?
rEax			ULONG ?

PreviousPreviousMode	ULONG ?

ExceptionList	PVOID ?

SegFs		ULONG ?

rEdi			ULONG ?
rEsi			ULONG ?
rEbx			ULONG ?
rEbp			ULONG ?

; IRET-frame.
ErrCode		ULONG ?
rEip			ULONG ?
rSegCs		ULONG ?
rEFlags		ULONG ?

HardwareEsp	ULONG ?
HardwareSegSs	ULONG ?

V86Es		ULONG ?
V86Ds		ULONG ?
V86Fs		ULONG ?
V86Gs		ULONG ?
KTRAP_FRAME ends
PKTRAP_FRAME typedef ptr KTRAP_FRAME

ThInitialStack equ 00018H

;
; Usermode callout frame.
;
CALLOUT_FRAME struct
InitialStack	PVOID ?
TrapFrame		PKTRAP_FRAME ?
CallbackStack	PVOID ?	; PCALLBACK_STACK
rEdi			DWORD ?
rEsi			DWORD ?
rEbx			DWORD ?
rEbp			DWORD ?
rEip			DWORD ?
Buffer		PVOID ?
BufferLength	ULONG ?
CALLOUT_FRAME ends
PCALLOUT_FRAME typedef ptr CALLOUT_FRAME

ThCallbackStack	equ 12CH

; +
; Проецирует часть ядерного стека, сожержащую базовый трап-фрейм.
;
MapViewOfTrapFrame proc uses ebx SectionHandle:HANDLE, ProcessHandle:HANDLE, ThreadHandle:HANDLE, TrapFrame:PVOID
Local ThreadObject:PVOID	; PETHREAD
Local ViewBase:PVOID, ViewSize:ULONG
	invoke QueryObject, ThreadHandle, addr ThreadObject
	test eax,eax
	mov ebx,ThreadObject
	jnz Exit
	VIRTUAL_TO_PHYSICAL Ebx
	mov ViewBase,eax
	mov ViewSize,PAGE_SIZE
	invoke MapViewOfPhysicalMemorySection, SectionHandle, Ebx, addr ViewBase, addr ViewSize, PAGE_READONLY
	and ebx,(PAGE_SIZE - 1)
	test eax,eax
	jnz Exit
	add ebx,ViewBase
	mov ebx,dword ptr [ebx + ThInitialStack]	; Выравнен на границу страницы.
	invoke ZwUnmapViewOfSection, NtCurrentProcess, ViewBase
	sub ebx,(KTRAP_FRAME_LENGTH + NPX_FRAME_LENGTH)
	mov ViewBase,0
	invoke MapViewOfPage, SectionHandle, ProcessHandle, Ebx, addr ViewBase
	and ebx,(PAGE_SIZE - 1)
	test eax,eax
	mov ecx,TrapFrame
	jnz Exit
	add ebx,ViewBase
	mov dword ptr [ecx],ebx
Exit:
	ret
MapViewOfTrapFrame endp

MapViewOfTrapFrameEx proc SectionHandle:HANDLE, ThreadHandle:HANDLE, TrapFrame:PVOID
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
	invoke MapViewOfTrapFrame, SectionHandle, ProcessHandle, ThreadHandle, TrapFrame
	push eax
	invoke ZwClose, ProcessHandle
	pop eax
Exit:
	ret
MapViewOfTrapFrameEx endp

MapViewOfCalloutFrame proc uses ebx SectionHandle:HANDLE, ProcessHandle:HANDLE, ThreadHandle:HANDLE, CalloutStack:PVOID
Local ThreadObject:PVOID	; PETHREAD
Local ViewBase:PVOID, ViewSize:ULONG
;	invoke ZwSuspendThread, ThreadHandle, NULL
;	test eax,eax
;	jnz Exit
	invoke QueryObject, ThreadHandle, addr ThreadObject
	test eax,eax
	mov ebx,ThreadObject
	jnz Resume
	VIRTUAL_TO_PHYSICAL Ebx
	mov ViewBase,eax
	mov ViewSize,PAGE_SIZE
	invoke MapViewOfPhysicalMemorySection, SectionHandle, Ebx, addr ViewBase, addr ViewSize, PAGE_READONLY
	and ebx,(PAGE_SIZE - 1)
	test eax,eax
	jnz Resume
	add ebx,ViewBase
	mov ebx,dword ptr [ebx + ThCallbackStack]
	invoke ZwUnmapViewOfSection, NtCurrentProcess, ViewBase
	mov ViewBase,0
	invoke MapViewOfPage, SectionHandle, ProcessHandle, Ebx, addr ViewBase
	and ebx,(PAGE_SIZE - 1)
	test eax,eax
	mov ecx,CalloutStack
	jnz Resume
	add ebx,ViewBase
	mov dword ptr [ecx],ebx
Resume:
;	push eax
;	invoke ZwResumeThread, ThreadHandle, NULL
;	pop eax
Exit:
	ret
MapViewOfCalloutFrame endp

MapViewOfCalloutFrameEx proc SectionHandle:HANDLE, ThreadHandle:HANDLE, CalloutStack:PVOID
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
	invoke MapViewOfCalloutFrame, SectionHandle, ProcessHandle, ThreadHandle, CalloutStack
	push eax
	invoke ZwClose, ProcessHandle
	pop eax
Exit:
	ret
MapViewOfCalloutFrameEx endp

MapViewOfPageInternal proc SectionHandle:HANDLE, PageAddress:PVOID, PageViewBase:PVOID
Local ThreadInformation:THREAD_BASIC_INFORMATION
Local ObjAttr:OBJECT_ATTRIBUTES
Local ProcessHandle:HANDLE
	invoke ZwQueryInformationThread, NtCurrentThread, ThreadBasicInformation, addr ThreadInformation, sizeof(THREAD_BASIC_INFORMATION), NULL
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
	invoke MapViewOfPage, SectionHandle, ProcessHandle, PageAddress, PageViewBase
	push eax
	invoke ZwClose, ProcessHandle
	pop eax
Exit:
	ret
MapViewOfPageInternal endp

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

_imp__EnumDisplayMonitors proto :dword, :dword, :dword, :dword

MessageBeep proto :dword

QUERY_SERVICE_ID macro
	mov eax,dword ptr [_imp__EnumDisplayMonitors]
	mov eax,dword ptr [eax + 1]	; ID NtUserEnumDisplayMonitors
endm

; +
; Сохранение контекста.
; o Eax: адрес возврата при восстановлении контекста.
; o Сохраняются регистры:
;   - EFlags
;   - Ebp
;   - Ebx
;   - Esp
; o NPX не сохраняется.
;
SAVE_TASK_STATE macro
Local Break
	mov esi,eax
	mov edi,esp
	Call @f
	jmp Break
@@:	
	pushad
	xor ecx,ecx
	push esp
	Call @f
	mov esp,dword ptr [esp + 4*4]
	popad
	retn
@@:
	push ecx
	push ecx
	QUERY_SERVICE_ID
	mov edx,esp
	Int 2EH
	xor eax,eax
	mov esp,edi
	jmp esi
Break:
endm

; Восстановление контекста.
;
RESTORE_TASK_STATE macro
	xor eax,eax
	mov edx,3*4
	push eax
	push eax
	push eax
	mov ecx,esp
	Int 2BH
endm

PUBLIC gThreadEip

ThreadRoutine proc StartupParameter:DWORD
	invoke MessageBeep, 0
	lea eax,offset cbRet
	SAVE_TASK_STATE
	xor ebx,ebx
	xor esi,esi
	xor edi,edi
	xor ebp,ebp
	lea eax,offset cbRet2
	SAVE_TASK_STATE
gThreadEip::
	jmp gThreadEip
	RESTORE_TASK_STATE
	int 3
	int 3
cbRet:
	nop
cbRet2:
	nop
	nop
	ret
ThreadRoutine endp

$Dll	CHAR "User32.dll",0

Entry proc
Local SectionHandle:HANDLE
Local ClientId:CLIENT_ID, ThreadHandle:HANDLE
Local TrapFrame:PKTRAP_FRAME
Local CalloutFrame:PCALLOUT_FRAME
Local Interval:LARGE_INTEGER
Local ViewBase:PVOID
	invoke OpenPhysicalMemorySection, addr SectionHandle
	BREAKERR
	invoke RtlCreateUserThread, NtCurrentProcess, NULL, FALSE, 0, 0, 0, ThreadRoutine, 0, addr ThreadHandle, addr ClientId
	BREAKERR
	mov dword ptr [Interval],0FFF0BDC0H	; 100ms
	mov dword ptr [Interval + 4],0FFFFFFFFH
	invoke Sleep, 1000
	invoke ZwDelayExecution, FALSE, addr Interval
	invoke ZwSuspendThread, ThreadHandle, NULL
	BREAKERR
	invoke MapViewOfCalloutFrameEx, SectionHandle, ThreadHandle, addr CalloutFrame
	BREAKERR
	mov ebx,CalloutFrame
@@:
	mov TrapFrame,eax
	mov ebx,CALLOUT_FRAME.TrapFrame[ebx]
	invoke MapViewOfPageInternal, SectionHandle, Ebx, addr TrapFrame
	and ebx,(PAGE_SIZE - 1)
	add ebx,TrapFrame
	mov ebx,KTRAP_FRAME.rEip[ebx]
	nop
	mov ebx,CalloutFrame
	mov ebx,CALLOUT_FRAME.CallbackStack[ebx]
	mov CalloutFrame,eax
	invoke MapViewOfPageInternal, SectionHandle, Ebx, addr CalloutFrame
	and ebx,(PAGE_SIZE - 1)
	add ebx,CalloutFrame
	jmp @b
	
	
	
	mov ebx,KTRAP_FRAME.rEip[ebx]

	
	

	mov ebx,TrapFrame
	assume ebx:PKTRAP_FRAME
	mov ecx,[ebx].rEax	; 12345678H
	mov edx,[ebx].rEip	; @gThreadEip
	int 3
	invoke ZwUnmapViewOfSection, NtCurrentProcess, TrapFrame
	ret
Entry endp
end Entry

CALLOUT_FRAME struct
InitialStack	PVOID ?
TrapFrame		PVOID ?	; KTRAP_FRAME
CallbackStack	PVOID ?	; PCALLBACK_STACK
rEdi			DWORD ?
rEsi			DWORD ?
rEbx			DWORD ?
rEbp			DWORD ?
rEip			DWORD ?
Buffer		PVOID ?
BufferLength	ULONG ?
CALLOUT_FRAME ends
PCALLOUT_FRAME typedef ptr CALLOUT_FRAME

; ETHREAD.CalloutStack:PCALLOUT_FRAME
;
ThCallbackStack	equ 12CH	; XP

; KTRAP_FRAME.rEip
;
TsEip	equ 00068H

; Eax: PETHREAD
	mov eax,dword ptr [eax + ThCallbackStack]
	.if Eax
	mov eax,CALLOUT_FRAME.TrapFrame[eax]
	mov eax,dword ptr [eax + TsEip]
	.endif