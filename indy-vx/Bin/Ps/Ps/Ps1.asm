	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

_imp__ZwResumeThread proto :dword, :dword
_imp__CreateProcessA proto :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword

%NTERR macro
	.if Eax
	Int 3
	.endif
endm

%APIERR macro
	.if !Eax
	Int 3
	.endif
endm

CR	equ 13
LF	equ 10
	
.code GPECODE
	include Bin\Gpe\Gpe.inc

.code GPPARSE
; o !GCBE_PARSE_SEPARATE
; o !GCBE_PARSE_OPENLIST
;
PARSE_CALLBACK_ROUTINE proc uses ebx Graph:PVOID,	; Ссылка на граф.
 GraphEntry:PVOID,	; Ссылка на описатель инструкции.
 SubsList:PVOID,	; Список описателей входов процедур в порядке вызова.
 SubsCount:ULONG,	; Число процедур в списке является уровнем вложенности(NL).
 PreOrPost:BOOLEAN,	; Тип вызова.
 Context:PVOID
; Def. Flags offset.
	mov ebx,GraphEntry
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	cmp eax,HEADER_TYPE_CALL
	jne @f
; (!BRANCH_DEFINED_FLAG)
	mov eax,dword ptr [ebx + EhAddress]
	cmp word ptr [eax],15FFH
	jne @f
	mov eax,dword ptr [eax + 2]
	mov eax,dword ptr [eax]
	cmp dword ptr [_imp__ZwResumeThread],eax
	jne @f
	mov ebx,dword ptr [ebx + EhBlink]
	and ebx,NOT(TYPE_MASK)
	jz @f
	test dword ptr [ebx + EhEntryType],TYPE_MASK
	jnz @f
	mov ebx,dword ptr [ebx + EhBlink]
	and ebx,NOT(TYPE_MASK)
	jz @f
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	cmp eax,HEADER_TYPE_JXX
	jne @f
	mov ebx,dword ptr [ebx + EhBlink]
	and ebx,NOT(TYPE_MASK)
	jz @f
	mov ebx,dword ptr [ebx + EhAddress]
	cmp byte ptr [ebx + 1],45H
	jne @f
	movzx eax,byte ptr [ebx]
	sub eax,0F6H
	jb @f
	.if Zero?
	movzx eax,byte ptr [ebx + 3]
	.else
	dec eax
	jnz @f
	mov eax,dword ptr [ebx + 3]
	.endif
	cmp eax,CREATE_SUSPENDED		; 4
	jne @f
	movzx eax,byte ptr [ebx + 2]
	cmp eax,4
	jna @f
	mov StFlagsOffset,eax
; Def. STACK_FRAME.Ip
	mov ecx,SubsList
	cmp SubsCount,2
	jb @f
	mov ecx,dword ptr [ecx]	; PCALL_HEADER
	mov ecx,dword ptr [ecx + EhFlink]
	and ecx,NOT(TYPE_MASK)
	jz @f
	mov ecx,dword ptr [ecx + EhAddress]
	mov eax,STATUS_WAIT_1
	mov StAddress,ecx
	jmp Exit
@@:
	xor eax,eax
Exit:
	ret
PARSE_CALLBACK_ROUTINE endp

comment '
NTSTATUS
LdrGetProcedureAddress (
    IN PVOID DllHandle,
    IN PANSI_STRING ProcedureName OPTIONAL,
    IN ULONG ProcedureNumber OPTIONAL,
    OUT PVOID *ProcedureAddress
    )
{
    return LdrpGetProcedureAddress(DllHandle,ProcedureName,ProcedureNumber,ProcedureAddress,TRUE);
}

NTSTATUS
LdrpGetProcedureAddress (
    IN PVOID DllHandle,
    IN PANSI_STRING ProcedureName OPTIONAL,
    IN ULONG ProcedureNumber OPTIONAL,
    OUT PVOID *ProcedureAddress,
    IN BOOLEAN RunInitRoutines
    )
	...
        if ( RunInitRoutines ) {
            PLDR_DATA_TABLE_ENTRY LdrInitEntry;

            //
            // Look at last entry in init order list. If entry processed
            // flag is not set, then a forwarded dll was loaded during the
            // getprocaddr call and we need to run init routines
            //

            Next = NtCurrentPeb()->Ldr->InInitializationOrderModuleList.Blink;
            LdrInitEntry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
            if ( !(LdrInitEntry->Flags & LDRP_ENTRY_PROCESSED) ) {
                try {
                    st = LdrpRunInitializeRoutines(NULL);
                    }
                except( EXCEPTION_EXECUTE_HANDLER ) {
                    st = GetExceptionCode();
                    }
                }
            }
	'
TbStackBase	equ 4
TbStackLimit	equ 8

.code CALLOUT

$Ld	CHAR "SFC Frame: 0x%p", CR, LF, 0

; o DLL_PROCESS_ATTACH.
;
	assume fs:nothing
DispatchCallout:
;	%GET_CURRENT_GRAPH_ENTRY
DispatchCalloutInternal proc DllHandle:PVOID, Reason:ULONG, Context:PVOID
	cmp Reason,DLL_PROCESS_ATTACH
	jne Exit
; Сбрасываем флаг LDRP_ENTRY_PROCESSED для последующих вызовов, взводится после возврата.
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	and byte ptr LDR_DATA_TABLE_ENTRY.Flags[eax + 1],NOT(LDR_ENTRY_PROCESSED)
	mov eax,STACK_FRAME.Next[ebp]
	mov ecx,StAddress
	assume eax:PSTACK_FRAME
@@:
	cmp eax,-1
	je Exit
	cmp fs:[TbStackBase],eax
	jna Exit
	cmp fs:[TbStackLimit],eax
	ja Exit
	cmp [eax].Ip,ecx
	je Load
	mov eax,[eax].Next
	jmp @b
Load:
	mov ecx,StFlagsOffset
	mov [eax].Ip,offset Fn2ndDispatch
	or dword ptr [eax + ecx],CREATE_SUSPENDED
	invoke DbgPrint, addr $Ld, Eax
Exit:
	mov eax,TRUE
	ret
DispatchCalloutInternal endp

LDR_ENTRY_PROCESSED	equ (LDRP_ENTRY_PROCESSED shr 8)

SET_CALLOUT macro Routine
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov ecx,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
;	Call Routine
	mov eax,Routine
	and byte ptr LDR_DATA_TABLE_ENTRY.Flags[ecx + 1],NOT(LDR_ENTRY_PROCESSED)
	xchg LDR_DATA_TABLE_ENTRY.EntryPoint[ecx],eax	; kernel32.dll
endm

.data
PUBLIC StFlagsOffset
PUBLIC StAddress
PUBLIC NtInit

StFlagsOffset	ULONG ?
StAddress		PVOID ?
NtInit		PVOID ?

.code
$Ch	CHAR "2nd'f called..", CR, LF, 0

Fn2ndDispatch proc C
	pushad
	invoke DbgPrint, addr $Ch
	popad
	jmp StAddress
Fn2ndDispatch endp

$PsName	CHAR "d:\windows\system32\calc.exe",0

$Fn	CHAR "Ip: 0x%p, Flg: 0x%x", CR, LF, 0

Ep proc
Local Snapshot:GP_SNAPSHOT
Local GpSize:ULONG
Local OldProtect:ULONG
Local StartupInfo:STARTUPINFO
Local ProcessInfo:PROCESS_INFORMATION
	SET_CALLOUT offset DispatchCalloutInternal
	mov NtInit,eax
	mov Snapshot.GpBase,NULL
	mov GpSize,1000H * X86_PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr Snapshot.GpBase, 0, addr GpSize, MEM_COMMIT, PAGE_READWRITE
	mov ebx,Snapshot.GpBase
	%NTERR
	add Snapshot.GpBase,0FFFH * X86_PAGE_SIZE
	mov GpSize,X86_PAGE_SIZE
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr Snapshot.GpBase, addr GpSize, PAGE_NOACCESS, addr OldProtect
	%NTERR
	mov Snapshot.GpLimit,ebx
	mov Snapshot.GpBase,ebx
	lea ecx,Snapshot.GpLimit
	push eax
	push eax
	push 1234H
	push offset PARSE_CALLBACK_ROUTINE
	push eax
	push 8
	push GCBE_PARSE_DISCLOSURE
	push ecx
	push dword ptr [_imp__CreateProcessA]
	%GPCALL GP_PARSE
	.if !Eax
	mov eax,STATUS_NOT_FOUND
	Int 3
	.elseif Eax != STATUS_WAIT_1
	Int 3
	.endif
	.if !StAddress
	Int 3
	.endif
	invoke DbgPrint, addr $Fn, StAddress, StFlagsOffset
	invoke GetStartupInfo, addr StartupInfo
; !CREATE_SUSPENDED
	invoke CreateProcess, addr $PsName, NULL, NULL, NULL, FALSE, 10000H, NULL, NULL, addr StartupInfo, addr ProcessInfo
	%APIERR
	invoke Sleep, 3000
	invoke ZwResumeThread, ProcessInfo.ThreadHandle, NULL
	%NTERR
	ret
Ep endp
end Ep