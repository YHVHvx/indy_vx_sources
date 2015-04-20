; o Враппер для системного загрузчика(для загрузки модулей из памяти).
; o Indy, 2010
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	include Hdr.inc
.code
MiEntry:
	test eax,eax
	jz xLdrLoadDll
	dec eax
	jz LdrImageQueryEntryFromCrc32
	dec eax
	jz LdrEncodeEntriesList
	mov eax,STATUS_UNSUCCESSFUL
	ret

	include Img.asm
	include Trap.asm

; +
; Если имеется отладочный порт, будет сгенерировано #STATUS_HANDLE_NOT_CLOSABLE.
; o Вызывается калбэк KiRaiseUserExceptionDispatcher().
;
xIsDebuggerPresent proc uses ebx Environment:PENVIRONMENT
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov eax,Environment
	assume eax:PENVIRONMENT
	push [eax].SectionHandle
	Call [eax].Fn.pZwClose
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xIsDebuggerPresent endp

; +
;
xLdrLoadDll proc uses ebx esi edi MapAddress:PVOID, DllName:PSTR, DllCharacteristics:PULONG, ImageBase:PVOID
Local Status:NTSTATUS
Local BufferSize:ULONG
Local ObjectInformation:DWORD	; OBJECT_HANDLE_FLAG_INFORMATION
Local ImageHeader:PIMAGE_NT_HEADERS
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor eax,eax
	mov Status,STATUS_UNSUCCESSFUL
; o Переменные храним в стеке.
; o Ссылку храним на дне стека.
	push eax	; Status
	push eax	; Recursion
	push eax	; BugIp
	push eax	; Buffer
	push eax	; ViewBase
	push eax	; DesiredBase
	push eax	; SectionHandle
	sub esp,2*sizeof(UNICODE_STRING) + 4	; + StackData
	push eax	; CalloutList
	$PUSH_FN_TABLE
	mov ebx,esp
	assume ebx:PENVIRONMENT
	invoke LdrEncodeEntriesList, Eax, Eax, Ebx
	test eax,eax
	jnz Clear
	invoke LdrImageNtHeader, MapAddress, addr ImageHeader
	test eax,eax
	mov ecx,ImageHeader
	jnz Clear
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.ImageBase[ecx]
	lea eax,BufferSize
	lea edx,[ebx].Buffer
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT
	mov [ebx].DesiredBase,ecx
	push eax
	mov BufferSize,16
	push 0
	push edx
	push NtCurrentProcess
	Call [ebx].Fn.pZwAllocateVirtualMemory
	test eax,eax
	mov ecx,[ebx].Buffer
	lea edx,[ebx].DllName
	jnz Clear
	mov dword ptr [ecx + TfBreaker],00030268H
	mov dword ptr [ecx + TfBreaker + 4],0C3F49D00H
	mov dword ptr [ecx + TfTracer],00030268H
	mov dword ptr [ecx + TfTracer + 4],0E0FF9D00H
comment '
; o Связка инструкции popfd с иной не должна быть нарушена при морфинге!
; Стаб для динамического определения второй инструкции диспетчера исключений.
TfBreaker:
	push EFLAGS_TF or EFLAGS_MASK	; 0x302
	popfd
	; Используем трассировочный баг. TF переносится в диспетчер исключений.
	; Если не пропускать трассировочный останов в диспетчере, это приведёт к деадлоку.
	hlt
TfSignal:
	ret
; Стаб для запуска трассировки LdrLoadDll().
TfTracer:
	push EFLAGS_TF or EFLAGS_MASK
	popfd
	jmp eax
	'
	push DllName
	push edx
	Call [ebx].Fn.pRtlCreateUnicodeStringFromAsciiz
	test eax,eax
	lea ecx,[ebx].Directory
	jz Free1
	push 'sl'
	push 'lDnw'	
	push 'onK\'
	push esp
	push ecx
	Call [ebx].Fn.pRtlCreateUnicodeStringFromAsciiz
	test eax,eax
	lea esp,[esp + 3*4]
	jz Free2
	Call $VEH
	push eax
	push 1
	Call [ebx].Fn.pRtlAddVectoredExceptionHandler
	test eax,eax
	mov edx,fs:[TEB.Tib.StackBase]
	mov [ebx].CalloutList,eax
	jz Free3
	mov eax,dword ptr [edx - 4]
	mov dword ptr [edx - 4],ebx
	lea ecx,[ebx].SectionHandle
	mov dword ptr [ebx].StackData,eax
	invoke LdrCreateImageSection, Ebx, Ecx, NULL, MapAddress, DllName	; NTSTATUS
	test eax,eax
	lea ecx,ObjectInformation
	jnz Uninit
	push 2
	push ecx
	push ObjectHandleFlagInformation
	push [ebx].SectionHandle
	mov dword ptr [ObjectInformation],0100H	; ProtectFromClose
	Call [ebx].Fn.pZwSetInformationObject
	test eax,eax
	jnz Close
	invoke xIsDebuggerPresent, Ebx
	test eax,eax
	mov ecx,[ebx].Buffer	; TfBreaker
	jnz Unprotect	; #STATUS_HANDLE_NOT_CLOSABLE
	mov [ebx].BugIp,1
	Call Ecx
	lea edx,[ebx].DllName
	mov ecx,[ebx].Buffer
	push ImageBase
	add ecx,TfTracer
	push edx
	mov eax,[ebx].Fn.pLdrLoadDll
	push DllCharacteristics
	push NULL
	Call Ecx
	mov ecx,[ebx].Buffer
	lea ecx,[ecx + TfSignal]
	Call Ecx		; TfSignal
Unprotect:
	push eax
	lea ecx,ObjectInformation
	push 2
	push ecx
	push ObjectHandleFlagInformation
	push [ebx].SectionHandle
	mov dword ptr [ObjectInformation],0
	Call [ebx].Fn.pZwSetInformationObject
	pop eax
Close:
	push eax
	push [ebx].SectionHandle
	Call [ebx].Fn.pZwClose
	pop eax
Uninit:
	mov edx,fs:[TEB.Tib.StackBase]
	push eax
	mov ecx,[ebx].StackData
	push [ebx].CalloutList
	mov dword ptr [edx - 4],ecx
	Call [ebx].Fn.pRtlRemoveVectoredExceptionHandler
	pop eax
Free:
	mov Status,eax
Free3:
	lea eax,[ebx].Directory
	push eax
	Call [ebx].Fn.pRtlFreeUnicodeString
Free2:
	lea eax,[ebx].DllName
	push eax
	Call [ebx].Fn.pRtlFreeUnicodeString
Free1:
	lea ecx,BufferSize
	lea edx,[ebx].Buffer
	push MEM_RELEASE
	push ecx
	push edx
	push NtCurrentProcess
	Call [ebx].Fn.pZwFreeVirtualMemory
Error:
	mov eax,Status
Clear:
	add esp,sizeof(ENVIRONMENT)
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xLdrLoadDll endp
end xLdrLoadDll