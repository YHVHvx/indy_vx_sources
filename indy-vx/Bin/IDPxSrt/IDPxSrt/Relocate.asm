; Загрузка копии образа.
;
; (c) Indy, 2011.
;
_imp__RtlEqualUnicodeString	proto :dword, :dword, :dword
_imp__KiUserExceptionDispatcher proto :dword, :dword
_imp__LdrLoadDll proto :dword, :dword, :dword, :dword
_imp__ZwAreMappedFilesTheSame proto :dword, :dword

%START_TRACE macro
	push EFLAGS_TF or EFLAGS_MASK
	popfd
endm

%LDRP_NT_ENTRY macro Reg32
	assume fs:nothing
	mov Reg32,fs:[TEB.Peb]
	mov Reg32,PEB.Ldr[Reg32]
	mov Reg32,PEB_LDR_DATA.InLoadOrderModuleList.Flink[Reg32]
	mov Reg32,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[Reg32]	; ntdll.dll
endm

.data
DllHandle			HANDLE ?
DllHandle2		HANDLE ?
pfLdrRelocateImage	PVOID ?
Delta			PVOID ?
User32String		UNICODE_STRING <sizeof pUser32 - 2, sizeof pUser32, offset pUser32>
Kernel32String		UNICODE_STRING <sizeof pKernel32 - 2, sizeof pKernel32, offset pKernel32>
pKernel32			WCHAR "k", "e", "r", "n", "e", "l", "3", "2", ".", "d", "l", "l",0
pUser32			WCHAR "u", "s", "e", "r", "3", "2", ".", "d", "l", "l", 0

.code
comment '
        status = (NTSTATUS)LdrRelocateImage(ViewBase,
                    "LDR",
                    (ULONG)STATUS_SUCCESS,
                    (ULONG)STATUS_CONFLICTING_ADDRESSES,
                    (ULONG)STATUS_INVALID_IMAGE_FORMAT
                    );
                    '
                    
LoadBase proc uses ebx
Local RegionAddress:PVOID
Local RegionSize:ULONG
Local OldProtect:ULONG
	mov ebx,DllHandle2
	add ebx,IMAGE_DOS_HEADER.e_lfanew[ebx]
	mov RegionSize,4
	add ebx,IMAGE_NT_HEADERS.OptionalHeader.ImageBase
	mov RegionAddress,ebx
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr RegionAddress, addr RegionSize, PAGE_EXECUTE_READWRITE, addr OldProtect
	test eax,eax
	mov ecx,Delta
	.if Zero?
	   xchg [ebx],ecx
	   mov Delta,ecx
	.endif
	push eax
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr RegionAddress, addr RegionSize, OldProtect, addr OldProtect
	pop eax
	ret
LoadBase endp

LdrXcpt proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local LdrEntry:PLDR_DATA_TABLE_ENTRY
	mov eax,ExceptionPointers
	mov ecx,EXCEPTION_POINTERS.ExceptionRecord[eax]
	assume ecx:PEXCEPTION_RECORD
	mov ebx,EXCEPTION_POINTERS.ContextRecord[eax]
	assume ebx:PCONTEXT
	cmp [ecx].ExceptionFlags,NULL
	jne Chain
	cmp [ecx].ExceptionCode,STATUS_SINGLE_STEP
	mov esi,[ebx].regEsp
	jne Chain
	mov eax,[ebx].regEip
	cmp eax,offset LdrBreak
	je Reset
	cmp dword ptr [_imp__RtlEqualUnicodeString],eax	; to resolve user32.dll & kernel32.dll
	jne @f
	invoke LdrFindEntryForAddress, dword ptr [Esi], addr LdrEntry
	test eax,eax
	jnz @f
	%LDRP_NT_ENTRY Edi
	cmp LdrEntry,edi	; Ip ~ ntdll.dll
	jne @f
	invoke LdrFindEntryForAddress, dword ptr [Esi + 4], addr LdrEntry
	.if Eax
	   invoke LdrFindEntryForAddress, dword ptr [Esi + 2*4], addr LdrEntry
	   test eax,eax
	   jnz @f
	.endif
	cmp LdrEntry,edi
	jne @f
	invoke RtlEqualUnicodeString, dword ptr [esi + 4], addr User32String, TRUE
	test eax,eax
	jnz Skip
	invoke RtlEqualUnicodeString, dword ptr [esi + 4], addr Kernel32String, TRUE
	test eax,eax
	jz @f
Skip:
	mov eax,dword ptr [esi]
	add [ebx].regEsp,4*4
	mov [ebx].regEax,FALSE
	mov [ebx].regEip,eax
	jmp Step
@@:
	mov eax,[ebx].regEip
	.if dword ptr [_imp__ZwAreMappedFilesTheSame] == Eax
	   mov eax,[ebx].regEsp
	   mov [ebx].regEax,STATUS_NOT_SAME_DEVICE
	   mov eax,dword ptr [eax]
	   add [ebx].regEsp,3*4
	   mov [ebx].regEip,eax
	   jmp Step
	.endif
	mov ecx,dword ptr [_imp__KiUserExceptionDispatcher]	; to avoid deadlock..
	cmp eax,ecx
	jb @f
	add ecx,15*2
	cmp eax,ecx
	jb Reset
@@:
	cmp pfLdrRelocateImage,eax
	jne @f
	invoke LoadBase
	jmp Reset
@@:
	cmp byte ptr [eax],0E8H	; Call RtlRelocateImage
	jne Step
	.if dword ptr [esi + 2*4] == STATUS_SUCCESS
	   .if dword ptr [esi + 3*4] == STATUS_CONFLICTING_ADDRESSES
	      .if dword ptr [esi + 4*4] == STATUS_INVALID_IMAGE_FORMAT
	         invoke ZwAreMappedFilesTheSame, DllHandle, dword ptr [Esi]
	         .if !Eax
	            mov eax,[ebx].regEip
	            mov ecx,dword ptr [esi]
	            add eax,5
	            mov DllHandle2,ecx
	            mov Delta,ecx
	            mov pfLdrRelocateImage,eax
	            invoke LoadBase
	         .endif
	      .endif
	   .endif
	.endif
Step:
	or [ebx].regEFlags,EFLAGS_TF
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	ret
Reset:
	and [ebx].regEFlags,NOT(EFLAGS_TF)
	jmp Load
Chain:
	xor eax,eax
	jmp Exit
LdrXcpt endp

LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED	equ 1

; +
; o Переменные сохраняеются(секции данных не релоцируются).
; o InitRoutine() не вызывается.
; 
LdrLoadImage proc DllName:PSTR
Local DllCharacteristics:ULONG
Local LdrEntry:PLDR_DATA_TABLE_ENTRY
Local Cookie:ULONG
Local DllNameU:UNICODE_STRING
Local Vhandle:PVOID
	invoke RtlAddVectoredExceptionHandler, 1, addr LdrXcpt
	.if !Eax
		mov eax,STATUS_INTERNAL_ERROR
		jmp Exit
	.endif
	mov Vhandle,eax
	invoke RtlCreateUnicodeStringFromAsciiz, addr DllNameU, DllName
	.if !Eax
	   mov eax,STATUS_INVALID_PARAMETER
	   jmp Remove
	.endif
	invoke LdrLockLoaderLock, LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED, NULL, addr Cookie
	test eax,eax
	jnz Free
	invoke LdrGetDllHandle, NULL, NULL, addr DllNameU, addr DllHandle
	test eax,eax
	mov DllCharacteristics,LDRP_STATIC_LINK
	jnz Unlock
	invoke LdrFindEntryForAddress, DllHandle, addr LdrEntry
	test eax,eax
	mov ecx,LdrEntry
	jnz Unlock
	assume ecx:PLDR_DATA_TABLE_ENTRY
	sub [ecx].BaseDllName._Length,2
	sub [ecx].FullDllName._Length,2
	inc [ecx].TimeDateStamp
	inc  [ecx].CheckSum
	%START_TRACE
	invoke LdrLoadDll, NULL, addr DllCharacteristics, addr DllNameU, addr DllHandle2
LdrBreak::
	mov ecx,LdrEntry
	dec [ecx].CheckSum
	dec [ecx].TimeDateStamp
	add [ecx].BaseDllName._Length,2
	add [ecx].FullDllName._Length,2
Unlock:
	push eax
	invoke LdrUnlockLoaderLock, LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED, Cookie
	pop eax
Free:
	push eax
	invoke RtlFreeUnicodeString, addr DllNameU
	pop eax
Remove:
	push eax
	invoke RtlRemoveVectoredExceptionHandler, Vhandle
	pop eax
Exit:
	ret
LdrLoadImage endp

LdrInitialize proc uses ebx esi edi
Local Buffer[MAX_PATH]:CHAR
Local TableEntry:PLDR_DATA_TABLE_ENTRY
Local ResultLength:ULONG, ImageBase:PVOID
	invoke GetModuleHandle, NULL
	%APIERR
	lea ecx,Buffer
	push MAX_PATH
	push ecx
	push eax
	Call GetModuleFileName
	%APIERR
	invoke LdrLoadImage, addr Buffer
	%NTERR
	invoke LdrFindEntryForAddress, DllHandle2, addr TableEntry
	%NTERR
	mov ebx,TableEntry
	assume ebx:PLDR_DATA_TABLE_ENTRY
	mov ImageBase,eax
	mov esi,[ebx].SizeOfImage
; Для большего сокрытия заменяем файловую проекцию на приватную память. Необходимо выполнять при захваченых LdrpLoaderLock и FastPebLock, тут не существенно, так как один поток.
	invoke VirtualAlloc, NULL, Esi, MEM_COMMIT, PAGE_EXECUTE_READWRITE
	%APIERR
	mov ImageBase,eax
	invoke WriteProcessMemory, NtCurrentProcess, ImageBase, DllHandle2, Esi, addr ResultLength
	%APIERR
;	bts [ebx].Flags[ecx],23	; LDRP_COR_OWNS_UNMAP
	btr [ebx].Flags,18	; LDRP_DONT_CALL_FOR_THREADS
	invoke LdrUnloadDll, DllHandle2
	%NTERR
	invoke VirtualAlloc, DllHandle2, Esi, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE
	%APIERR
	invoke WriteProcessMemory, NtCurrentProcess, DllHandle2, ImageBase, Esi, addr ResultLength
	%APIERR
	invoke VirtualFree, ImageBase, NULL, MEM_RELEASE
	%APIERR
	ret
LdrInitialize endp