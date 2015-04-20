	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

_imp__RtlEqualUnicodeString	proto :dword, :dword, :dword
_imp__KiUserExceptionDispatcher proto :dword, :dword
_imp__LdrLoadDll proto :dword, :dword, :dword, :dword

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

%LOAD_IMAGE_BASE macro

endm

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
	include ..\..\Bin\Gcbe.inc

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

TrapXcpt proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
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
	cmp eax,offset Break
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
TrapXcpt endp

LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED	equ 1

xLdrLoadImage proc DllName:PSTR
Local DllCharacteristics:ULONG
Local LdrEntry:PLDR_DATA_TABLE_ENTRY
Local Cookie:ULONG
Local DllNameU:UNICODE_STRING
	invoke RtlCreateUnicodeStringFromAsciiz, addr DllNameU, DllName
	.if !Eax
	   mov eax,STATUS_INVALID_PARAMETER
	   jmp Exit
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
	%START_TRACE
	invoke LdrLoadDll, NULL, addr DllCharacteristics, addr DllNameU, addr DllHandle2
	mov ecx,LdrEntry
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
Exit:
	ret
xLdrLoadImage endp

$DllName	CHAR "ntdll.dll",0

$Viol	CHAR "GP: Integrity violation: 0x%p, 0x%p, 0x%p", 13, 10, 0

Entry proc
Local GpBase:PVOID
Local GpLimit:ULONG	
Local GpSize:ULONG
Local OldProtect:ULONG
	invoke RtlAddVectoredExceptionHandler, 1, addr TrapXcpt
	%APIERR
	invoke LoadLibrary, addr $DllName
	%APIERR
	invoke xLdrLoadImage, addr $DllName
Break::
	%NTERR
	mov GpBase,eax
	mov GpSize,1000H * X86_PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr GpBase, 0, addr GpSize, MEM_COMMIT, PAGE_READWRITE
	mov ebx,GpBase
	%NTERR
	add GpBase,0FFFH * X86_PAGE_SIZE
	mov GpSize,X86_PAGE_SIZE
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr GpBase, addr GpSize, PAGE_NOACCESS, addr OldProtect
	%NTERR
	mov GpLimit,ebx
	mov GpBase,ebx
	lea ecx,GpLimit
	mov edx,dword ptr [_imp__LdrLoadDll]
	push eax
	push eax
	sub edx,DllHandle
	push eax
	push eax
	add edx,DllHandle2
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push GCBE_PARSE_IPCOUNTING	; or GCBE_PARSE_SEPARATE
	push ecx
	push edx
	%GPCALL GP_PARSE
	%NTERR
	mov edx,DllHandle
	cld
	sub edx,DllHandle2
@@:
	mov eax,dword ptr [ebx + EhEntryType]
	mov esi,dword ptr [ebx + EhAddress]
	test eax,TYPE_MASK
	mov ecx,dword ptr [ebx + EhSize]
	.if !Zero?	; Line
	   push esi
	   %GPCALL GP_LDE
	   movzx ecx,al
	.endif
	   lea edi,[esi + edx]
	   mov eax,edi
	   repe cmpsb
	   .if !Zero?
	      push edx
	      invoke DbgPrint, addr $Viol, Eax, dword ptr [ebx + EhAddress], Ebx
	      pop edx
	   .endif
	add ebx,ENTRY_HEADER_SIZE
	cmp GpLimit,ebx
	ja @b
	ret
Entry endp
end Entry