Public Sym_MapViewOfSectionI
Public Sym_MapViewOfSectionII
Public Sym_IsMapped
Public Sym_Skip_ZwMapViewOfSection
Public Sym_MapViewOfSection
Public Sym_Close
Public Sym_OpenSection

; +
; VEH
;
	assume fs:nothing
$VEH:
	GET_CURRENT_GRAPH_ENTRY
LdrDispatchException proc uses ebx esi edi ExceptionPointers:PEXCEPTION_POINTERS
Local ViewBase:PVOID, ViewSize:ULONG
	mov edx,ExceptionPointers
	mov ebx,fs:[TEB.Tib.StackBase]
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[edx]
	assume esi:PEXCEPTION_RECORD
	mov ebx,dword ptr [ebx - 4]
	mov edi,EXCEPTION_POINTERS.ContextRecord[edx]
	assume edi:PCONTEXT
	assume ebx:PENVIRONMENT
	inc [ebx].Recursion
	cmp [esi].ExceptionFlags,NULL
	jnz Chain
	cmp [esi].ExceptionCode,STATUS_SINGLE_STEP
	mov eax,[ebx].BugIp
	jne IsBreak
	test eax,eax
	mov ecx,[esi].ExceptionAddress
	je NotBug
	cmp eax,1
	je @f
	cmp eax,ecx
	jne NotBug
	jmp Stop
@@:
	mov [ebx].BugIp,ecx
	jmp Stop
IsBreak:
	mov eax,[ebx].Buffer
	cmp [esi].ExceptionCode,STATUS_PRIVILEGED_INSTRUCTION	; (Hlt)
	lea eax,[eax + TfHalt]
	jne Chain
	cmp [esi].ExceptionAddress,eax	; ExceptionAddress = Eip
	jne Chain
	inc [edi].regEip
Stop:
	and [edi].regEFlags,NOT(EFLAGS_TF)
Continue:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
Exit:
	dec [ebx].Recursion
	ret
Chain:
	xor eax,eax	; EXCEPTION_CONTINUE_SEARCH
	jmp Exit
NotBug:
	mov eax,[ebx].Buffer
	mov esi,[edi].regEsp
	lea eax,[eax + TfSignal]
	cmp eax,ecx
	je Stop
	cmp [ebx].Recursion,1
	jne Stop
	cmp [ebx].Status,LDR_STATUS_SECTION_CLOSED
	jnb Chain
	cmp [ebx].Fn.pZwOpenSection,ecx
	je BpxOpenSection
	cmp [ebx].Fn.pZwClose,ecx
	je BpxClose
	cmp [ebx].Fn.pZwMapViewOfSection,ecx
	je BpxMapViewOfSection
Trace:
	or [edi].regEFlags,EFLAGS_TF
	jmp Continue
BpxOpenSection:
Sym_OpenSection::
; NtOpenSection()
; [Esp + 4]	OUT PHANDLE SectionHandle
; [Esp + 2*4]	IN ACCESS_MASK DesiredAccess
; [Esp + 3*4]	IN POBJECT_ATTRIBUTES ObjectAttributes
	cmp [ebx].Status,LDR_STATUS_PROCESSING
	mov ecx,dword ptr [esi + 3*4]	; ObjectAttributes
	jne Trace
	assume ecx:POBJECT_ATTRIBUTES
	cmp [ecx].uLength,sizeof(OBJECT_ATTRIBUTES)
	mov eax,[ecx].hRootDirectory
	jne Trace
	test eax,eax
	jz Trace
	push [ecx].pObjectName
	invoke LdrIsKnownDllDirectory, Ebx, Eax
	test eax,eax
	pop ecx
	jnz Trace
	test ecx,ecx	; Don't use Jecxz.
	lea edx,[ebx].DllName
	je Trace
	push TRUE
	push ecx
	push edx
	Call [ebx].Fn.pRtlCompareUnicodeString
	test eax,eax
	mov ecx,dword ptr [esi + 4]	; SectionHandle
	jnz Trace
	mov eax,[ebx].SectionHandle
	mov edx,dword ptr [esi]
	add [edi].regEsp,4*4
	mov [edi].regEax,STATUS_SUCCESS
	mov dword ptr [ecx],eax
	mov [edi].regEip,edx
	inc [ebx].Status	; LDR_STATUS_SECTION_OPENED
	jmp Trace
BpxClose:
Sym_Close::
; NtClose()
; [Esp + 4]	IN HANDLE Handle
	mov eax,[ebx].Status	; LDR_STATUS_PROCESSING
	test eax,eax
	jz Trace
	cmp eax,LDR_STATUS_SECTION_CLOSED
	mov ecx,dword ptr [esi + 4]
	jnb Stop
	cmp [ebx].SectionHandle,ecx
	jne Trace
	mov ecx,dword ptr [esi]
	mov [ebx].Status,LDR_STATUS_SECTION_CLOSED
	add [edi].regEsp,2*4
	mov [edi].regEax,STATUS_SUCCESS
	mov [edi].regEip,ecx
	jmp Stop
BpxMapViewOfSection:
Sym_MapViewOfSection::
; MapViewOfSection()
; [Esp + 4]	IN HANDLE SectionHandle
; [Esp + 2*4]	IN HANDLE ProcessHandle
; [Esp + 3*4]	IN OUT PVOID *BaseAddress
; [Esp + 4*4]	IN ULONG ZeroBits
; [Esp + 5*4]	IN ULONG CommitSize
; [Esp + 6*4]	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL
; [Esp + 7*4]	IN OUT PULONG ViewSize
; [Esp + 8*4]	IN SECTION_INHERIT InheritDisposition
; [Esp + 9*4]	IN ULONG AllocationType
; [Esp + 10*4]	IN ULONG Protect
	mov eax,[ebx].Status	; LDR_STATUS_PROCESSING
	test eax,eax
	jz Trace
	cmp eax,LDR_STATUS_SECTION_CLOSED
	mov ecx,dword ptr [esi + 4]
	jnb Trace
	cmp [ebx].SectionHandle,ecx
	jne Trace
	cmp dword ptr [esi + 2*4],NtCurrentProcess
	mov ecx,dword ptr [esi + 3*4]
	jne Trace
	cmp dword ptr [esi + 6*4],NULL
	mov edx,[ebx].DesiredBase
	jne Stop
	dec eax
	jnz IsMapped	; LDR_STATUS_SECTION_OPENED
	cmp dword ptr [ecx],eax
	jne Stop
	lea ecx,ViewSize
	push PAGE_EXECUTE_READWRITE
	push 0
	push ViewShare
	push ecx
	push eax
	push eax
	lea ecx,ViewBase
	push eax
	mov ViewBase,edx
	mov ViewSize,eax
	push ecx
	push NtCurrentProcess
	push [ebx].SectionHandle
Sym_MapViewOfSectionI::
	Call [ebx].Fn.pZwMapViewOfSection
	test eax,eax
	mov [edi].regEax,eax
	jnz @f
	test ebx,ebx
Store:
	mov ecx,ViewBase
	mov [ebx].Status,LDR_STATUS_SECTION_MAPPED
	push ViewSize
	mov [ebx].ViewBase,ecx
	mov eax,dword ptr [esi + 3*4]
	mov edx,dword ptr [esi + 7*4]
	mov dword ptr [eax],ecx
	pop dword ptr [edx]
Sym_Skip_ZwMapViewOfSection::
Skip:
	mov ecx,[edi].regEsp
	mov eax,dword ptr [esi]
	lea ecx,[ecx + 11*4]
	mov dword ptr [edi].regEip,eax
	mov [edi].regEsp,ecx
	jnz Stop
	jmp Trace
@@:
	xor eax,eax
	lea ecx,ViewSize
	push PAGE_EXECUTE_READWRITE
	push 0
	push ViewShare
	push ecx
	push eax
	push eax
	lea ecx,ViewBase
	push eax
	mov ViewBase,eax
	push ecx
	push NtCurrentProcess
	push [ebx].SectionHandle
Sym_MapViewOfSectionII::
	Call [ebx].Fn.pZwMapViewOfSection
	test eax,eax
	mov [edi].regEax,eax
	jnz Skip
	mov [edi].regEax,STATUS_IMAGE_NOT_AT_BASE
	jmp Store
IsMapped:
Sym_IsMapped::
	dec eax
	mov edx,[ebx].ViewBase
	jnz Stop	; LDR_STATUS_SECTION_MAPPED
	cmp dword ptr [ecx],edx
	jne Stop
	test ebx,ebx
	mov [edi].regEax,STATUS_SUCCESS
	mov [ebx].Status,LDR_STATUS_SECTION_CHECKED
	jmp Skip
LdrDispatchException endp