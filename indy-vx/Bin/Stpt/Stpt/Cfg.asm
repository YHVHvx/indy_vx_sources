; +
; Настройка директории конфигурации. Регистрация SEH.
; o SysStub - адрес системного стаба(напр. call dword ptr ds:[RtlpStartThreadFunc]).
;
ConfigureConfigDirectory proc uses ebx esi edi SysStub:PVOID, pZwProtectVirtualMemory:PVOID
Local RegionAddress:PVOID, RegionSize:ULONG, Protect:ULONG
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov ebx,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	mov edi,ebx
	add edi,IMAGE_DOS_HEADER.e_lfanew[ebx]
	assume edi:PIMAGE_NT_HEADERS
	mov esi,[edi].OptionalHeader.DataDirectory.VirtualAddress[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * sizeof(IMAGE_DATA_DIRECTORY)]
	mov RegionAddress,edi
	test esi,esi
	jz Error
	add esi,ebx	; _load_config_used
	assume esi:PIMAGE_LOAD_CONFIG_DIRECTORY
	cmp [esi]._Size,sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)
	jne Error
	cmp [esi].SEHandlerCount,0
	movzx ecx,[edi].FileHeader.NumberOfSections
	je Error
	test ecx,ecx
	jz Error
Scan:
	cmp dword ptr IMAGE_SECTION_HEADER._Name[edi + sizeof(IMAGE_NT_HEADERS)][0],"tad."
	jne Next
	cmp dword ptr IMAGE_SECTION_HEADER._Name[edi + sizeof(IMAGE_NT_HEADERS)][4],"a"
	jne Next
	mov eax,IMAGE_SECTION_HEADER.Characteristics[edi + sizeof(IMAGE_NT_HEADERS)]
	and eax,IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_READ or IMAGE_SCN_CNT_INITIALIZED_DATA
	cmp eax,IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_READ or IMAGE_SCN_CNT_INITIALIZED_DATA
	jne Error
	mov eax,IMAGE_SECTION_HEADER.VirtualSize[edi + sizeof(IMAGE_NT_HEADERS)]
	mov ecx,[esi].SEHandlerCount
	and eax,(X86_PAGE_SIZE - 1)
	lea ecx,[ecx*4 + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY) + 4]
	not eax
	lea eax,[eax + X86_PAGE_SIZE + 1]
	cld
	cmp eax,ecx
	mov edx,IMAGE_SECTION_HEADER.VirtualAddress[edi + sizeof(IMAGE_NT_HEADERS)]
	jb Error
	mov edi,IMAGE_SECTION_HEADER.VirtualSize[edi + sizeof(IMAGE_NT_HEADERS)]
	add edi,edx
	mov RegionSize,4
	add edi,ebx
	mov ecx,sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)/4
	mov edx,edi
	assume edx:PIMAGE_LOAD_CONFIG_DIRECTORY
	rep movsd
	mov esi,[edx].SEHandlerTable
	mov ecx,[edx].SEHandlerCount
	mov [edx].SEHandlerTable,edi
	mov eax,SysStub
	rep movsd
	sub eax,ebx
	mov esi,RegionAddress
	stosd
	inc [edx].SEHandlerCount
	lea eax,Protect
	lea ecx,RegionSize
	mov edi,edx
	push eax
	push PAGE_READWRITE
	lea eax,RegionAddress
	push ecx
	push eax
	push NtCurrentProcess
	%APICALL pZwProtectVirtualMemory, 5
	test eax,eax
	jnz Exit
	sub edi,ebx
	mov IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * sizeof(IMAGE_DATA_DIRECTORY)][esi],edi
	lea eax,Protect
	lea ecx,RegionSize
	push eax
	push Protect
	lea eax,RegionAddress
	push ecx
	push eax
	push NtCurrentProcess
	%APICALL pZwProtectVirtualMemory, 5
	xor eax,eax
	jmp Exit
Next:
	add edi,sizeof(IMAGE_SECTION_HEADER)
	dec ecx
	jnz Scan
Error:
	mov eax,STATUS_UNSUCCESSFUL
Exit:
	ret
ConfigureConfigDirectory endp

OP_ESC_2B	equ 0FH

; +
; Двухпроходовый сигнатурный поиск шлюза.
;
; CsrClientCallServer:
; 	cmp byte ptr ds:[_CsrServerProcess],bl
; 	jnz XXXX
; 	...
; XXXX:
; ApiMessage->Header.ClientId = NtCurrentTeb()->ClientId;
; Status = CsrServerApiRoutine(&ApiMessage->Header, &ApiMessage->Header);
; $		64:A1 18000000		mov eax,dword ptr fs:[18]	; PTEB
; $+6	8B48 20			mov ecx,dword ptr ds:[eax+20]	; TID
; $+9	894E 08			mov dword ptr ds:[esi+8],ecx
; $+C	8B40 24			mov eax,dword ptr ds:[eax+24]	; PID
; $+F	56				push esi
; $+10	56				push esi	; PPORT_MESSAGE
; $+11	8946 0C			mov dword ptr ds:[esi+C],eax
; typedef NTSTATUS
;   (NTAPI *PCSR_SERVER_API_ROUTINE)(IN PPORT_MESSAGE Request, IN PPORT_MESSAGE Reply);
; PCSR_SERVER_API_ROUTINE CsrServerApiRoutine;
; $+14	FF15 DCC9977C		call dword ptr ds:[_CsrServerApiRoutine]
; 	...
; -
; o Eax: @Call [CsrServerApiRoutine]
; o Ecx: @CsrServerApiRoutine
;   Edx: @Back IP
;
QueryGate proc
Local Stub:PVOID
Local SizeOfCode:ULONG
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov edx,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	mov eax,IMAGE_DOS_HEADER.e_lfanew[edx]
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.SizeOfCode[edx + eax]
	add edx,IMAGE_NT_HEADERS.OptionalHeader.BaseOfCode[edx + eax]
	mov SizeOfCode,ecx
	mov eax,edx
	sub ecx,8*4
; 64 A1 18 00 00 00 8B 48 20 89 4E 08 8B 40 24 56 56 89 46 0C FF 15
Scan:
	cmp dword ptr [eax],0018A164H
	je @f
Step:
	inc eax
	loop Scan
	jmp Error
@@:
	cmp dword ptr [eax + 4],488B0000H
	jne Step
	cmp dword ptr [eax + 2*4],084E8920H
	jne Step
	cmp dword ptr [eax + 3*4],5624408BH
	jne Step
	cmp dword ptr [eax + 4*4],0C468956H
	jne Step
	cmp word ptr [eax + 5*4],15FFH
	jne Step
comment '
	mov Stub,eax
	mov ecx,SizeOfCode
	sub eax,edx
	sub ecx,6
	sub eax,4
Scan2nd:
	cmp dword ptr [edx],eax
	je @f
Step2nd:
	dec eax
	inc edx
	loop Scan2nd
	jmp Error
@@:
	cmp byte ptr [edx - 2],OP_ESC_2B
	jne Step2nd
	cmp byte ptr [edx - 1],85H	; Jne
	je @f
	cmp byte ptr [edx - 1],84H	; Je
	jne Step2nd
	mov eax,Stub
	add edx,4
	'
	add eax,14H
Exit:
	mov ecx,dword ptr [eax + 2]	; @CsrServerApiRoutine
	ret
Error:
	xor eax,eax
	jmp Exit
QueryGate endp