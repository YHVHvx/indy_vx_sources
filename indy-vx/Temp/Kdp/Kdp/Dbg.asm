; o KeEnterKernelDebugger
; o KdInitSystem
; o KiHardwareTrigger
; o KeBugCheckCount
; o KiDebugRoutine
; o KdpStub
	
KDEBUG_ENVIRONMENT struct
pKeEnterKernelDebugger	PVOID ?
pKdInitSystem			PVOID ?
pKiHardwareTrigger		PVOID ?
pKeBugCheckCount		PVOID ?
pKiDebugRoutine		PVOID ?
pKdpStub				PVOID ?
KDEBUG_ENVIRONMENT ends
PKDEBUG_ENVIRONMENT typedef ptr KDEBUG_ENVIRONMENT

xQueryDebugEnvironment proc uses ebx esi edi NtImageBase:PVOID, DbgEnv:PKDEBUG_ENVIRONMENT
Local ImageHeader:PIMAGE_NT_HEADERS, ImageLimit:PVOID
Local Fn:KDEBUG_ENVIRONMENT
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov edi,NtImageBase
	invoke LdrImageNtHeader, Edi, addr ImageHeader
	test eax,eax
	mov Fn.pKeEnterKernelDebugger,6DED839AH	; HASH("KeEnterKernelDebugger")
	mov Fn.pKeEnterKernelDebugger[4],eax
	jnz Exit
	invoke LdrEncodeEntriesList, Edi, 0, addr Fn.pKeEnterKernelDebugger
	test eax,eax
	mov esi,Fn.pKeEnterKernelDebugger
	jnz Exit
	mov edi,8	; IP's
	xor ebx,ebx
KiHardwareTrigger@Step:
	movzx eax,word ptr [esi]
	cmp al,33H	; 33 /r (xor r32,r/m32)
	jne KiHardwareTrigger@IsImm
comment '
	33F6			xor esi,esi
	46			inc esi
	8935 XXXXXXXX	mov dword ptr ds:[_KiHardwareTrigger],esi
	'
	mov cl,ah	; ModR/M
	mov al,ah
	and cl,MODRM_MOD_MASK
	and al,MODRM_REG_MASK
	cmp cl,MODRM_MOD_MASK
	jne KiHardwareTrigger@Next
	shr al,3	; Reg
	and ah,MODRM_RM_MASK
	cmp al,ah
	movzx ebx,al
	jne KiHardwareTrigger@Next
	add al,40H	; 40 + rd (inc r32)
	cmp byte ptr [esi + 2],al
	jne KiHardwareTrigger@Next
	cmp byte ptr [esi + 3],89H	; 89 /r (mov r/m32,r32)
	mov al,byte ptr [esi + 4]	; ModR/M
	jne KiHardwareTrigger@Next
	ror al,3
	mov ah,al
; (011B:EBX, 110B:ESI, 111B:EDI)
	and al,(MODRM_REG_MASK shr 3)
	and ah,NOT(MODRM_REG_MASK shr 3)
	cmp ah,10100000B
	movzx eax,al
	jne KiHardwareTrigger@Next
	cmp eax,ebx
	jne KiHardwareTrigger@Next
	mov eax,dword ptr [esi + 5]	; _KiHardwareTrigger
	add esi,9
	jmp KeBugCheckCount@Scan
KiHardwareTrigger@Next:
	Call VirXasm32
	add esi,eax
	dec edi
	jnz KiHardwareTrigger@Step
	jmp Error
KiHardwareTrigger@IsImm:
	cmp ax,05C7H	; mov dword ptr ds:[_KiHardwareTrigger],1    
	jne KiHardwareTrigger@Next
	cmp dword ptr [esi + 6],1
	jne KiHardwareTrigger@Next
	mov eax,dword ptr [esi + 2]	; _KiHardwareTrigger
; _KeBugCheckCount
	add esi,10
KeBugCheckCount@Scan:
	mov Fn.pKiHardwareTrigger,eax
	lea edi,[esi + 60H]
KeBugCheckCount@Step:
	mov ax,word ptr [esi]
	cmp al,0C3H	; ret
	je Error
	cmp al,0CCH	; int 3
	je Error
	sub al,0B8H	; B8 + rb (mov r32,imm32)
	jb KeBugCheckCount@Next
	cmp al,7	; Reg
	ja KeBugCheckCount@Next
	mov ecx,dword ptr [esi + 1]	; _KeBugCheckCount
	movzx eax,al
	add esi,5
	test ebx,ebx
	mov Fn.pKdInitSystem,eax	; /Reg
	mov Fn.pKeBugCheckCount,ecx
	jz KeBugCheckCount@Xadd
KeBugCheckCount@Xchg:
; xchg
	mov eax,dword ptr [esi]
	.if al == 0F0H	; Pfx lock
	shr eax,8
	.endif
	cmp al,087H	; 87 /r (xchg r/m32,r32)
	jne Error
	mov al,ah
	test ah,MODRM_MOD_MASK
	jnz Error
	and eax,(MODRM_RM_MASK or (MODRM_REG_MASK shl 8))
	cmp byte ptr [Fn.pKdInitSystem],al
	jne Error
	shr ah,3
	cmp ah,bl
	jne Error
	jmp KdInitSystem@Scan
KeBugCheckCount@Xadd:
	Call VirXasm32
	add esi,eax
; xadd
	mov eax,dword ptr [esi]
	.if al == 0F0H	; Pfx lock
	shr eax,8
	.endif
	cmp ax,0C10FH	; 0FC1 /r (xadd r/m32,r32)
	jne Error
	shr eax,16
	movzx eax,al
	test al,MODRM_MOD_MASK
	jnz Error
	and eax,MODRM_RM_MASK
	cmp Fn.pKdInitSystem,eax	; /Reg
	jne Error
	jmp KdInitSystem@Scan
KeBugCheckCount@Next:
	Call VirXasm32
	add esi,eax
	cmp esi,edi
	jb KeBugCheckCount@Step
	jmp Error
KdInitSystem@Scan:
; _KdInitSystem
	lea ebx,[esi + 50H]
	mov edi,NtImageBase
KdInitSystem@Step:
	Call VirXasm32
	add esi,eax
	cmp byte ptr [esi],OPCODE_CALL	; call _KdInitSystem
	jne KdInitSystem@Next
	cmp word ptr [esi + 5],056AH	; push DBG_STATUS_FATAL(5)
	jne KdInitSystem@Next
	cmp byte ptr [esi + 7],OPCODE_CALL	; call _KiBugCheckDebugBreak
	jne KdInitSystem@Next
	mov eax,ImageHeader
	add esi,dword ptr [esi + 1]
	mov eax,IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage[eax]
	add esi,5		; _KdInitSystem
	add eax,edi
	mov Fn.pKdInitSystem,esi
	lea ebx,[esi + 80H]
	mov ImageLimit,eax
	cmp esi,edi
	jna Error
	cmp esi,eax
	jae Error
KiDebugRoutine@Step:
	Call VirXasm32
	add esi,eax
	cmp word ptr [esi],05C7H		; mov dword ptr ds:[_KiDebugRoutine],@KdpStub
	jne KiDebugRoutine@Next
	mov ecx,dword ptr [esi + 2]	; @KiDebugRoutine
	mov edx,dword ptr [esi + 6]	; @KdpStub
	cmp ecx,edi
	jna Error
	cmp edx,edi
	jna Error
	cmp ImageLimit,ecx
	jbe Error
	cmp ImageLimit,edx
	jbe Error
	cld
	mov Fn.pKiDebugRoutine,ecx
	lea esi,Fn
	mov edi,DbgEnv
	mov ecx,sizeof(KDEBUG_ENVIRONMENT)/4
	mov Fn.pKdpStub,edx
	xor eax,eax
	rep movsd
	jmp Exit
KiDebugRoutine@Next:
	cmp byte ptr [esi],OPCODE_CALL
	je Error
	cmp esi,ebx
	jc KiDebugRoutine@Step
	jmp Error	
KdInitSystem@Next:
	cmp byte ptr [esi],0C3H	; ret
	je Error
	cmp esi,ebx
	jc KdInitSystem@Step
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xQueryDebugEnvironment endp