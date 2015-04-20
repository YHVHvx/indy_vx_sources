; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
; Маршрутизация.
;
SWT_KERNEL_MODE		equ 000001B
SWT_TRACE				equ 000010B
SWT_ENABLE_ROUTING		equ 000100B
SWT_ROUTE_LAST_FRAME	equ 001000B
SWT_CURRENT_CALLER		equ 010000B

STACK_FRAME_EX struct
Ref		PVOID ?
Sfc		STACK_FRAME <>
STACK_FRAME_EX ends
PSTACK_FRAME_EX typedef ptr STACK_FRAME_EX

PcStackBase	equ 4
PcStackLimit	equ 8

TsDbgArgMark	equ 00008H	; KTRAP_FRAME.DbgArgMark

MODE_MASK		equ 01B
KernelMode	equ 0
UserMode		equ 1

comment '
typedef NTSTATUS (*PSET_CONTEXT_ROUTINE)(
   IN PVOID Ip,
   IN PVOID Gp,
   IN PVOID Arg
   );

typedef NTSTATUS (*PFRAME_ENUMERATION_ROUTINE)(
   IN ULONG Mode,
   IN OUT PSTACK_FRAME_EX Frame,
   IN PVOID Arg
   );

typedef NTSTATUS (*PFRAME_LOAD_ROUTINE)(
   IN PSTACK_FRAME Frame,
   IN PVOID Ip,
   IN PVOID Gp,
   IN PVOID Arg
   );

typedef NTSTATUS (*PENTRY)(
  IN PGP_SNAPSHOTPVOID Snapshot,
  IN ULONG Flags,
  IN PVOID Ip,
  IN ULONG NestingLevel,
  IN PSEARCH_CALLBACK_ROUTINE SetCtxRoutine,
  IN PVOID SetCtxRoutineArg
  IN PPARSE_CALLBACK_ROUTINE FrEnumRoutine OPTIONAL,
  IN PVOID FrEnumRoutineArg,
  IN PSEARCH_CALLBACK_ROUTINE FrLoadRoutine OPTIONAL,
  IN PVOID FrLoadRoutineArg
  );
  '
  
; +
; 
GpSwitchThread proc uses ebx esi edi Snapshot:PGP_SNAPSHOT, Flags:ULONG, Ip:PVOID, NL:ULONG, SetCtxRoutine:PVOID, SetCtxRoutineArg:PVOID, FrEnumRoutine:PVOID, FrEnumRoutineArg:PVOID, FrLoadRoutine:PVOID, FrLoadRoutineArg:PVOID
Local GpEntry:PVOID, GpFirstEntry:PVOID
Local Frame:STACK_FRAME_EX
Local Mode:BOOLEAN
	test Flags,SWT_KERNEL_MODE
	xor ebx,ebx	; Bp
	setz byte ptr [Mode]
	xor edi,edi	; Frame
	and Mode,MODE_MASK
	cmp NL,ebx
	mov Frame.Ref,ebx
	lea esi,Frame
	jnz Walk
	test Flags,SWT_CURRENT_CALLER
	jnz Walk
	mov eax,Ip
	Call xGpCheckIpBelongToSnapshot
	test eax,eax
	jz Switch
	cmp eax,STATUS_NOT_FOUND
	jnz Exit
	jmp Walk
Switch:
	mov eax,GpEntry
 if GP_LINK_VALIDATION
	mov eax,dword ptr [eax + EhCrossLink]
	and eax,NOT(TYPE_MASK)
	jz Error	; Rw-table, IDLE etc.
 endif
	push SetCtxRoutineArg
	push eax
	push dword ptr [eax + EhAddress]
	Call SetCtxRoutine
	jmp Exit
Walk:
	inc NL
Scan:
	.if !FrEnumRoutine
	   mov eax,Frame.Ref
	   .if !Eax
	      mov eax,ebp
	   .else
	      mov eax,STACK_FRAME.Next[eax]
	   .endif
	   cmp fs:[PcStackBase],eax
	   jna Error
	   cmp fs:[PcStackLimit],eax
	   ja Error
	   test Mode,MODE_MASK
	   mov Frame.Ref,eax
	   .if Zero?	; KernelMode
	      cmp dword ptr [eax + TsDbgArgMark],0BADB0D00H
	      je Error	; Trap frame.
	   .endif
	   mov ecx,STACK_FRAME.Ip[eax]
	   mov edx,STACK_FRAME.Next[eax]
	   mov Frame.Sfc.Ip,ecx
	   mov Frame.Sfc.Next,edx
	.else
	   push FrEnumRoutineArg
	   push esi
	   push Mode
	   Call FrEnumRoutine
	   test eax,eax
	   jnz Exit
	.endif
	mov eax,Frame.Sfc.Ip
	Call xGpCheckIpBelongToSnapshot
	.if Eax
	   cmp eax,STATUS_NOT_FOUND
	   jne Exit
	   test edi,edi
	   jnz Exit
	   jmp Scan
	.endif
	test edi,edi
	.if Zero?
	   mov eax,GpEntry
	   mov edi,Frame.Ref
	   mov GpFirstEntry,eax
	.endif
	dec NL
	jnz Scan
	test Flags,SWT_CURRENT_CALLER
	mov ebx,GpEntry
	.if Zero?
	   mov eax,Ip
	   Call xGpCheckIpBelongToSnapshot
	   test eax,eax
	   jz Switch
	   cmp eax,STATUS_NOT_FOUND
	   jne Exit
	.endif
	test Flags,SWT_ENABLE_ROUTING
	jz Error
	test Flags,SWT_ROUTE_LAST_FRAME
	.if Zero?
	   mov eax,ebx
	   mov ecx,Frame.Ref
	.else
	   mov eax,GpFirstEntry
	   mov ecx,edi
	.endif
 if GP_LINK_VALIDATION
	mov eax,dword ptr [eax + EhCrossLink]
	and eax,NOT(TYPE_MASK)
	jz Error	; Rw-table, IDLE etc.
 endif
	push FrLoadRoutineArg
	push eax
	push dword ptr [eax + EhAddress]
	push ecx
	.if !FrLoadRoutine
	   pop ecx
	   xor eax,eax
	   pop STACK_FRAME.Ip[ecx]
	   add esp,2*4
	.else
	   Call FrLoadRoutine
	.endif
Exit:
	ret
xGpCheckIpBelongToSnapshot:
	lea ecx,GpEntry
	test Flags,SWT_TRACE
	push ecx
	push eax
	.if Zero?
	   push Snapshot
	   Call CsCheckIpBelongToSnapshot
	.else
	   push GCBE_PARSE_NL_UNLIMITED
	   push Snapshot
	   Call RwCheckIpBelongToSnapshot
	.endif
	retn
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
GpSwitchThread endp