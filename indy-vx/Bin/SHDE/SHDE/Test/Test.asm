	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.code
SHDE:
	include SHDE.inc

.data
gDb	DATABASE <>

.code
$Fail	CHAR "Analysis failure: %s", 13, 10, 0
$Present	CHAR "Hook: %s, 0x%p", 13, 10, 0
$Defined	CHAR "Hook: %s, 0x%p, %s", 13, 10, 0

Entry proc
	push offset gDb
	Call SHDE
	.if Eax
		Int 3
	.endif
	mov ebx,gDb.AvList
	assume ebx:PSYSENTRY
	mov esi,SERVICE_COUNT
Log:
	test [ebx].Flags,FLG_ANALYSIS_FAILURE
	.if !Zero?
		invoke DbgPrint, addr $Fail, [ebx].SsList
	.else
		test [ebx].Flags,FLG_FILTER_PRESENT
		.if !Zero?
			test [ebx].Flags,FLG_FILTER_DEFINED
			.if !Zero?
				mov ecx,[ebx].AvList
				lea ecx,RTL_PROCESS_MODULE_INFORMATION.FullPathName[ecx]
				invoke DbgPrint, addr $Defined, [ebx].SsList, [ebx].Filter, Ecx
			.else
				invoke DbgPrint, addr $Present, [ebx].SsList, [ebx].Filter
			.endif
		.endif
	.endif
	add ebx,sizeof(SYSENTRY)
	dec esi
	jnz Log
	ret
Entry endp
end Entry