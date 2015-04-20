	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\ws2_32.inc
	includelib \masm32\lib\ws2_32.lib
	
	include \masm32\include\urlmon.inc
	includelib \masm32\lib\urlmon.lib

.code
	include Img.asm
	include GCBE\Bin\Gcbe.inc

	include Wsp.asm
	include Hmgr.asm
	include Htr.asm
	include Trap.asm
	
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

.data
cDBG_XCPT_BREAK_DISPATCH	ULONG ?

Env	ENVIRONMENT <>

.code
$File db "c:\1.html", 0
$Link db "http://www.google.ru/",0

HsForceFlags    equ 10H    ; HEAP.ForceFlags

HEAP_FLAG_PAGE_ALLOCS			equ 01000000H
HEAP_SKIP_VALIDATION_CHECKS		equ 10000000H
HEAP_VALIDATE_ALL_ENABLED		equ 20000000H
HEAP_VALIDATE_PARAMETERS_ENABLED	equ 40000000H

xHmgrInvalidateHeapsCallback:
	%GET_CURRENT_GRAPH_ENTRY
HmgrInvalidateHeapsCallback proc HeapHandle:HANDLE, NewSign:ULONG 
	mov eax,NewSign
	mov ecx,HeapHandle
	lock xchg dword ptr [ecx + HsSignature],eax
	and dword ptr [ecx + HsForceFlags],NOT(HEAP_FLAG_PAGE_ALLOCS or HEAP_SKIP_VALIDATION_CHECKS)
	or dword ptr [ecx + HsForceFlags],(HEAP_VALIDATE_ALL_ENABLED or HEAP_VALIDATE_PARAMETERS_ENABLED)
	xor eax,eax
	ret
HmgrInvalidateHeapsCallback endp

Ip proc
Local Api:APIS
Local WspParseData:WSP_PARSE_DATA
Local HmgrSnapshot:GP_SNAPSHOT
Local Wsa:WSADATA
	invoke InitializeApis, addr Env.Apis
	%NTERR
	invoke WspInitialize, addr Env.Apis, addr Env.WspSnapshot
	%NTERR
	invoke HmgrInitialize, addr Env.Apis, addr Env.HmgrSnapshot
	%NTERR
	
	%GET_GRAPH_ENTRY xXcptDispatch
	push eax
	push TRUE
	Call Env.Apis.pRtlAddVectoredExceptionHandler
	%APIERR
	
	%SET_ENV_PTR offset Env
	mov eax,fs:[TEB.Peb]
	or PEB.BeingDebugged[eax],1
	
	push INVALID_HEAP_SIGNATURE
	%GET_GRAPH_ENTRY xHmgrInvalidateHeapsCallback
	push eax
	Call Env.Apis.pRtlEnumProcessHeaps
	%NTERR

	invoke HtEnableHandleTracing, addr Env.Apis
	%NTERR
	
	invoke WSAStartup, 0202H, addr Wsa
	invoke URLDownloadToFile, NULL, addr $Link, addr $File, 0, NULL
	
	invoke WSACleanup
	ret
Ip endp
end Ip