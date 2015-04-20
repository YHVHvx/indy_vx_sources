.code
	include ..\..\..\Bin\Graph\Dasm\VirXasm32b.asm
	include ..\..\..\Bin\Graph\Mm\Img.asm
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Статический поиск переменной ntdll.ShowSnaps
;
QueryShowSnaps proc uses esi ShowSnaps:PVOID
Local List[2]:DWORD
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor eax,eax
	lea ecx,List
	mov dword ptr [List],0B64C13EEH	; CRC32("LdrGetProcedureAddress")
	mov dword ptr [List + 4],eax
	invoke NtEncodeEntriesList, Eax, Eax, Ecx, Ecx
	test eax,eax
	mov esi,dword ptr [List]	; ptr LdrGetProcedureAddress()
	jnz exit_
	mov ecx,40H
sub_query_:
	cmp byte ptr [esi],0E8H	; Call near.
	jne sub_next_
	add esi,dword ptr [esi + 1]
	add esi,5	; LdrpGetProcedureAddress()/LdrGetProcedureAddressEx()
	mov ecx,50H
var_query_:
	Call VirXasm32
	cmp al,6
	jb var_next_
	cmp word ptr [esi],3D80H	; cmp byte ptr ds:[XXXX],0
	jne @f
	cmp byte ptr [esi + 6],0
	jne var_next_
	jmp store_
@@:
	cmp word ptr [esi],0585H	; test dword ptr ds:[XXXX],eax
	jne var_next_
store_:
	mov ecx,dword ptr [esi + 2]
	mov edx,ShowSnaps
	xor eax,eax
	mov dword ptr [edx],ecx
	jmp exit_
var_next_:
	add esi,eax
	loop var_query_
	jmp error_
sub_next_:
	Call VirXasm32
	add esi,eax
	loop sub_query_
error_:
	mov eax,STATUS_NOT_FOUND
	jmp exit_
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
exit_:
	Call SEH_Epilog
	ret
QueryShowSnaps endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~