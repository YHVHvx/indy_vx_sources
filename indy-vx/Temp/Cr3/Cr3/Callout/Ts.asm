_imp__EnumDisplayMonitors proto :dword, :dword, :dword, :dword

QUERY_SERVICE_ID macro
	mov eax,dword ptr [_imp__EnumDisplayMonitors]
	mov eax,dword ptr [eax + 1]	; ID NtUserEnumDisplayMonitors
endm

; +
; Сохранение контекста.
; o Сохраняются регистры:
;   - EFlags
;   - Ebp
;   - Ebx
;   - Esp
;
SAVE_TASK_STATE macro Ip
Local Break
	mov esi,Ip
	mov edi,esp
	Call @f
	jmp Break
@@:	
	pushad
	xor ecx,ecx
	push esp
	Call @f
	mov esp,dword ptr [esp + 4*4]
	popad
	retn
@@:
	push ecx
	push ecx
	QUERY_SERVICE_ID
	mov edx,esp
	Int 2EH
	xor eax,eax
	mov esp,edi
	jmp esi
Break:
endm

; Восстановление контекста.
;
RESTORE_TASK_STATE macro
	xor eax,eax
	mov edx,3*4
	push eax
	push eax
	push eax
	mov ecx,esp
	Int 2BH
endm