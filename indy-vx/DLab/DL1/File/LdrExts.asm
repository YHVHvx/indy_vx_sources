; Расширения для загрузчика.
; o Микод.
; o Не нарушается цепочка стековых фреймов.
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
LDR_LOAD_DLL		equ 0
LDR_QUERY_ENTRY	equ 1
LDR_QUERY_ENTRIES	equ 2

; #define LDR_LOAD_DLL 0x00000000
; 
; typedef NTSTATUS (*PENTRY)(
; 	IN PVOID MapAddress,
; 	IN PSTR DllName,
; 	IN PULONG DllCharacteristics OPTIONAL,
; 	OUT PVOID *ImageBase
; 	);
; 
; * Имя модуля при загрузке не имеет значения.
; 	
; #define LDR_QUERY_ENTRY 0x00000001
; 
; typedef NTSTATUS (*PENTRY)(
; 	IN PVOID ImageBase OPTIONAL,
; 	IN PVOID HashOrFunctionName,
; 	IN PCOMPUTE_HASH_ROUTINE HashRoutine OPTIONAL,
; 	IN ULONG PartialCrc,
; 	OUT *PVOID Entry
; 	);
; 	
; typedef ULONG (*PCOMPUTE_HASH_ROUTINE)(
; 	IN ULONG UserParameter,
; 	IN PVOID Buffer,
; 	IN ULONG Length
; 	);
; 	
; * Если калбэк вычисляющий хэш(HashRoutine) не задан, то второй параметр рассматривается как указатель на имя экспорта.
; * Если база модуля не задана, то используется ntdll.
; * Калбэк должен возвратить в регистре Eax хэш для строки.
; 
; #define LDR_QUERY_ENTRIES 0x00000002
; 
; typedef NTSTATUS (*PENTRY)(
; 	IN PVOID ImageBase OPTIONAL,
; 	IN ULONG PartialCrc,
; 	IN OUT *PVOID EntriesList
; 	);
; 
; * Маркером конца списка хэшей(CRC32) является ноль.


.code
	include Ldr.inc
	include VirXasm32b.asm
	
BREAKER macro
	.if Eax
	Int 3
	.endif
endm

GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm

SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	assume fs:nothing
	push dword ptr fs:[TEB.Tib.ExceptionList]
	mov dword ptr fs:[TEB.Tib.ExceptionList],esp
	jmp ecx
SEH_Prolog endp

; o Не восстанавливаются Ebx, Esi и Edi.
;
SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[TEB.Tib.ExceptionList]
	lea esp,[esp + 3*4]
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

_$_GetCallbackReference::
	pop eax
	ret
	
; +
; Поправка базы для GetModuleHandle(0).
;
LDR_FIXUP_PEB macro DllHandle
	assume fs:nothing
	mov ecx,fs:[TEB.Peb]
	mov eax,DllHandle
	lock xchg PEB.ImageBaseAddress[ecx],eax
endm

; +
; Поправка базы для загрузчика(GetModuleHandle() etc).
;
LDR_FIXUP_DATABASE macro DllHandle
	assume fs:nothing
	mov ecx,fs:[TEB.Peb]
	mov eax,DllHandle
	mov ecx,PEB.Ldr[ecx]
	mov ecx,PEB_LDR_DATA.InLoadOrderModuleList.Flink[ecx]
	lock xchg LDR_DATA_TABLE_ENTRY.DllBase[ecx],eax
endm

LdrImageNtHeader proc ImageBase:PVOID, ImageHeader:PIMAGE_NT_HEADERS
	mov edx,ImageBase
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	assume edx:PIMAGE_DOS_HEADER
	cmp [edx].e_magic,'ZM'
	jne @f
	add edx,[edx].e_lfanew
	assume edx:PIMAGE_NT_HEADERS
	cmp [edx].Signature,'EP'
	jne @f
	cmp [edx].FileHeader.SizeOfOptionalHeader,sizeof(IMAGE_OPTIONAL_HEADER32)
	jne @f
	cmp [edx].FileHeader.Machine,IMAGE_FILE_MACHINE_I386	
	jne @f
	test [edx].FileHeader.Characteristics,IMAGE_FILE_32BIT_MACHINE
	je @f
	mov ecx,ImageHeader
	xor eax,eax
	mov dword ptr [ecx],edx
@@:
	ret
LdrImageNtHeader endp

; +
; Перечисление загруженных модулей.
;
comment '
typedef
VOID (NTAPI *PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION)(
    IN PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    IN PVOID Context,
    IN OUT BOOLEAN *StopEnumeration
    );'
    
xLdrEnumerateLoadedModules proc EnumerationRoutine:PVOID, EnumerationContext:PVOID
Local pLdrEnumerateLoadedModules[2]:PVOID
	xor ecx,ecx
	lea edx,pLdrEnumerateLoadedModules
	mov pLdrEnumerateLoadedModules[0],0FC07EBC7H	; CRC32("LdrEnumerateLoadedModules")
	mov eax,LDR_QUERY_ENTRIES
	mov pLdrEnumerateLoadedModules[4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	.if !Eax
	push EnumerationContext
	push EnumerationRoutine
	push eax
	Call pLdrEnumerateLoadedModules[0]
	.endif
	ret
xLdrEnumerateLoadedModules endp

; +
; Поиск модуля по указателю в нём.
; o STATUS_NO_MORE_ENTRIES если не найден модуль.
;
xLdrFindEntryForAddress proc Address:PVOID, TableEntry:PVOID
Local pLdrFindEntryForAddress[2]:PVOID
	xor ecx,ecx
	lea edx,pLdrFindEntryForAddress
	mov pLdrFindEntryForAddress[0],0CB096353H	; CRC32("LdrFindEntryForAddress")
	mov eax,LDR_QUERY_ENTRIES
	mov pLdrFindEntryForAddress[4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	.if !Eax
	push TableEntry
	push Address
	Call pLdrFindEntryForAddress[0]
	.endif
	ret
xLdrFindEntryForAddress endp

; +
; Запрещает вызов InitRoutine модуля.
;
xLdrDisableThreadCalloutsForDll proc DllHandle:PVOID
Local pLdrDisableThreadCalloutsForDll[2]:PVOID
	xor ecx,ecx
	lea edx,pLdrDisableThreadCalloutsForDll
	mov pLdrDisableThreadCalloutsForDll[0],21F56BC4H	; CRC32("LdrDisableThreadCalloutsForDll")
	mov eax,LDR_QUERY_ENTRIES
	mov pLdrDisableThreadCalloutsForDll[4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	.if !Eax
	push DllHandle
	Call pLdrDisableThreadCalloutsForDll[0]
	.endif
	ret
xLdrDisableThreadCalloutsForDll endp

; +
; Получение списка модулей.
;
RTL_PROCESS_MODULE_INFORMATION struct
Section			HANDLE ?
MappedBase		PVOID ?
ImageBase			PVOID ?
ImageSize			ULONG ?
Flags			ULONG ?
LoadOrderIndex		USHORT ?
InitOrderIndex		USHORT ?
LoadCount			USHORT ?
OffsetToFileName	USHORT ?
FullPathName		UCHAR 256 DUP (?)
RTL_PROCESS_MODULE_INFORMATION ends
PRTL_PROCESS_MODULE_INFORMATION typedef ptr RTL_PROCESS_MODULE_INFORMATION

RTL_PROCESS_MODULES struct
NumberOfModules	ULONG ?
Modules			RTL_PROCESS_MODULE_INFORMATION 1 DUP (<>)
RTL_PROCESS_MODULES ends
PRTL_PROCESS_MODULES typedef ptr RTL_PROCESS_MODULES

xLdrQueryProcessModuleInformation proc ModuleInformation:PRTL_PROCESS_MODULES, ModuleInformationLength:ULONG, ReturnLength:PULONG
Local pLdrQueryProcessModuleInformation[2]:PVOID
	xor ecx,ecx
	lea edx,pLdrQueryProcessModuleInformation
	mov pLdrQueryProcessModuleInformation[0],0A1B699E6H	; CRC32("LdrQueryProcessModuleInformation")
	mov eax,LDR_QUERY_ENTRIES
	mov pLdrQueryProcessModuleInformation[4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	.if !Eax
	push ReturnLength
	push ModuleInformationLength
	push ModuleInformation
	Call pLdrQueryProcessModuleInformation[0]
	.endif
	ret
xLdrQueryProcessModuleInformation endp

; +
; Получает базу модуля по имени.
;
xLdrGetDllHandle proc DllName:PSTR, DllHandle:PVOID
Local Entries[4]:PVOID
Local DllNameU:UNICODE_STRING
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],0F45CAC9DH	; CRC32("RtlCreateUnicodeStringFromAsciiz")
	mov Entries[4],043681CE6H	; CRC32("RtlFreeUnicodeString")
	mov Entries[2*4],0E21C1C46H	; CRC32("LdrGetDllHandle")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[3*4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	lea ecx,DllNameU
	jnz Exit
	push DllName
	push ecx
	Call Entries[0]	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea ecx,DllNameU
	.if Zero?
	mov eax,STATUS_INVALID_PARAMETER
	.else
	push DllHandle
	push ecx
	push NULL
	push NULL
	Call Entries[2*4]	; LdrGetDllHandle()
	lea ecx,DllNameU
	push eax
	push ecx
	Call Entries[4]	; RtlFreeUnicodeString()
	pop eax
	.endif
Exit:
	ret
xLdrGetDllHandle endp

; +
; Загрузка модуля посредством LdrLoadDll().
;
xLdrLoadDll proc DllName:PSTR, DllCharacteristics:PULONG, DllHandle:PVOID
Local Entries[4]:PVOID
Local DllNameU:UNICODE_STRING
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],0F45CAC9DH	; CRC32("RtlCreateUnicodeStringFromAsciiz")
	mov Entries[4],043681CE6H	; CRC32("RtlFreeUnicodeString")
	mov Entries[2*4],0183679F2H	; CRC32("LdrLoadDll")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[3*4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	lea ecx,DllNameU
	jnz Exit
	push DllName
	push ecx
	Call Entries[0]	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea ecx,DllNameU
	.if Zero?
	mov eax,STATUS_INVALID_PARAMETER
	.else
	push DllHandle
	push ecx
	push DllCharacteristics
	push NULL
	Call Entries[2*4]	; LdrLoadDll()
	lea ecx,DllNameU
	push eax
	push ecx
	Call Entries[4]	; RtlFreeUnicodeString()
	pop eax
	.endif
Exit:
	ret
xLdrLoadDll endp

; +
; Выгрузка модуля.
;
LDRP_COR_OWNS_UNMAP	equ 800000H

xLdrUnloadDll proc DllHandle:PVOID, DontUnmap:BOOLEAN
Local Entries[3]:PVOID
Local TableEntry:PLDR_DATA_TABLE_ENTRY
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],0CB096353H	; CRC32("LdrFindEntryForAddress")
	mov Entries[4],0FED4B3C2H	; CRC32("LdrUnloadDll")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[2*4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	lea ecx,TableEntry
	jnz Exit
	push ecx
	push DllHandle
	Call Entries[0]
	test eax,eax
	jnz Exit
	cmp DontUnmap,eax
	mov ecx,TableEntry
	.if Zero?
	btr dword ptr LDR_DATA_TABLE_ENTRY.Flags[ecx],23	; LDRP_COR_OWNS_UNMAP
	.else
	bts LDR_DATA_TABLE_ENTRY.Flags[ecx],23
	.endif
	push DllHandle
	Call Entries[4]	; LdrUnloadDll()
Exit:
	ret
xLdrUnloadDll endp

; +
; Поиск переменной ShowSnaps.
; o Используется дизассемблер длин(by Malum).
; o Переменная размером в байт.
; Если значение этой переменной отлично от нуля, то выполняется 
; логгирование событий в загрузчике посредством вывода отладочных
; сообщений, напр. при вызове LdrGetProcedureAddress(): DbgPrint(
; "LDR: LdrGetProcedureAddress by NAME - %s", либо "LDR: LdrGetPr
; ocedureAddress by ORDINAL - %lx").
; Для фильтрации установить обработчик исключений, фильтрующий 
; DBG_PRINTEXCEPTION_C(0x40010006, PEB.BeingDebugged = TRUE).
; Информация об исключении:
;  - ExceptionRecord.ExceptionCode = DBG_PRINTEXCEPTION_C
;  - ExceptionRecord.NumberParameters = 2
;  - ExceptionRecord.ExceptionFlags = 0
;  - ExceptionRecord.ExceptionInformation[0] = Length + 1
;  - ExceptionRecord.ExceptionInformation[4] = @String
;
OP_CALL_NEAR	equ 0E8H

xLdrQueryShowSnaps proc uses ebx esi edi ImageBase:PVOID, ShowSnaps:PVOID
Local Entries[2]:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],0B64C13EEH	; CRC32("LdrGetProcedureAddress")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[4],ecx
	push edx
	push ecx
	push ImageBase
	Call LDR
	test eax,eax
	mov esi,Entries[0]	; @LdrGetProcedureAddress()
	jnz Exit
	mov ecx,40H
QuerySub:
	cmp byte ptr [esi],OP_CALL_NEAR
	jne FindSub
	add esi,dword ptr [esi + 1]
	add esi,5		; @LdrpGetProcedureAddress()/@LdrGetProcedureAddressEx()
	mov ecx,50H
QueryVar:
	Call VirXasm32
	cmp al,6
	jb NextVar
	cmp word ptr [esi],3D80H	; cmp byte ptr ds:[XXXX],0
	jne @f
	cmp byte ptr [esi + 6],0
	jne NextVar
	jmp Store
@@:
	cmp word ptr [esi],0585H	; test dword ptr ds:[XXXX],eax
	jne NextVar
Store:
	mov ecx,dword ptr [esi + 2]
	mov edx,ShowSnaps
	xor eax,eax
	mov dword ptr [edx],ecx
	jmp Exit
NextVar:
	add esi,eax
	loop QueryVar
	jmp Error
FindSub:
	Call VirXasm32
	add esi,eax
	loop QuerySub	; ..
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xLdrQueryShowSnaps endp

; +
; Разрешает логгирование событий загрузчиком и устанавливает VEH.
;
xLdrEnableShowSnaps proc uses ebx esi edi ShowSnaps:PVOID, Handler:PVOID, First:BOOLEAN, ListEntry:PVOID
Local Entries[2]:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor ecx,ecx
	lea edx,Entries
	mov ebx,ShowSnaps
	mov Entries[0],0BAAB0208H	; CRC32("RtlAddVectoredExceptionHandler")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	mov esi,dword ptr [ebx]
	jnz Exit
	test esi,esi
	lea edx,ShowSnaps
	.if Zero?
	invoke xLdrQueryShowSnaps, Eax, Edx
	test eax,eax
	mov esi,ShowSnaps
	jnz Exit
	mov dword ptr [ebx],esi
	.endif
	push Handler
	push First
	Call Entries[0]
	test eax,eax
	mov ecx,ListEntry
	.if Zero?
	mov eax,STATUS_INTERNAL_ERROR
	jmp Exit
	.endif
	mov edx,fs:[TEB.Peb]
	mov dword ptr [ecx],eax
	mov byte ptr [esi],TRUE
	mov PEB.BeingDebugged[edx],TRUE
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xLdrEnableShowSnaps endp

; +
; Поиск переменной LdrpLoaderLockAcquisitionCount.
; o Ссылка на LdrpLoaderLock находится в PEB.LoaderLock
;
; LdrLockLoaderLock:
; ...
; B9 XXXX		mov ecx,offset ntdll.LdrpLoaderLockAcquisitionCount
; F00FC119	lock xadd dword ptr ds:[ecx],ebx
;
xLdrQueryLoaderLockAcquisitionCountReference proc uses ebx esi edi ImageBase:PVOID, AcquisitionCountReference:PVOID
Local Entries[2]:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],95DB37F4H		; CRC32("LdrLockLoaderLock")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[4],ecx
	push edx
	push ecx
	push ImageBase
	Call LDR
	test eax,eax
	mov edi,Entries[0]
	jnz Exit
	cld
	mov ecx,0A4H
	mov al,0B9H
Scan:
	repne scasb
	jne @f
	cmp dword ptr [edi + 4],19C10FF0H
	jne @f
	mov ecx,dword ptr [edi]
	mov edx,AcquisitionCountReference
	xor eax,eax
	mov dword ptr [edx],ecx
	jmp Exit
@@:
	test ecx,ecx	; Don't use Jecxz.
	jnz Scan
	mov eax,STATUS_NOT_FOUND
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xLdrQueryLoaderLockAcquisitionCountReference endp

; +
; Перечисление фиксапов для ссылки.
;
; typedef VOID (*LDR_FIXUP_ENUMERATION_CALLBACK)(
;	IN PVOID ImageBase,
;	IN PVOID Fixup,
;	IN PVOID Context,
;	IN OUT BOOLEAN *StopEnumeration
;	);
;
xLdrEnumerateFixups proc uses ebx esi edi ImageBase:PVOID, Section:PIMAGE_SECTION_HEADER, Ip:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
Local ExitFlag:BOOLEAN
Local SectionBaseVA:ULONG, SectionLimitVA:ULONG
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	.if ImageBase == NULL
	mov eax,fs:[TEB.Peb]
	mov ecx,PEB.LoaderLock[eax]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	mov ImageBase,eax
	.endif
	invoke LdrImageNtHeader, ImageBase, addr ExitFlag
	test eax,eax
	mov ecx,ExitFlag
	mov edx,Section
	jnz Exit
	test edx,edx
	mov esi,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress[ecx + IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof(IMAGE_DATA_DIRECTORY)]
	mov edi,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory._Size[ecx + IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof(IMAGE_DATA_DIRECTORY)]
	.if !Zero?
	mov eax,IMAGE_SECTION_HEADER.VirtualAddress[edx]
	mov SectionBaseVA,eax
	add eax,IMAGE_SECTION_HEADER.VirtualSize[edx]
	mov SectionLimitVA,eax
	.endif
	test esi,esi
	mov edx,Ip
	jz Error
	test edx,edx
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage[ecx]
	jz @f
	sub edx,ImageBase
	jbe Error
	cmp edx,ecx
	jnb Error
@@:
	test edi,edi
	jz Error
	add esi,ImageBase
	add edi,esi	; Limit
	assume esi:PIMAGE_BASE_RELOCATION
Scan:
	mov ebx,[esi].SizeOfBlock
	sub ebx,sizeof(IMAGE_BASE_RELOCATION)
	jbe Error		; ..
	shr ebx,1
	cmp Section,NULL
	mov eax,[esi].VirtualAddress
	jz @f
	cmp SectionBaseVA,eax
	mov edx,SectionLimitVA
	ja Block
	cmp SectionLimitVA,eax
	jbe Block
@@:
	movzx eax,word ptr [esi + ebx*2 + sizeof(IMAGE_BASE_RELOCATION) - 2]
	mov edx,eax
	and edx,NOT(0FFFH)
	and eax,0FFFH
	cmp edx,(IMAGE_REL_BASED_HIGHLOW shl 12)
	jne Next
	add eax,[esi].VirtualAddress
	mov ecx,Ip
	add eax,ImageBase
	.if !Ecx || dword ptr [Eax] == Ecx
	lea edx,ExitFlag
	mov ExitFlag,FALSE
	push edx
	push CallbackParameter
	push eax
	push ImageBase
	Call CallbackRoutine
	cmp ExitFlag,FALSE
	jne Exit
	.endif
Next:
	dec ebx
	jnz @b
Block:
	add esi,[esi].SizeOfBlock
	cmp esi,edi
	jb Scan
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
xLdrEnumerateFixups endp

; +
; Получение базы Kernel32.dll
;
xLdrGetKernel32ImageBase proc DllHandle:PVOID
Local DllName[16]:CHAR
	mov dword ptr [DllName],"nreK"
	mov dword ptr [DllName + 4],"23le"
	mov dword ptr [DllName + 2*4],"lld."
	mov dword ptr [DllName + 3*4],0
	invoke xLdrGetDllHandle, addr DllName, DllHandle
	ret
xLdrGetKernel32ImageBase endp

; +
; Загрузка User32.dll
;
xLdrLoadUser32 proc DllHandle:PVOID
Local DllName[12]:CHAR
	mov dword ptr [DllName],"resU"
	mov dword ptr [DllName + 4],"d.23"
	mov dword ptr [DllName + 2*4],"ll"
	invoke xLdrLoadDll, addr DllName, NULL, DllHandle
	ret
xLdrLoadUser32 endp

; +
; Установка LdrpAppCompatDllRedirectionCallbackFunction и LdrpAppCompatDllRedirectionCallbackData.
; o Не возвращает предыдущие значения.
; o В W7 заглушка.
;
comment '
NTSTATUS
NTAPI
LdrSetAppCompatDllRedirectionCallback(
    IN ULONG Flags,
    IN PLDR_APP_COMPAT_DLL_REDIRECTION_CALLBACK_FUNCTION CallbackFunction,
    IN PVOID CallbackData
    );
    
typedef
NTSTATUS (NTAPI *PLDR_APP_COMPAT_DLL_REDIRECTION_CALLBACK_FUNCTION)(
    IN ULONG Flags,
    IN PCWSTR DllName,
    IN PCWSTR DllPath OPTIONAL,
    IN OUT PULONG DllCharacteristics OPTIONAL,
    IN PVOID CallbackData,
    OUT PWSTR *EffectiveDllPath
    );
    '
xLdrSetAppCompatDllRedirectionCallback proc CallbackFunction:PVOID, CallbackData:PVOID
Local pLdrSetAppCompatDllRedirectionCallback[2]:PVOID
	xor ecx,ecx
	lea edx,pLdrSetAppCompatDllRedirectionCallback
	mov pLdrSetAppCompatDllRedirectionCallback[0],0A533A9FBH	; CRC32("LdrSetAppCompatDllRedirectionCallback")
	mov eax,LDR_QUERY_ENTRIES
	mov pLdrSetAppCompatDllRedirectionCallback[4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	.if !Eax
	push CallbackData
	push CallbackFunction
	push eax
	Call pLdrSetAppCompatDllRedirectionCallback[0]
	.endif
	ret
xLdrSetAppCompatDllRedirectionCallback endp

; +
; Загружает оригинальный модуль с диска.
; o Захват LdrpLoaderLock(монопольный доступ).
; o Не подгружается импорт.
; o Не выполняется нотификация модуля.
; o Релоки настраиваются.
;
LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED	equ 1

xLdrLoadImage proc DllName:PSTR, DllHandle:PVOID
Local Entries[3]:PVOID
Local DllCharacteristics:ULONG
Local LocDllHandle:PVOID
Local TableEntry:PLDR_DATA_TABLE_ENTRY
Local Cookie:ULONG
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],095DB37F4H	; CRC32("LdrLockLoaderLock")
	mov Entries[4],02CCB252FH	; CRC32("LdrUnlockLoaderLock")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[2*4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	lea ecx,Cookie
	jnz Exit
	push ecx
	push eax
	push LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED
	Call Entries[0]
	test eax,eax
	mov DllCharacteristics,LDRP_STATIC_LINK
	jnz Unlock
	invoke xLdrGetDllHandle, DllName, addr LocDllHandle
	test eax,eax
	jnz Unlock
	invoke xLdrFindEntryForAddress, LocDllHandle, addr TableEntry
	test eax,eax
	mov ecx,TableEntry
	jnz Unlock
; o Доступ при захваченной базе данных.
	assume ecx:PLDR_DATA_TABLE_ENTRY
	sub [ecx].BaseDllName._Length,2
	sub [ecx].FullDllName._Length,2
	invoke xLdrLoadDll, DllName, addr DllCharacteristics, DllHandle
	mov ecx,TableEntry
	add [ecx].BaseDllName._Length,2
	add [ecx].FullDllName._Length,2
Unlock:
	push eax
	push Cookie
	push LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED
	Call Entries[4]
	pop eax
Exit:
	ret
xLdrLoadImage endp

; +
; Загрузка оригинальной Ntdll.dll
;
xLdrLoadNtImage proc DllHandle:PVOID
Local DllName[12]:CHAR
	mov dword ptr [DllName],"ldtn"
	mov dword ptr [DllName + 4],"ld.l"
	mov dword ptr [DllName + 2*4],"l"
	invoke xLdrLoadImage, addr DllName, DllHandle
	ret
xLdrLoadNtImage endp

; +
;
OP_PUSH32	equ 68H

LDR_CALLBACK_DATA struct
Routine	PVOID ?
Context	PVOID ?
LDR_CALLBACK_DATA ends
PLDR_CALLBACK_DATA typedef ptr LDR_CALLBACK_DATA

$LdrSearchFixup:
	GET_CURRENT_GRAPH_ENTRY
LdrSearchFixupCallbackInternal proc ImageBase:PVOID, Fixup:PVOID, CallbackData:PLDR_CALLBACK_DATA, Stop:PBOOLEAN
	mov eax,Fixup
	mov ecx,CallbackData
	dec eax
	.if byte ptr [Eax] == OP_PUSH32
	push Stop
	push LDR_CALLBACK_DATA.Context[ecx]
	push eax
	push ImageBase
	Call LDR_CALLBACK_DATA.Routine[ecx]
	.endif
	xor eax,eax
	ret
LdrSearchFixupCallbackInternal endp

; +
; Ищет инструкцию Push XXXX для ссылки сканируя таблицу базовых поправок.
;
xLdrSearchReferenceInRelocationTable proc ImageBase:PVOID, Section:PIMAGE_SECTION_HEADER, Ip:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
	cmp Ip,NULL
	lea ecx,CallbackRoutine
	.if Zero?
	mov eax,STATUS_INVALID_PARAMETER
	.else
	Call $LdrSearchFixup
	invoke xLdrEnumerateFixups, ImageBase, Section, Ip, Eax, Ecx
	.endif
	ret
xLdrSearchReferenceInRelocationTable endp

; +
;
$LdrSearchFixupForLoaderLockInitialization:
	GET_CURRENT_GRAPH_ENTRY
LdrSearchFixupForLoaderLockInitializationCallbackInternal proc ImageBase:PVOID, Fixup:PVOID, LoaderLock:PVOID, Stop:PBOOLEAN
	mov eax,Fixup
	mov ecx,LoaderLock
	cmp byte ptr [eax - 1],0A1H	; mov eax,dword ptr ds:[LdrpLoaderLock]
	jne Exit
	cmp word ptr [eax + 4],40C7H	; mov dword ptr ds:[eax + 4],offset LdrpLoaderLock
	jne Exit
	cmp byte ptr [eax + 5],40H
	jne Exit
	dec eax
	mov edx,Stop
	mov dword ptr [ecx],eax
	mov dword ptr [edx],TRUE
Exit:
	xor eax,eax
	ret
LdrSearchFixupForLoaderLockInitializationCallbackInternal endp

; +
; Поиск кода, выполняющего инициализацию кс LdrpLoaderLock(внутри LdrpInitializeProcess()).
; 
xLdrSearchLoaderLockInitialization proc Reference:PVOID
Local ImageHeader:PIMAGE_NT_HEADERS
	mov eax,fs:[TEB.Peb]
	mov ecx,PEB.LoaderLock[eax]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov edx,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	Call $LdrSearchFixupForLoaderLockInitialization
	invoke xLdrEnumerateFixups, Edx, NULL, Ecx, Eax, Reference
	ret
xLdrSearchLoaderLockInitialization endp

; +
;
$LdrSearchFixupForLdrpShutdownInProgress:
	GET_CURRENT_GRAPH_ENTRY
LdrSearchFixupForLdrpShutdownInProgressCallbackInternal proc ImageBase:PVOID, Fixup:PVOID, Reference:PVOID, Stop:PBOOLEAN
	mov eax,Fixup
	mov ecx,Reference
	cmp dword ptr [eax + 4],50C0950FH	; setne al/push eax
	jne @f
	cmp dword ptr [eax - 4],0538C033H	; xor eax,eax/cmp byte ptr ds:[LdrpShutdownInProgress],al
	jne @f
	add eax,8
	mov edx,Stop
	mov dword ptr [ecx],eax
	mov dword ptr [edx],TRUE
@@:
	xor eax,eax
	ret
LdrSearchFixupForLdrpShutdownInProgressCallbackInternal endp

; +
; Поиск переменной LdrpDllNotificationList.
;
xLdrQueryLdrpDllNotificationList proc uses ebx esi edi DllHandle:PVOID, pLdrpDllNotificationList:PVOID
Local Reference:PVOID
Local Entries[2]:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],0778B6040H	; CRC32("RtlDllShutdownInProgress")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	mov ecx,Entries[0]
	jnz Exit
	.if dword ptr [ecx] == 0538C033H	; xor eax,eax/cmp byte ptr ds:[LdrpShutdownInProgress],al
	mov ecx,dword ptr [ecx + 4]		; @LdrpShutdownInProgress
	.elseif word ptr [ecx] == 3D80H	; cmp byte ptr ds:[LdrpShutdownInProgress],0
	mov ecx,dword ptr [ecx + 2]
	.else
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
	.endif
	lea edx,Reference
	Call $LdrSearchFixupForLdrpShutdownInProgress
	invoke xLdrEnumerateFixups, DllHandle, NULL, Ecx, Eax, Edx
	mov edx,0E856H		; push esi/call LdrpSendDllNotifications
	test eax,eax
	mov esi,Reference
	jnz Exit
	cmp word ptr [esi],dx
	je @f
	cmp word ptr [esi + 2],dx
	jne Error
	inc esi	; push 2
	inc esi
@@:
	add esi,dword ptr [esi + 2]
	add esi,6		; @LdrpSendDllUnloadedNotifications/LdrpSendDllUnloadedNotifications
	lea ebx,[esi + 40H]
Scan:
	Call VirXasm32
	cmp al,6
	je Check
	cmp al,3
	jne @f
	cmp byte ptr [esi],0C2H	; ret #
	je Error
@@:
	add esi,eax
	cmp esi,ebx
	jb Scan
	jmp Error
Check:
	cmp word ptr [esi],358BH	; mov esi,dword ptr ds:[LdrpDllNotificationList]
	jne @b
	mov ebx,dword ptr [esi + 2]
	mov ecx,pLdrpDllNotificationList
	xor eax,eax
	mov dword ptr [ecx],ebx
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xLdrQueryLdrpDllNotificationList endp

LDR_DLL_NOTIFICATION_DATA struct
ShutdownInProgress	BOOLEAN ?		; LDR_DLL_UNLOADED_FLAG_PROCESS_TERMINATION
FullDllName   		PUNICODE_STRING ?
BaseDllName   		PUNICODE_STRING ?
DllBase			PVOID ?
SizeOfImage		ULONG ?
LDR_DLL_NOTIFICATION_DATA ends
PLDR_DLL_NOTIFICATION_DATA typedef ptr LDR_DLL_NOTIFICATION_DATA

LDR_DLL_NOTIFICATION_RECORD struct
Entry		LIST_ENTRY <>
Handler		PVOID ?
Context		PVOID ?
LDR_DLL_NOTIFICATION_RECORD ends
PLDR_DLL_NOTIFICATION_RECORD typedef ptr LDR_DLL_NOTIFICATION_RECORD

LDR_DLL_NOTIFICATION_REASON_LOADED		equ 1
LDR_DLL_NOTIFICATION_REASON_UNLOADED	equ 2

LDR_DLL_UNLOADED_FLAG_PROCESS_TERMINATION	equ 1	; def. ntldr.h

; +
; Регистрация нотификатора в LdrpDllNotificationList.
; o ListHead:PLDR_DLL_NOTIFICATION_RECORD начало списка(@LdrpDllNotificationList).
; o LdrpLoaderLock захвачена.
;
xLdrRegisterDllNotification proc ListHead:PLDR_DLL_NOTIFICATION_RECORD, ListRecord:PLDR_DLL_NOTIFICATION_RECORD, Handler:PVOID, Context:PVOID, First:BOOLEAN
	push Handler
	mov ecx,ListHead
	push Context	
	cmp First,FALSE
	mov edx,ListRecord
	.if Zero?
	assume eax:PLDR_DLL_NOTIFICATION_RECORD
	assume ecx:PLDR_DLL_NOTIFICATION_RECORD
	assume edx:PLDR_DLL_NOTIFICATION_RECORD
	mov eax,[ecx].Entry.Flink
	mov [edx].Entry.Blink,ecx
	mov [ecx].Entry.Flink,edx
	mov [edx].Entry.Flink,eax
	mov [eax].Entry.Blink,edx
	.else
	mov eax,[ecx].Entry.Blink
	mov [edx].Entry.Flink,ecx
	mov [ecx].Entry.Blink,edx
	mov [edx].Entry.Blink,eax
	mov [eax].Entry.Flink,edx
	.endif
	pop [edx].Context
	pop [edx].Handler
	ret
xLdrRegisterDllNotification endp

; +
; Регистрация нотификатора в LdrpDllNotificationList.
;
xLdrRegisterDllNotificationEx proc uses ebx esi edi ListHead:PLDR_DLL_NOTIFICATION_RECORD, ListRecord:PLDR_DLL_NOTIFICATION_RECORD, Handler:PVOID, Context:PVOID, First:BOOLEAN
Local Entries[5]:PVOID
Local Cookie:ULONG
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor ecx,ecx
	lea edx,Entries
	mov ebx,ListRecord
	mov Entries[0],095DB37F4H	; CRC32("LdrLockLoaderLock")
	mov Entries[4],02CCB252FH	; CRC32("LdrUnlockLoaderLock")
	mov Entries[2*4],0A1D45974H	; CRC32("RtlAllocateHeap")
	mov Entries[3*4],0A1AB46D1H	; CRC32("RtlGetLastNtStatus")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[4*4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	jnz Exit
	.if ListHead == Eax
	invoke xLdrQueryLdrpDllNotificationList, NULL, addr ListHead
	test eax,eax
	jnz Exit
	.endif
	lea ecx,Cookie
	push ecx
	push eax
	push LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED
	Call Entries[0]
	test eax,eax
	mov esi,dword ptr [ebx]
	jnz Exit
	test esi,esi
	mov ecx,fs:[TEB.Peb]
	.if Zero?
	push sizeof(LDR_DLL_NOTIFICATION_RECORD)	; *
	push eax
	push PEB.ProcessHeap[ecx]
	Call Entries[2*4]
	test eax,eax
	jnz @f
	Call Entries[3*4]
	jmp Unlock
@@:
	mov esi,eax
	mov dword ptr [ebx],eax
	.endif
	invoke xLdrRegisterDllNotification, ListHead, Esi, Handler, Context, First
	xor eax,eax
Unlock:
	push eax
	push Cookie
	push LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED
	Call Entries[4]
	pop eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xLdrRegisterDllNotificationEx endp

; +
;
xCompareStringSensitiveInternal proc uses ebx UnicodeString:PUNICODE_STRING, AnsiString:PSTR, StringLength:ULONG
	mov ebx,StringLength
	mov edx,UnicodeString
	lea eax,[ebx*2]
	assume edx:PUNICODE_STRING
	cmp [edx]._Length,ax
	jne Exit
	mov ecx,AnsiString
	mov edx,[edx].Buffer
@@:
	movzx eax,byte ptr [ecx + ebx - 1]
	cmp word ptr [edx + ebx*2 - 2],ax
	jne Exit
	dec ebx
	jnz @b
	xor eax,eax
Exit:
	ret
xCompareStringSensitiveInternal endp

BASE_REGION_SIZE	equ 10000H

; +
; Опредедяет описатель в LdrpKnownDllObjectDirectory.
;
xQueryKnownDllsDirectory proc uses ebx esi edi Directory:PVOID
Local SystemInformation:PVOID, SystemInformationLength:ULONG
Local $Directory[12]:CHAR, ObjectName[sizeof(UNICODE_STRING) + (10*2 + 4)]:BYTE
Local Entries[5]:PVOID
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],0D820A574H	; CRC32("ZwAllocateVirtualMemory")
	mov Entries[4],0F97A25D4H	; CRC32("ZwFreeVirtualMemory")
	mov Entries[2*4],05A91FB11H	; CRC32("ZwQueryObject")
	mov Entries[3*4],0F775FBC7H	; CRC32("ZwQuerySystemInformation")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[4*4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	lea ecx,SystemInformationLength
	jnz Exit
	mov SystemInformationLength,eax
	mov SystemInformation,eax
	push ecx
	push eax
	push eax
	push ObjectAllTypesInformation
	push eax
	Call Entries[2*4]
	cmp eax,STATUS_INFO_LENGTH_MISMATCH
	lea ecx,SystemInformationLength
	lea edx,SystemInformation
	.if !Zero?
; def. 224 bytes.
	mov SystemInformationLength,PAGE_SIZE
	.endif
	push PAGE_READWRITE
	push MEM_COMMIT
	push ecx
	push 0
	push edx
	push NtCurrentProcess
	Call Entries[0]
	test eax,eax
	jnz Exit
	push eax
	push SystemInformationLength
	push SystemInformation
	push ObjectAllTypesInformation
	push eax
	Call Entries[2*4]
	test eax,eax
	mov edi,SystemInformation
	jnz Parse
	mov esi,OBJECT_ALL_TYPES_INFORMATION.NumberOfTypes[edi]
	mov dword ptr $Directory[0],"eriD"
	mov dword ptr $Directory[4],"rotc"
	mov dword ptr $Directory[2*4],"y"
	mov ebx,esi
	add edi,4
	assume edi:POBJECT_TYPE_INFORMATION
@@:
	invoke xCompareStringSensitiveInternal, Edi, addr $Directory, 9
	movzx ecx,[edi].TypeName._Length
	je Parse
	and ecx,NOT(3)
	mov edi,[edi].TypeName.Buffer
	lea edi,[edi + ecx + 4]
	dec esi
	jnz @b
	mov eax,STATUS_UNSUCCESSFUL
Parse:
	push eax
	lea ecx,SystemInformationLength
	lea edx,SystemInformation
	push MEM_RELEASE
	push ecx
	push edx
	push NtCurrentProcess
	Call Entries[4]
	pop eax
	sub ebx,esi	; ObjectTypeNumber
	test eax,eax
	mov esi,BASE_REGION_SIZE
	jnz Exit
	inc ebx
NextRegion:
	mov SystemInformationLength,esi
	mov SystemInformation,NULL
	lea ecx,SystemInformationLength
	lea edx,SystemInformation
	push PAGE_READWRITE
	push MEM_COMMIT
	push ecx
	push 0
	push edx
	push NtCurrentProcess
	Call Entries[0]
	test eax,eax
	jnz Exit
	push eax
	push SystemInformationLength
	push SystemInformation
	push SystemHandleInformation
	Call Entries[3*4]
	test eax,eax
	lea ecx,SystemInformationLength
	lea edx,SystemInformation
	jz ParseInfo
	push eax
	push MEM_RELEASE
	push ecx
	push edx
	push NtCurrentProcess
	Call Entries[4]
	pop eax
	cmp eax,STATUS_INFO_LENGTH_MISMATCH
	jnz Exit
	add esi,BASE_REGION_SIZE
	cmp esi,32*BASE_REGION_SIZE
	jb NextRegion
	jmp Exit
ParseInfo:
	mov esi,SystemInformation
	mov dword ptr $Directory[0],"onK\"
	mov ecx,fs:[TEB.Cid.UniqueProcess]
	mov edi,dword ptr [esi]
	mov dword ptr $Directory[4],"lDnw"
	mov dword ptr $Directory[2*4],"sl"
	add esi,4
NextEntry:
	assume esi:PSYSTEM_HANDLE_INFORMATION
	cmp [esi].ProcessId,ecx
	jne @f
	cmp [esi].ObjectTypeNumber,bl	; def. 2: Directory.
	jne @f
	push ecx
	lea edx,ObjectName
	push NULL
	push sizeof(UNICODE_STRING) + (10*2 + 4)
	movzx ecx,[esi].Handle
	push edx
	push ObjectNameInformation
	push ecx
	Call Entries[2*4]
	test eax,eax
	pop ecx
	jnz @f
	cmp UNICODE_STRING._Length[ObjectName],14H
	jne @f
	push ecx
	invoke xCompareStringSensitiveInternal, addr ObjectName, addr $Directory, 10
	pop ecx
	jne @f
	mov edx,Directory
	movzx ecx,[esi].Handle
	mov dword ptr [edx],ecx
	jmp ParseError
@@:
	add esi,sizeof(SYSTEM_HANDLE_INFORMATION)
	dec edi
	jnz NextEntry
	mov eax,STATUS_NOT_FOUND
ParseError:
	push eax
	lea ecx,SystemInformationLength
	push MEM_RELEASE
	lea edx,SystemInformation
	push ecx
	push edx
	push NtCurrentProcess
	Call Entries[4]
	pop eax
Exit:
	ret
xQueryKnownDllsDirectory endp

HEAP_SIGNATURE	equ 0EEFFEEFFH

; o Сообщение задаём статически, не меняется.
MSG_HEAP_INVALID_SIGNATURE	equ 03BC3320H	; CRC32("Invalid heap signature for heap "), 0x32
MSG_HEAP_INVALID_SIGNATURE_LENGTH	equ 32

DBG_HEAP_DISPATCH_INFORMATION struct
Message					ULONG ?	; MSG_HEAP_INVALID_SIGNATURE
pDbgPrint					PVOID ?
pDbgBreakPoint				PVOID ?
pRtlComputeCrc32			PVOID ?
pRtlpCheckHeapSignature		PVOID ?
pRtlpBreakPointHeap			PVOID ?
fpRtlpBreakPointHeap		PVOID ?	; * (SFC)
pRtlpHeapInvalidBreakPoint	PVOID ?
pRtlpHeapInvalidBadAddress	PVOID ?
fpDbgBreakPoint			PVOID ?	; * (SFC)
fpDbgPrint				PVOID ?	; * (SFC)
DBG_HEAP_DISPATCH_INFORMATION ends
PDBG_HEAP_DISPATCH_INFORMATION typedef ptr DBG_HEAP_DISPATCH_INFORMATION

; +
; Поиск и парсинг RtlpCheckHeapSignature().
;
xLdrParseRtlpCheckHeapSignature proc uses ebx esi edi ParseInfo:PDBG_HEAP_DISPATCH_INFORMATION
Local Env:DBG_HEAP_DISPATCH_INFORMATION
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	xor ecx,ecx
	lea edx,Env
	mov dword ptr [Env],051B1009EH	; CRC32("RtlLockHeap")
	mov [Env].pDbgPrint,0D318D52FH	; CRC32("DbgPrint")
	mov [Env].pDbgBreakPoint,0EC63CD77H	; CRC32("DbgBreakPoint")
	mov [Env].pRtlComputeCrc32,0CACBBC36H	; CRC32("RtlComputeCrc32")
	mov eax,LDR_QUERY_ENTRIES
	mov Env.pRtlpCheckHeapSignature,ecx
	push edx
	mov Env.fpDbgPrint,ecx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	mov esi,dword ptr [Env]	; @RtlLockHeap
	jnz Exit
	lea ebx,[esi + 60H]
Scan1:
	Call VirXasm32
	cmp al,5
	je Check1
	cmp al,3
	jne @f
	cmp byte ptr [esi],0C2H	; ret #
	je Error
@@:
	add esi,eax
	cmp esi,ebx
	jb Scan1
	jmp Error
Check1:
	cmp byte ptr [esi],OP_CALL_NEAR
	jne @b
	add esi,dword ptr [esi + 1]
	add esi,5		; @RtlpCheckHeapSignature
; Validate
	mov Env.Message,MSG_HEAP_INVALID_SIGNATURE
	lea ebx,[esi + 70H]
	mov [Env].pRtlpCheckHeapSignature,esi
Scan2:
	Call VirXasm32
	cmp al,6
	je Check2
	cmp al,3
	jne @f
	cmp byte ptr [esi],0C2H	; ret #
	je Error
@@:
	add esi,eax
	cmp esi,ebx
	jb Scan2
	jmp Error
Check2:
	cmp word ptr [esi],3F81H	; cmp dword ptr ds:[edi],EEFFEEFF
	jne @b
	cmp dword ptr [esi + 2],HEAP_SIGNATURE
	jne @b
	cmp word ptr [esi + 6],850FH	; jnz XXXX
	jne Error
	add esi,dword ptr [esi + 8]
	add esi,12
	lea ebx,[esi + 80H]
Scan3:
	Call VirXasm32
	cmp al,5
	je Check3
	cmp al,2
	jne @f
	cmp word ptr [esi],0C032H	; xor al,al
	je Error
@@:
	add esi,eax
Next3:
	cmp esi,ebx
	jb Scan3
	jmp Error
Check3:
	cmp byte ptr [esi],OP_CALL_NEAR
	mov edi,dword ptr [esi + 1]
	jne @b
	lea edi,[esi + edi + 5]
	cmp Env.pDbgPrint,edi
	jne @f
; @DbgPrint
	cmp byte ptr [esi - 5],OP_PUSH32
	jne @b
	push MSG_HEAP_INVALID_SIGNATURE_LENGTH
	push dword ptr [esi - 4]	; "Invalid heap signature for heap "
	push 0	; Partial crc.
	add esi,eax
	Call Env.pRtlComputeCrc32
	cmp eax,MSG_HEAP_INVALID_SIGNATURE
	jne Next3
	mov Env.fpDbgPrint,esi
	jmp Next3	
@@:
; @RtlpBreakPointHeap
	add esi,5
	cmp Env.fpDbgPrint,0
	mov Env.pRtlpBreakPointHeap,edi
	je Error
	cmp word ptr [esi],0C032H	; xor al,al
	jne Error
	mov Env.fpRtlpBreakPointHeap,esi
	lea ebx,[edi + 38H]
	mov esi,edi
Scan4:
	Call VirXasm32
	cmp al,7
	je Check4
	cmp al,3
	jne @f
	cmp word ptr [esi],0C2H	; ret #
	je Error
@@:
	add esi,eax
	cmp esi,ebx
	jb Scan4
	jmp Error
Check4:
	cmp word ptr [esi],05C6H	; mov byte ptr ds:[RtlpHeapInvalidBreakPoint],1
	jne @b
	cmp word ptr [esi + 6],0A301H	; mov dword ptr ds:[RtlpHeapInvalidBadAddress],eax
	jne @b
	cmp byte ptr [esi + 12],OP_CALL_NEAR
	jne @b
	cmp word ptr [esi + 17],05C6H	; mov byte ptr ds:[RtlpHeapInvalidBreakPoint],0
	jne @b
	mov ecx,dword ptr [esi + 13]
	cmp byte ptr [esi + 23],0H
	lea ecx,[ecx + esi + 17]
	jne @b
	cmp Env.pDbgBreakPoint,ecx
	jne Error
	mov ecx,dword ptr [esi + 2]	; @RtlpHeapInvalidBreakPoint
	mov edx,dword ptr [esi + 8]	; @RtlpHeapInvalidBadAddress
	add esi,17
	cld
	mov Env.pRtlpHeapInvalidBreakPoint,ecx
	mov Env.fpDbgBreakPoint,esi
	mov edi,ParseInfo
	mov ecx,sizeof(DBG_HEAP_DISPATCH_INFORMATION)/4
	lea esi,Env
	mov Env.pRtlpHeapInvalidBadAddress,edx
	xor eax,eax
	rep movsd
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
xLdrParseRtlpCheckHeapSignature endp

INVALID_HEAP_SIGNATURE	equ 0ECBFDACBH

; def. Heap.h
HsSignature	equ 8H	; HEAP.Signature

INVALIDATE_HEAP_SIGNATURE macro
	mov ecx,fs:[TEB.Peb]
	mov eax,INVALID_HEAP_SIGNATURE
	mov ecx,PEB.ProcessHeap[ecx]
	lock xchg dword ptr [ecx + HsSignature],eax
endm

VALIDATE_HEAP_SIGNATURE macro
	mov ecx,fs:[TEB.Peb]
	mov eax,HEAP_SIGNATURE
	mov ecx,PEB.ProcessHeap[ecx]
	lock xchg dword ptr [ecx + HsSignature],eax
endm

CHECK_HEAP_SIGNATURE macro
	mov ecx,fs:[TEB.Peb]
	mov eax,INVALID_HEAP_SIGNATURE
	mov ecx,PEB.ProcessHeap[ecx]
	lock cmpxchg dword ptr [ecx + HsSignature],eax
endm

HsForceFlags	equ 10H	; HEAP.ForceFlags

HEAP_FLAG_PAGE_ALLOCS			equ 01000000H
HEAP_SKIP_VALIDATION_CHECKS		equ 10000000H
HEAP_VALIDATE_ALL_ENABLED		equ 20000000H
HEAP_VALIDATE_PARAMETERS_ENABLED	equ 40000000H

ENABLE_HEAP_VALIDATION macro
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.ProcessHeap[eax]
	and dword ptr [eax + HsForceFlags],NOT(HEAP_FLAG_PAGE_ALLOCS or HEAP_SKIP_VALIDATION_CHECKS)
	or dword ptr [eax + HsForceFlags],(HEAP_VALIDATE_ALL_ENABLED or HEAP_VALIDATE_PARAMETERS_ENABLED)
endm

ENABLE_DEBUG_EXCEPTIONS macro
	mov eax,fs:[TEB.Peb]
	mov PEB.BeingDebugged[eax],TRUE
endm

STACK_FRAME struct
rEbp		PVOID ?	; Next frame, PSTACK_FRAME
rEip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

DBG_PRINTEXCEPTION_C	equ 40010006H

; +
;
xHmgrDispatchException proc uses ebx esi edi Env:PDBG_HEAP_DISPATCH_INFORMATION, ExceptionPointers:PEXCEPTION_POINTERS, ContinueHandler:PVOID, Tls:PVOID
	mov ebx,ExceptionPointers
	mov esi,EXCEPTION_POINTERS.ExceptionRecord[ebx]
	assume esi:PEXCEPTION_RECORD
	mov edi,EXCEPTION_POINTERS.ContextRecord[ebx]
	assume edi:PCONTEXT
	cmp [esi].ExceptionFlags,NULL
	mov ebx,Env
	jne Chain
	CHECK_HEAP_SIGNATURE
	jne Chain
	assume ebx:PDBG_HEAP_DISPATCH_INFORMATION
	cmp [esi].ExceptionCode,DBG_PRINTEXCEPTION_C
	jne IsBreak
	cmp [esi].NumberParameters,2
	jne Chain
	cmp [esi].ExceptionInformation[0],MSG_HEAP_INVALID_SIGNATURE_LENGTH
	jna Chain
	push MSG_HEAP_INVALID_SIGNATURE_LENGTH
	push [esi].ExceptionInformation[4]
	push 0	; Partial crc.
	Call [ebx].pRtlComputeCrc32
	test eax,eax
	jz Chain
	cmp [ebx].Message,eax	; MSG_HEAP_INVALID_SIGNATURE
	jne Chain
; SFC
	mov esi,[edi].regEbp
	mov ecx,4
	mov eax,[ebx].fpDbgPrint
	assume esi:PSTACK_FRAME
; * Не проверяем вхождение адреса возврата в диапазон модуля.
@@:
	test esi,esi
	jz Chain
	cmp [esi].rEip,eax
	mov esi,[esi].rEbp
	je @f	; Don't use Loopnz.
	dec ecx
	jnz @b
	jmp Chain 
@@:
	test esi,esi
	jz Chain
	; ..
	jmp Load
IsBreak:
	assume esi:PEXCEPTION_RECORD
	cmp [esi].ExceptionCode,STATUS_BREAKPOINT
	mov eax,[ebx].pRtlpHeapInvalidBreakPoint
	jne Chain
	cmp byte ptr [eax],1
	mov ecx,[esi].ExceptionAddress
	jne Chain
	mov eax,[edi].regEsp
	cmp [ebx].pDbgBreakPoint,ecx	; ExceptionAddress = Eip
	mov eax,dword ptr [eax]
	jne Chain
	mov edx,[ebx].fpRtlpBreakPointHeap
	cmp [ebx].fpDbgBreakPoint,eax
	mov ecx,[edi].regEbp
	jne Chain
	test ecx,ecx
	jz Chain
	assume ecx:PSTACK_FRAME
	cmp [ecx].rEip,edx
	jne Chain
	mov ecx,[ecx].rEbp
	mov eax,ContinueHandler
	test ecx,ecx
	mov edx,Tls
	jz Chain
	xchg [ecx].rEip,eax
	inc [edi].regEip
	mov dword ptr [edx],eax
Load:
	mov eax,EXCEPTION_CONTINUE_EXECUTION
	jmp Exit
Chain:
	xor eax,eax
Exit:
	ret
xHmgrDispatchException endp

PROCESS_HANDLE_TRACING_ENABLE struct
Flags		ULONG ?
PROCESS_HANDLE_TRACING_ENABLE ends

PROCESS_HANDLE_TRACING_MAX_STACKS	equ 16

HANDLE_TRACE_DB_OPEN	equ 1
HANDLE_TRACE_DB_CLOSE	equ 2
HANDLE_TRACE_DB_BADREF	equ 3

PROCESS_HANDLE_TRACING_ENTRY struct
Handle		HANDLE ?
ClientId		CLIENT_ID <>
_Type		ULONG ?	; HANDLE_TRACE_DB_*
Stacks		PVOID PROCESS_HANDLE_TRACING_MAX_STACKS DUP (?)
PROCESS_HANDLE_TRACING_ENTRY ends

PROCESS_HANDLE_TRACING_QUERY struct
Handle		HANDLE ?
TotalTraces	ULONG ?
HandleTrace	PROCESS_HANDLE_TRACING_ENTRY 1 DUP (<>)
PROCESS_HANDLE_TRACING_QUERY ends

ProcessHandleTracing	equ 32

; +
;
xEnableHandleTracing proc
Local Tracing:PROCESS_HANDLE_TRACING_ENABLE
Local Entries[2]:PVOID
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],04885FB3EH	; CRC32("ZwSetInformationProcess")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	lea ecx,Tracing
	.if Zero?
	mov Tracing,eax
	push sizeof(PROCESS_HANDLE_TRACING_ENABLE)
	push ecx
	push ProcessHandleTracing
	push NtCurrentProcess
	Call Entries[0]
	.endif
	ret
xEnableHandleTracing endp