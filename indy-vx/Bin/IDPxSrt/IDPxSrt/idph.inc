IDP_INITIALIZE_ENGINE	equ 0
; typedef NTSTATUS (*PENTRY)(
;	);

IDP_ADD_REFERENCE		equ 1
; typedef NTSTATUS (*PENTRY)(
;    IN OUT PVOID *Reference
;	IN ULONG SpaceSize
;    );

; typedef LONG (*PVECTORED_EXCEPTION_HANDLER)(
;    IN OUT PEXCEPTION_POINTERS *ExceptionInformation
;    );

IDP_ADD_VEH			equ 2
; typedef PVOID (*PENTRY)(
;    IN ULONG First,
;    IN PVECTORED_EXCEPTION_HANDLER Handler
;    );

IDP_REMOVE_VEH			equ 3
; typedef ULONG (*PENTRY)(
;	IN PVOID Handle
;	);

IDP_QUERY_ENTRY		equ 4
;typedef NTSTATUS (*PENTRY)(
;	IN PVOID ImageBase OPTIONAL,
;	IN PVOID HashOrFunctionName,
;	IN PCOMPUTE_HASH_ROUTINE HashRoutine OPTIONAL,
;	IN ULONG PartialCrc,
;	OUT *PVOID Entry
;	);

;typedef ULONG (*PCOMPUTE_HASH_ROUTINE)(
;	IN ULONG UserParameter,
;	IN PVOID Buffer,
;	IN ULONG Length
;	);

IDP_QUERY_ENTRIES		equ 5
; typedef NTSTATUS (*PENTRY)(
;	IN PVOID ImageBase OPTIONAL,
;	IN ULONG PartialCrc,
;	IN PULONG Crc32List,
;	OUT *PVOID EntriesList
;	);

; —мещение в странице TEB до переменной, содержащей 
; указатель на структуру, описывающую адрес к которому 
; произошло обращение.
;
SEGMENT_ENTRY struct
SegmentBase	PVOID ?
SegmentLimit	ULONG ?
SegmentAddress	PVOID ?	; јдрес области пам€ти.
Reference		PVOID ?	; јдрес переменной, ссылающейс€ на область пам€ти.
SEGMENT_ENTRY ends
PSEGMENT_ENTRY typedef ptr SEGMENT_ENTRY

IDP_SEGMENT_ENTRY_OFFSET	equ (PAGE_SIZE - 4)

IDP_BREAKPOINT		equ 80FE0001H
IDP_SINGLE_STEP	equ 80FE0002H

FACILITY_IDP_ENGINE	equ 0FEH

STATUS_SCALE_FACILITY	equ 16
STATUS_SCALE_R			equ 28
STATUS_SCALE_C			equ 29
STATUS_SCALE_SEVERITY	equ 30

STATUS_SEVERITY_WARNING	equ 2

IDP_BREAKPOINT		equ ((STATUS_SEVERITY_WARNING shl STATUS_SCALE_SEVERITY) or (FACILITY_IDP_ENGINE shl STATUS_SCALE_FACILITY) or 0001H)	; Code = 1, 0x80FE0001
IDP_SINGLE_STEP	equ ((STATUS_SEVERITY_WARNING shl STATUS_SCALE_SEVERITY) or (FACILITY_IDP_ENGINE shl STATUS_SCALE_FACILITY) or 0002H)	; Code = 2, 0x80FE0002

THREAD_STATE struct
rEFlags	DWORD ?
Entry	PSEGMENT_ENTRY ?
THREAD_STATE ends
PTHREAD_STATE typedef ptr THREAD_STATE