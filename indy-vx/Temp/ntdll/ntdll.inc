include windows.inc
include ntstatus.inc
; include ntimage.inc
; include cpu.inc

PNTSTATUS typedef ptr NTSTATUS
; Thread affinity
KAFFINITY		typedef	DWORD
PKAFFINITY	typedef PTR KAFFINITY
; Thread priority
KPRIORITY		typedef SDWORD

POOL_TYPE	typedef ULONG

; Pointer to a SECURITY_DESCRIPTOR  opaque data type.
PSECURITY_DESCRIPTOR	typedef	PTR	; winnt

ACCESS_MASK	typedef DWORD
PACCESS_MASK	typedef PTR ACCESS_MASK

NT_CURRENT_PROCESS		equ -1
NT_CURRENT_THREAD		equ -2
NtCurrentProcess		equ -1
NtCurrentThread		equ -2

OB_FLAG_CREATE_INFO		equ 01h	;Object header has OBJECT_CREATE_INFO */
OB_FLAG_KERNEL_MODE		equ 02h	;Created by kernel */
OB_FLAG_CREATOR_INFO	equ 04h	;Object header has OBJECT_CREATOR_INFO */
OB_FLAG_EXCLUSIVE		equ 08h	;OBJ_EXCLUSIVE */
OB_FLAG_PERMAMENT		equ 10h	;OBJ_PERMAMENT */
OB_FLAG_SECURITY		equ 20h	;Object header has SecurityDescriptor != NULL */
OB_FLAG_SINGLE_PROCESS	equ 40h	;absent HandleDBList */

OB_SECURITY_CHARGE		equ 00000800h

UNICODE_STRING struct 
_Length		USHORT	?
MaximumLength	USHORT	?
Buffer		PWSTR   	?
UNICODE_STRING ends
PUNICODE_STRING typedef ptr UNICODE_STRING

PCUNICODE_STRING	typedef PUNICODE_STRING

STRING struct
_Length 		USHORT ?
MaximumLength	USHORT ?
Buffer    	PCHAR ?
STRING ends
PSTRING typedef ptr STRING

ANSI_STRING struct
_Length 		USHORT ?
MaximumLength	USHORT ?
Buffer    	PSTR ?
ANSI_STRING ends
PANSI_STRING typedef PTR ANSI_STRING

LARGE_STRING struct
_Length		ULONG ?
MaximumLength	ULONG ?
Buffer		PWSTR ?
LARGE_STRING ends
PLARGE_STRING typedef ptr LARGE_STRING

RTL_BITMAP struct
SizeOfBitMap	DWORD ?	;
Buffer		PDWORD ?	;
RTL_BITMAP ends
PRTL_BITMAP typedef ptr RTL_BITMAP

SYSTEM_STRINGS struct
SystemRoot	UNICODE_STRING <>
System32Root	UNICODE_STRING <>
BaseNamedObjects	UNICODE_STRING <>
SYSTEM_STRINGS ends
PSYSTEM_STRINGS typedef ptr SYSTEM_STRINGS 

TEXT_INFO struct
Reserved		PVOID ?
SystemStrings	PSYSTEM_STRINGS ?
TEXT_INFO ends
PTEXT_INFO typedef ptr TEXT_INFO 

PEB_FREE_BLOCK STRUCT	; sizeof = 8
Next		PVOID	?	; PPEB_FREE_BLOCK
_Size	DWORD	?	; original name Size
PEB_FREE_BLOCK ENDS
PPEB_FREE_BLOCK typedef ptr PEB_FREE_BLOCK

PEB_LDR_DATA struct
lLength						ULONG ?		;+0
Initialized					BOOLEAN ?		;+4
SsHandle						PVOID ?		;+8h
InLoadOrderModuleList			LIST_ENTRY <>	;+0Ch	ref. to PLDR_DATA_TABLE_ENTRY->InLoadOrderModuleList
InMemoryOrderModuleList			LIST_ENTRY <>	;+14h	ref. to PLDR_DATA_TABLE_ENTRY->InMemoryOrderModuleList
InInitializationOrderModuleList	LIST_ENTRY <>	;+1Ch	ref. to PLDR_DATA_TABLE_ENTRY->InInitializationOrderModuleList
EntryInProgress				PVOID ?
PEB_LDR_DATA ends
PPEB_LDR_DATA typedef ptr PEB_LDR_DATA

; Private flags for loader data table entries
LDRP_STATIC_LINK				equ 00000002H
LDRP_IMAGE_DLL					equ 00000004H
LDRP_LOAD_IN_PROGRESS			equ 00001000H
LDRP_UNLOAD_IN_PROGRESS			equ 00002000H
LDRP_ENTRY_PROCESSED			equ 00004000H
LDRP_ENTRY_INSERTED				equ 00008000H
LDRP_CURRENT_LOAD				equ 00010000H
LDRP_FAILED_BUILTIN_LOAD			equ 00020000H
LDRP_DONT_CALL_FOR_THREADS		equ 00040000H
LDRP_PROCESS_ATTACH_CALLED		equ 00080000H
LDRP_DEBUG_SYMBOLS_LOADED		equ 00100000H
LDRP_IMAGE_NOT_AT_BASE			equ 00200000H
LDRP_COR_IMAGE					equ 00400000H
LDRP_COR_OWNS_UNMAP				equ 00800000H
LDRP_SYSTEM_MAPPED				equ 01000000H
LDRP_IMAGE_VERIFYING			equ 02000000H
LDRP_DRIVER_DEPENDENT_DLL		equ 04000000H
LDRP_ENTRY_NATIVE				equ 08000000H
LDRP_REDIRECTED				equ 10000000H
LDRP_NON_PAGED_DEBUG_INFO		equ 20000000H
LDRP_MM_LOADED					equ 40000000H
LDRP_COMPAT_DATABASE_PROCESSED	equ 80000000H

LDR_WX86_IGNORE_MACHINETYPE		equ 0400000H

LDR_DATA_TABLE_ENTRY struct
InLoadOrderModuleList    	LIST_ENTRY <>		;+0
InMemoryOrderModuleList    	LIST_ENTRY <>		;+8
InInitializationOrderModuleList	LIST_ENTRY <>	;+16(10h)
DllBase			PVOID ?	;+24(18h)
EntryPoint		PVOID ?	;+28(1Ch)
SizeOfImage		ULONG ?	;+32(20h)	in bytes
FullDllName    	UNICODE_STRING <>	;+36(24h)
BaseDllName    	UNICODE_STRING <>	;+44(2Ch)
Flags			ULONG ?	;+52(34h)	LDR_*
LoadCount			USHORT ?	;+56(38h)
TlsIndex			USHORT ?	;+58(3Ah)
HashLinks    		LIST_ENTRY <>	;+60(3Ch)
SectionPointer		PVOID ?	;+68(44h)
CheckSum			ULONG ? 	;+72(48h)
TimeDateStamp		ULONG ?	;+76(4Ch)
LoadedImports		PVOID ?
EntryPointActivationContext	PVOID ?
LDR_DATA_TABLE_ENTRY ends
PLDR_DATA_TABLE_ENTRY typedef ptr LDR_DATA_TABLE_ENTRY

CLIENT_ID STRUCT	; sizeof = 8 
UniqueProcess	HANDLE	?
UniqueThread	HANDLE	?
CLIENT_ID ENDS
PCLIENT_ID typedef PTR CLIENT_ID

OBJECT_ATTRIBUTES struct
uLength				ULONG	?
hRootDirectory			HANDLE	?
pObjectName			PUNICODE_STRING	?
uAttributes			ULONG	?
pSecurityDescriptor		PVOID	?
pSecurityQualityOfService	PVOID	?
OBJECT_ATTRIBUTES ends
POBJECT_ATTRIBUTES typedef ptr OBJECT_ATTRIBUTES

OBJ_INHERIT 		equ 00000002h
OBJ_PERMANENT 		equ 00000010h
OBJ_EXCLUSIVE 		equ 00000020h
OBJ_CASE_INSENSITIVE 	equ 00000040h
OBJ_OPENIF 		equ 00000080h
OBJ_OPENLINK 		equ 00000100h
OBJ_KERNEL_HANDLE 	equ 00000200h
OBJ_VALID_ATTRIBUTES	equ 000001F2h

CURDIR STRUCT		; sizeof = 0Ch
DosPath		UNICODE_STRING <>	; 0
Handle		PVOID ?	; 8
CURDIR ENDS
PCURDIR typedef ptr CURDIR

RTL_DRIVE_LETTER_CURDIR STRUCT	; sizeof = 10h
Flags		WORD		?	; 00h
_Length		WORD		?	; 02h original name Length
TimeStamp		DWORD		?	; 04h
DosPath		STRING		<>	; 08h
RTL_DRIVE_LETTER_CURDIR ENDS
PRTL_DRIVE_LETTER_CURDIR typedef ptr PTR RTL_DRIVE_LETTER_CURDIR

RTL_USER_PROCESS_PARAMETERS struct ;sizeof = 290h
MaximumLength    	ULONG 		?			;000h
_Length    		ULONG 		?			;004h 
Flags    			ULONG 		?			;008h	; PROCESS_PARAMETERS_NORMALIZED
DebugFlags    		ULONG 		?			;00Ch
ConsoleHandle   	HANDLE 		?			;010h
ConsoleFlags   	ULONG 		?			;014h
StandardInput    	HANDLE 		?			;018h
StandardOutput    	HANDLE 		?			;01Ch
StandardError    	HANDLE 		?			;020h
CurrentDirectory    CURDIR 		<>			;024h
DllPath    		UNICODE_STRING 	<>		;030h
ImagePathName    	UNICODE_STRING 	<>		;038h
CommandLine    	UNICODE_STRING 	<>		;040h
Environment    	PWSTR 		?			;048h
StartingX    		ULONG 		?			;04Ch
StartingY    		ULONG 		?			;050h
CountX    		ULONG 		?			;054h
CountY    		ULONG 		?			;058h
CountCharsX    	ULONG 		?			;05Ch
CountCharsY    	ULONG 		?			;060h
FillAttribute    	ULONG 		?			;064h
WindowFlags    	ULONG 		?			;068h
ShowWindowFlags    	ULONG 		?			;06Ch
WindowTitle    	UNICODE_STRING 	<>		;070h
Desktop    		UNICODE_STRING 	<>		;078h
ShellInfo    		UNICODE_STRING 	<>		;080h
RuntimeInfo    	UNICODE_STRING 	<>		;088h
CurrentDirectores	RTL_DRIVE_LETTER_CURDIR 32h DUP (<>)	;090h
RTL_USER_PROCESS_PARAMETERS ends
PRTL_USER_PROCESS_PARAMETERS typedef ptr RTL_USER_PROCESS_PARAMETERS

;Thread Information Block
NT_TIB STRUCT				; sizeof = 1Ch
	ExceptionList			PVOID	?	; PTR EXCEPTION_REGISTRATION_RECORD
	StackBase				PVOID	?	; 04h
	StackLimit			PVOID	?	; 08h
	SubSystemTib			PVOID	?	; 0Ch
	union
		FiberData			PVOID	?	; 10h
		Version			DWORD	?	; 10h
	ends
	ArbitraryUserPointer	PVOID	?	; 14h
	Self					PVOID	?	; 18h PTR NT_TIB
NT_TIB ENDS
PNT_TIB typedef PTR NT_TIB

GDI_TEB_BATCH struct
_Offset	ULONG ?
_HDC		ULONG ?
Buffer	ULONG 133h DUP (?)	;136h
GDI_TEB_BATCH ends
PGDI_TEB_BATCH typedef PTR GDI_TEB_BATCH

RTL_ACTIVATION_CONTEXT_STACK_FRAME struct
Previous    		DWORD ?	;struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ;
ActivationContext	DWORD ?	;struct _ACTIVATION_CONTEXT*                 ;4
Flags			ULONG ?                                       		;8
RTL_ACTIVATION_CONTEXT_STACK_FRAME ends
PRTL_ACTIVATION_CONTEXT_STACK_FRAME typedef PTR RTL_ACTIVATION_CONTEXT_STACK_FRAME

ACTIVATION_CONTEXT_STACK struct
Flags		ULONG ?
NextCookieSequenceNumber	ULONG ?
ActiveFrame	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ?
FrameListCache	LIST_ENTRY <>
ACTIVATION_CONTEXT_STACK ends
PACTIVATION_CONTEXT_STACK typedef PTR ACTIVATION_CONTEXT_STACK

Wx86ThreadState struct
CallBx86Eip		PULONG ?
DeallocationCpu	PVOID ?
UseKnownWx86Dll	UCHAR ?	;8
OleStubInvoked		UCHAR ?	;9
Wx86ThreadState ends
PWx86ThreadState typedef PTR PWx86ThreadState

TEB_ACTIVE_FRAME_CONTEXT struct
Flags		ULONG ?
FrameName		PCHAR ?
TEB_ACTIVE_FRAME_CONTEXT ends
PTEB_ACTIVE_FRAME_CONTEXT typedef PTR TEB_ACTIVE_FRAME_CONTEXT

TEB_ACTIVE_FRAME struct
Flags	ULONG ?
;Previous	DWORD ?
Context	PTEB_ACTIVE_FRAME_CONTEXT ?
TEB_ACTIVE_FRAME ends
PTEB_ACTIVE_FRAME typedef PTR TEB_ACTIVE_FRAME

RTL_CRITICAL_SECTION_DEBUG struct
_Type			WORD ?
CreatorBackTraceIndex	WORD ?
CriticalSection	PVOID ?	; RTL_CRITICAL_SECTION ?
ProcessLocksList    LIST_ENTRY <>
EntryCount		DWORD ?
ContentionCount	DWORD ?
Spare			DWORD 2 DUP (?)
RTL_CRITICAL_SECTION_DEBUG ends
PRTL_CRITICAL_SECTION_DEBUG typedef ptr RTL_CRITICAL_SECTION_DEBUG

RTL_CRITICAL_SECTION STRUCT
DebugInfo       PRTL_CRITICAL_SECTION_DEBUG ?
LockCount       LONG ?
RecursionCount  LONG ?
OwningThread    HANDLE ?	;from the thread's ClientId->UniqueThread
LockSemaphore   HANDLE ?
SpinCount       ULONG ?	;force size on 64-bit systems when packed
RTL_CRITICAL_SECTION ENDS
PRTL_CRITICAL_SECTION typedef PTR RTL_CRITICAL_SECTION

RTL_CRITSECT_TYPE	equ 0
RTL_RESOURCE_TYPE	equ 1   
;::::::::::::::::::::::::::::::::::::::WinXP::::::::::::::::::::::::::::::::::::::::::::::::::::::::
;Process Environment Block (PEB). Initialize:+
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
;PEB_BITS RECORD \
;	SpareBits:30,		; bits 2-31
;	ExecuteOptions:2		; bits 0-1
PEB struct
InheritedAddressSpace		UCHAR ?				;0000h
ReadImageFileExecOptions		UCHAR ?				;0001h
BeingDebugged				UCHAR ?				;0002h
b003						BYTE ?				;0003h
Mutant					PVOID ?				;0004h	+
ImageBaseAddress			PVOID ?				;0008h	+
Ldr						PPEB_LDR_DATA ?		;000Ch
ProcessParameters			PRTL_USER_PROCESS_PARAMETERS ?	;0010h	+
SubSystemData				PVOID ?				;0014h  
ProcessHeap				PVOID ?				;0018h
FastPebLock				PRTL_CRITICAL_SECTION ?	;001Ch			
FastPebLockRoutine			PVOID ?				;0020h	PPEBLOCKROUTINE	;RtlEnterCriticalSection
FastPebUnlockRoutine		PVOID ?				;0024h	PPEBLOCKROUTINE	;RtlLeaveCriticalSection
EnvironmentUpdateCount		ULONG ?				;0028h
KernelCallbackTable			PVOID ?				;002Ch
 EventLogSection			PVOID ?				;0030h
 EventLog					PVOID ?				;0034h
 ;*SystemReserved			DWORD	1 dup(?)		;0030h
 ;*PebBits				PEB_BITS	<>			;0034h
FreeList					PPEB_FREE_BLOCK ?		;0038h
TlsExpansionCounter			ULONG ?				;003Ch
TlsBitmap					PRTL_BITMAP ?			;0040h
TlsBitmapData				ULONG 2h DUP (?)		;0044h
ReadOnlySharedMemoryBase		PVOID ?				;004Ch
ReadOnlySharedMemoryHeap		PVOID ?				;0050h
ReadOnlyStaticServerData		PTEXT_INFO ?			;0054h
InitAnsiCodePageData		PVOID ?				;0058h	+
InitOemCodePageData			PVOID ?				;005Ch	+
InitUnicodeCaseTableData		PVOID ?				;0060h	+
KeNumberProcessors			ULONG ?				;0064h	+
NtGlobalFlag				ULONG ?				;0068h	+
d6C						DWORD ?				;006Ch
MmCriticalSectionTimeout		LONG64 ?				;0070h	+
MmHeapSegmentReserve		ULONG ?				;0078h	+
MmHeapSegmentCommit			ULONG ?				;007Ch	+
MmHeapDeCommitTotalFreeThreshold	ULONG ?			;0080h	+
MmHeapDeCommitFreeBlockThreshold	ULONG ?			;0084h	+
NumberOfHeaps				ULONG ?				;0088h
AvailableHeaps				ULONG ?				;008Ch	MaximumNumberOfHeaps	+
ProcessHeapsListBuffer		PHANDLE ?				;0090h	+
GdiSharedHandleTable		PVOID ?				;0094h
ProcessStarterHelper		PVOID ?				;0098h
GdiDCAttributeList			PVOID ?				;009Ch	; [Win32k!gInitialBatchCount], загрузка в GdiProcessCallout().
LoaderLock				PRTL_CRITICAL_SECTION ?	;00A0h
NtMajorVersion				ULONG ?				;00A4h	+
NtMinorVersion				ULONG ?				;00A8h	+
NtBuildNumber				USHORT ?				;00ACh	+
NtCSDVersion				USHORT ?				;00AEh	+
PlatformId				ULONG ?				;00B0h	+
Subsystem					ULONG ?				;00B4h	ImageSubsystem	+
MajorSubsystemVersion		ULONG ?				;00B8h	ImageSubsystemMajorVersion	+
MinorSubsystemVersion		ULONG ?				;00BCh	ImageSubsystemMinorVersion	+
AffinityMask				ULONG ?				;00C0h	*KAFFINITY	ImageProcessAffinityMask
GdiHandleBuffer			ULONG 22h DUP (?) 		;00C4h
PostProcessInitRoutine		ULONG ?				;014Ch
TlsExpansionBitmap			ULONG ?				;0150h
TlsExpansionBitmapBits		UCHAR 80h DUP (?)		;0154h
SessionId					ULONG ?				;01D4h
AppCompatFlags				LONG64 <>				;01D8h
AppCompatFlagsUser			LONG64 <>				;01E0h
pShimData					PVOID ?				;01E8h
AppCompatInfo				PVOID ?				;01ECh
CSDVersion				UNICODE_STRING <>		;01F0h	UNICODE "Service Pack 2"
ActivationContextData		PVOID ?				;01F8h	PTR ACTIVATION_CONTEXT_DATA	+
ProcessAssemblyStorageMap	PVOID ?				;01FCh	PTR ASSEMBLY_STORAGE_MAP
SystemDefaultActivationContextData	PVOID ?			;0200h	PTR ACTIVATION_CONTEXT_DATA	+
SystemAssemblyStorageMap		PVOID ?				;0204h	PTR ASSEMBLY_STORAGE_MAP
MinimumStackCommit			DWORD ?				;0208h
						DWORD ?				;020Ch padding	
PEB ends
PPEB typedef ptr PEB
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Thread Environment Block (TEB)
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
TEB struct 
Tib					NT_TIB <>			;00h
EnvironmentPointer		PVOID ?			;1Ch
Cid					CLIENT_ID <>		;20h
RpcHandle				PVOID ?			;28h		[ActiveRpcInfo]
ThreadLocalStorage		PVOID ?			;2Ch
Peb					PPEB ?			;30h
LastErrorValue			ULONG ?			;34h
CountOfOwnedCriticalSections	ULONG ?		;38h
CsrClientThread		PVOID ?			;3Ch
 Win32ThreadInfo_		PVOID ?			;40h		[struct _W32THREAD* Win32ThreadInfo]   
 Win32ClientInfo_		ULONG 1Fh DUP (?)	;44h		[ULONG User32Reserved[26] ULONG UserReserved[5]]
WOW32Reserved			PVOID ?			;C0h
CurrentLocale			ULONG ?			;C4h		[LCID CurrentLocale]
FpSoftwareStatusRegister	ULONG ?			;C8h
SystemReserved1		PVOID 36h DUP (?)	;CCh
ExceptionCode			LONG ?			;1A4h
ActivationContextStack   ACTIVATION_CONTEXT_STACK <> 	;1A8h
SpareBytes1  			UCHAR 18h dup (?)	;1BCh
GdiTebBatch  			GDI_TEB_BATCH <>	;1D4h
gdiRgn				ULONG ?			;6A8h
gdiPen				ULONG ?			;6ACh
gdiBrush				ULONG ?			;6B0h
RealClientId			CLIENT_ID <>		;6B4h
GdiCachedProcessHandle	PVOID ?			;6BCh
GdiClientPID			ULONG ?			;6C0h
GdiClientTID			ULONG ?			;6C4h
GdiThreadLocaleInfo		PVOID ?			;6C8h
Win32ClientInfo   		PVOID 3Eh dup (?)	;6CCh
glDispatchTable  		PVOID 0E9h dup (?)	;7C4h
glReserved1   			ULONG 1Dh dup (?)	;B68h
glReserved2			PVOID ?			;BDCh
glSectionInfo			PVOID ?			;BE0h
glSection				PVOID ?			;BE4h
glTable				PVOID ?			;BE8h
glCurrentRC			PVOID ?			;BECh
glContext				PVOID ?			;BF0h
LastStatusValue		NTSTATUS ?		;BF4h
StaticUnicodeString		UNICODE_STRING <>	;BF8h
StaticUnicodeBuffer		WCHAR 106h DUP (?)	;C00h
DeallocationStack		PVOID ?           	;E0Ch
TlsSlots				PVOID 40h DUP (?)	;E10h
TlsLinks				LIST_ENTRY <>		;F10h
Vdm					PVOID ?			;F18h
ReservedForNtRpc		PVOID ?			;F1Ch
DbgSsReserved			PVOID 2h DUP (?)	;F20h
HardErrorDisabled		ULONG ?			;F28h
Instrumentation		PVOID 10h DUP (?)	;F2Ch
WinSockData			PVOID ?			;F6Ch
GdiBatchCount			ULONG ?			;F70h
InDbgPrint  			BYTE ?			;F74h
FreeStackOnTermination   BYTE ?			;F75h
HasFiberData   		BYTE ?			;F76h
IdealProcessor   		UCHAR ?			;F77h
GuaranteedStackBytes   	ULONG ?			;F78h
ReservedForPerf   		ULONG ?			;F7Ch   
ReservedForOle			PVOID ?			;F80h
WaitingOnLoaderLock		ULONG ?			;F84h
Wx86Thread   			Wx86ThreadState <>	;F88h
TlsExpansionSlots   	PVOID ?			;F94h
ImpersonationLocale   	ULONG ?			;F98h
IsImpersonating   		ULONG ?			;F9Ch
NlsCache   			PVOID ?			;FA0h
pShimData   			PVOID ?			;FA4h
HeapVirtualAffinity   	ULONG ?			;FA8h
CurrentTransactionHandle	PVOID ?			;FACh
ActiveFrame   			PTEB_ACTIVE_FRAME <>;FB0h
FlsSlots   			PVOID ?			;FB4h
TEB ends
PTEB typedef ptr TEB

PcTeb		equ TEB.Tib.Self

;typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
StandardDesign	equ 0	; None == 0 == standard design
NEC98x86		equ 1	; NEC PC98xx series on X86
EndAlternatives	equ 2	; past end of known alternatives

PROCESSOR_FEATURE_MAX	equ 64

KUSER_SHARED_DATA_ADDRESS	equ 7FFE0000h

KSYSTEM_TIME STRUCT		; sizeof = 0Ch
	LowPart		DWORD		?	; 0000h
	High1Time		SDWORD		?	; 0004h
	High2Time		SDWORD		?	; 0008h
KSYSTEM_TIME ENDS
PKSYSTEM_TIME typedef PTR KSYSTEM_TIME

NT_PRODUCT_TYPE typedef SDWORD

KUSER_SHARED_DATA struct 
;Current low 32-bit of tick count and tick count multiplier.
;N.B. The tick count is updated each time the clock ticks.
TickCountLow			ULONG ?			;0000h	;ntoskrnl.KeTickCount
TickCountMultiplier		ULONG ?			;0004h
;Current 64-bit interrupt time in 100ns units.
InterruptTime			KSYSTEM_TIME <>	;0008h
;Current 64-bit system time in 100ns units.
SystemTime			KSYSTEM_TIME <>	;0014h
;Current 64-bit time zone bias.
TimeZoneBias			KSYSTEM_TIME <>	;0020h
;Support image magic number range for the host system.
;N.B. This is an inclusive range.
ImageNumberLow			USHORT ?			;002Ch
ImageNumberHigh		USHORT ?			;002Eh
;Copy of system root in Unicode
NtSystemRoot			WCHAR 260 DUP (?)	;0030h
;Maximum stack trace depth if tracing enabled.
MaxStackTraceDepth		ULONG ?			;0238h
CryptoExponent			ULONG ?			;023Ch
TimeZoneId			ULONG ?			;0240h
Reserved2				ULONG 8 DUP (?)	;0244h
NtProductType			ULONG ?			;0264h	NT_PRODUCT_TYPE ?
ProductTypeIsValid		BOOLEAN ?			;0268h
;NT Version. Note that each process sees a version from its PEB, but
;if the process is running with an altered view of the system version,
;the following two fields are used to correctly identify the version
NtMajorVersion			ULONG ?			;[026Ch]*
NtMinorVersion			ULONG ?			;[0270h]*
;Processor Feature Bits
ProcessorFeatures		BYTE PROCESSOR_FEATURE_MAX DUP (?)	;[0274h]	;PF_, IsProcessorFeaturePresent()
;Reserved fields - do not use
Reserved1				ULONG ?			;[02B4h]
Reserved3				ULONG ?			;[02B8h]
;Time slippage while in debugger
TimeSlip				ULONG ?			;[02BCh]
;Alternative system architecture.  Example: NEC PC98xx on x86
AlternativeArchitecture	ULONG ?			;[02C0h]	ALTERNATIVE_ARCHITECTURE_TYPE
					ULONG ?			;02C4h
;If the system is an evaluation unit, the following field contains the
;date and time that the evaluation unit expires. A value of 0 indicates
;that there is no expiration. A non-zero value is the UTC absolute time
;that the system expires.
SystemExpirationDate	LARGE_INTEGER <>	;[02C8h]
;Suite Support
SuiteMask				ULONG ?			;[02D0h]
;TRUE if a kernel debugger is connected/enabled
KdDebuggerEnabled		BOOL ?			;[02D4h]*	Режим отладки
Undefined01			BYTE 3 DUP (?)		;[2D5h]
;Current console session Id. Always zero on non-TS systems
ActiveConsoleId		ULONG ?			;[2D8h]
;Force-dismounts cause handles to become invalid. Rather than
;always probe handles, we maintain a serial number of
;dismounts that clients can use to see if they need to probe handles.
DismountCount			ULONG ?			;[2DCh]
;This field indicates the status of the 64-bit COM+ package on the system.
;It indicates whether the Itermediate Language (IL) COM+ images need to
;use the 64-bit COM+ runtime or the 32-bit COM+ runtime.
ComPlusPackage			ULONG ?			;[2E0h]
;Time in tick count for system-wide last user input across all
;terminal sessions. For MP performance, it is not updated all
;the time (e.g. once a minute per session). It is used for idle detection.
LastSystemRITEventTickCount	ULONG ?		;[2E4h]
;Number of physical pages in the system.  This can dynamically
;change as physical memory can be added or removed from a running system.
NumberOfPhysicalPages	ULONG ?			;[2E8h]
;True if the system was booted in safe boot mode.
SafeBootMode			BOOLEAN ?			;[2ECh]*	Защищённый режим
;The following field is used for Heap  and  CritSec Tracing
;The last bit is set for Critical Sec Collision tracing and
;second Last bit is for Heap Tracing
;Also the first 16 bits are used as counter.
TraceLogging			ULONG ?			;[2F0h]
;Depending on the processor, the code for fast system call
;will differ, the following buffer is filled with the appropriate
;code sequence and user mode code will branch through it.
;(32 bytes, using ULONGLONG for alignment).
Undefined1			ULONG ?			;2F4h
ReturnOpcode			ULONG ?			;2F8h	;Opcode 'Ret'=0C3h
Undefined3			ULONG ?			;2FCh	;NULL
SystemCall			PVOID ?			;[300h]*
SystemCallRet			PVOID ?			;[304h]*
					DWORD 2Ch DUP (?)
EncodeMask			ULONG ?			;[330h]*	;RtlEncodeSystemPointer=EncodeMask xor Parameter

KUSER_SHARED_DATA ends
PKUSER_SHARED_DATA typedef PTR KUSER_SHARED_DATA

SIZE_OF_80387_REGISTERS		equ 80

; The following flags control the contents of the CONTEXT structure.
CONTEXT_i386				equ 00010000h    ; this assumes that i386 and
CONTEXT_i486				equ 00010000h    ; i486 have identical context records

CONTEXT_CONTROL				equ (CONTEXT_i386 or 00000001h) ; SS:SP, CS:IP, FLAGS, BP
CONTEXT_INTEGER				equ (CONTEXT_i386 or 00000002h) ; AX, BX, CX, DX, SI, DI
CONTEXT_SEGMENTS			equ (CONTEXT_i386 or 00000004h) ; DS, ES, FS, GS
CONTEXT_FLOATING_POINT		equ (CONTEXT_i386 or 00000008h) ; 387 state
CONTEXT_DEBUG_REGISTERS		equ (CONTEXT_i386 or 00000010h) ; DB 0-3,6,7
CONTEXT_EXTENDED_REGISTERS	equ (CONTEXT_i386 or 00000020h) ; cpu specific extensions

CONTEXT_FULL				equ (CONTEXT_CONTROL or CONTEXT_INTEGER or CONTEXT_SEGMENTS)
CONTEXT_ALL	equ CONTEXT_CONTROL or CONTEXT_INTEGER or CONTEXT_SEGMENTS or CONTEXT_FLOATING_POINT or CONTEXT_DEBUG_REGISTERS

CONTEXT_EXCEPTION_ACTIVE		equ 8000000h
CONTEXT_SERVICE_ACTIVE		equ 10000000h
CONTEXT_EXCEPTION_REQUEST	equ 40000000h
CONTEXT_EXCEPTION_REPORTING	equ 80000000h

MAXIMUM_SUPPORTED_EXTENSION	equ 512

INITIAL_MXCSR		equ 1F80h	;initial MXCSR value
INITIAL_FPCSR		equ 027Fh	;initial FPCSR value

M128A struct
_Low		ULONGLONG ?
_High	LONGLONG ?
M128A ends
PM128A typedef ptr M128A

XMM_SAVE_AREA32 struct
ControlWord	WORD ?
StatusWord	WORD ?
TagWord		BYTE ?
Reserved1		BYTE ?
ErrorOpcode	WORD ?
ErrorOffset	DWORD ?
ErrorSelector	WORD ?
Reserved2		WORD ?
DataOffset	DWORD ?
DataSelector	WORD ?
Reserved3		WORD ?
MxCsr		DWORD ?
MxCsr_Mask	DWORD ?
FloatRegisters	M128A 8 dup (<>)
XmmRegisters	M128A 16 dup (<>)
Reserved4		BYTE 96 dup (?)
XMM_SAVE_AREA32 ends
PXMM_SAVE_AREA32 typedef ptr XMM_SAVE_AREA32

FLOATING_SAVE_AREA STRUCT		; sizeof = 070h
	ControlWord		DWORD		?	; 0000h
	StatusWord		DWORD		?	; 0004h
	TagWord			DWORD		?	; 0008h
	ErrorOffset		DWORD		?	; 000Ch
	ErrorSelector		DWORD		?	; 0010h
	DataOffset		DWORD		?	; 0014h
	DataSelector		DWORD		?	; 0018h
	RegisterArea		BYTE		SIZE_OF_80387_REGISTERS dup(?)	; 001Ch
	Cr0NpxState		DWORD		?	; 006Ch
FLOATING_SAVE_AREA ENDS
PFLOATING_SAVE_AREA typedef PTR FLOATING_SAVE_AREA

; Context Frame
;  This frame has a several purposes: 1) it is used as an argument to
;  NtContinue, 2) is is used to constuct a call frame for APC delivery,
;  and 3) it is used in the user level thread creation routines.
;  The layout of the record conforms to a standard call frame.

CONTEXT STRUCT			; sizeof = 02CCh
	; The flags values within this flag control the contents of
	; a CONTEXT record.
	; If the context record is used as an input parameter, then
	; for each portion of the context record controlled by a flag
	; whose value is set, it is assumed that that portion of the
	; context record contains valid context. If the context record
	; is being used to modify a threads context, then only that
	; portion of the threads context will be modified.
	; If the context record is used as an IN OUT parameter to capture
	; the context of a thread, then only those portions of the thread's
	; context corresponding to set flags will be returned.
	; The context record is never used as an OUT only parameter.
	ContextFlags		DWORD		?	; 0000h
	; This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
	; set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
	; included in CONTEXT_FULL.
	regDr0			DWORD		?	; 0004h
	regDr1			DWORD		?	; 0008h
	regDr2			DWORD		?	; 000Ch
	regDr3			DWORD		?	; 0010h
	regDr6			DWORD		?	; 0014h
	regDr7			DWORD		?	; 0018h
	; This section is specified/returned if the
	; ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
	FloatSave			FLOATING_SAVE_AREA <>	; 001Ch
	; This section is specified/returned if the
	; ContextFlags word contians the flag CONTEXT_SEGMENTS.
	regSegGs			DWORD		?	; 008Ch
	regSegFs			DWORD		?	; 0090h
	regSegEs			DWORD		?	; 0094h
	regSegDs			DWORD		?	; 0098h
	; This section is specified/returned if the
	; ContextFlags word contians the flag CONTEXT_INTEGER.
	regEdi			DWORD		?	; 009Ch
	regEsi			DWORD		?	; 00A0h
	regEbx			DWORD		?	; 00A4h
	regEdx			DWORD		?	; 00A8h
	regEcx			DWORD		?	; 00ACh
	regEax			DWORD		?	; 00B0h
	; This section is specified/returned if the
	; ContextFlags word contians the flag CONTEXT_CONTROL.
	regEbp			DWORD		?	; 00B4h
	regEip			DWORD		?	; 00B8h
	regSegCs			DWORD		?	; 00BCh  MUST BE SANITIZED
	regEFlags			DWORD		?	; 00C0h  MUST BE SANITIZED
	regEsp			DWORD		?	; 00C4h
	regSegSs			DWORD		?	; 00C8h
	; This section is specified/returned if the ContextFlags word
	; contains the flag CONTEXT_EXTENDED_REGISTERS.
	; The format and contexts are processor specific
	ExtendedRegisters	BYTE		MAXIMUM_SUPPORTED_EXTENSION dup(?)	; 00CCh
CONTEXT ENDS
PCONTEXT typedef PTR CONTEXT
; Exception flag definitions.
EXCEPTION_NONCONTINUABLE 			equ 1	; Noncontinuable exception

; Define maximum number of exception parameters.
EXCEPTION_MAXIMUM_PARAMETERS		equ 15	; maximum number of exception parameters

; Exception record definition.
EXCEPTION_RECORD STRUCT		; sizeof = 050h
	ExceptionCode			NTSTATUS		?	; 0000h
	ExceptionFlags			DWORD		?	; 0004h
	ExceptionRecord		PVOID		?	; 0008h PTR EXCEPTION_RECORD
	ExceptionAddress		PVOID		?	; 000Ch
	NumberParameters		DWORD		?	; 0010h
	ExceptionInformation	DWORD		EXCEPTION_MAXIMUM_PARAMETERS dup(?)	; 0014h
EXCEPTION_RECORD ENDS
PEXCEPTION_RECORD typedef PTR EXCEPTION_RECORD

EXCEPTION_RECORD32 STRUCT
	ExceptionCode			NTSTATUS	?
	ExceptionFlags			DWORD	?
	ExceptionRecord		DWORD	?
	ExceptionAddress		DWORD	?
	NumberParameters		DWORD	?
	ExceptionInformation	DWORD EXCEPTION_MAXIMUM_PARAMETERS dup(?)
EXCEPTION_RECORD32 ENDS
PEXCEPTION_RECORD32 typedef PTR EXCEPTION_RECORD32

; Typedef for pointer returned by exception_info()
EXCEPTION_POINTERS STRUCT
	ExceptionRecord	PEXCEPTION_RECORD ?
	ContextRecord		PCONTEXT ?
EXCEPTION_POINTERS ENDS
PEXCEPTION_POINTERS typedef PTR EXCEPTION_POINTERS

;Define the base asynchronous I/O argument types
IO_STATUS_BLOCK struct
Status		NTSTATUS ?
Pointer		PVOID ?
Information	PULONG ?
IO_STATUS_BLOCK ends
PIO_STATUS_BLOCK typedef ptr IO_STATUS_BLOCK

;Define an Asynchronous Procedure Call from I/O viewpoint
IO_APC_ROUTINE struct
ApcContext	PVOID ?
IoStatusBlock	PIO_STATUS_BLOCK ?
Reserved		ULONG ?
IO_APC_ROUTINE ends
PIO_APC_ROUTINE typedef ptr IO_APC_ROUTINE

OSVERSIONINFOA STRUCT
	dwOSVersionInfoSize		DWORD	?		; 000h
	dwMajorVersion			DWORD	?		; 004h
	dwMinorVersion			DWORD	?		; 008h
	dwBuildNumber			DWORD	?		; 00Ch
	dwPlatformId			DWORD	?		; 010h
	szCSDVersion			BYTE 128 dup(?)	; 014h Maintenance string for PSS usage
OSVERSIONINFOA ENDS
POSVERSIONINFOA typedef ptr OSVERSIONINFOA
LPOSVERSIONINFOA typedef ptr OSVERSIONINFOA

OSVERSIONINFOW STRUCT
	dwOSVersionInfoSize		DWORD	?		; 000h
	dwMajorVersion			DWORD	?		; 004h
	dwMinorVersion			DWORD	?		; 008h
	dwBuildNumber			DWORD	?		; 00Ch
	dwPlatformId			DWORD	?		; 010h
	szCSDVersion			WORD 128 dup(?)	; 014h Maintenance string for PSS usage
OSVERSIONINFOW ENDS
POSVERSIONINFOW typedef ptr OSVERSIONINFOW
LPOSVERSIONINFOW typedef ptr OSVERSIONINFOW

RTL_OSVERSIONINFOW equ <OSVERSIONINFOW>
PRTL_OSVERSIONINFOW typedef ptr OSVERSIONINFOW

IFDEF UNICODE
OSVERSIONINFO equ <OSVERSIONINFOW>
POSVERSIONINFO typedef ptr OSVERSIONINFOW
LPOSVERSIONINFO typedef ptr OSVERSIONINFOW
ELSE
OSVERSIONINFO equ <OSVERSIONINFOA>
POSVERSIONINFO typedef ptr OSVERSIONINFOA
LPOSVERSIONINFO typedef ptr OSVERSIONINFOA
ENDIF

OSVERSIONINFOEXW  STRUCT
	dwOSVersionInfoSize	DWORD ?		; 000h
	dwMajorVersion		DWORD ?		; 004h
	dwMinorVersion		DWORD ?		; 008h
	dwBuildNumber		DWORD ?		; 00Ch
	dwPlatformId		DWORD ?		; 010h
	szCSDVersion		WORD 128 dup(?)	; 014h Maintenance string for PSS usage
	wServicePackMajor	WORD	?		; 114h
	wServicePackMinor	WORD	?		; 116h
	wSuiteMask		WORD	?		; 118h
	wProductType		BYTE	?		; 11Ah
	wReserved			BYTE	?		; 11Bh
OSVERSIONINFOEXW ENDS
POSVERSIONINFOEXW typedef ptr OSVERSIONINFOEXW
LPOSVERSIONINFOEXW typedef ptr OSVERSIONINFOEXW

RTL_OSVERSIONINFOEXW equ <OSVERSIONINFOEXW>
PRTL_OSVERSIONINFOEXW typedef ptr OSVERSIONINFOEXW

IFDEF UNICODE
OSVERSIONINFOEX equ <OSVERSIONINFOEXW>
POSVERSIONINFOEX typedef ptr OSVERSIONINFOEXW
LPOSVERSIONINFOEX typedef ptr OSVERSIONINFOEXW
ELSE
OSVERSIONINFOEX equ <OSVERSIONINFOEXA>
POSVERSIONINFOEX typedef ptr OSVERSIONINFOEXA
LPOSVERSIONINFOEX typedef ptr OSVERSIONINFOEXA
ENDIF

; RtlVerifyVersionInfo() conditions
VER_EQUAL                       equ 1
VER_GREATER                     equ 2
VER_GREATER_EQUAL               equ 3
VER_LESS                        equ 4
VER_LESS_EQUAL                  equ 5
VER_AND                         equ 6
VER_OR                          equ 7

VER_CONDITION_MASK              equ 7
VER_NUM_BITS_PER_CONDITION_MASK equ 3

; RtlVerifyVersionInfo() type mask bits
VER_MINORVERSION                equ 0000001h
VER_MAJORVERSION                equ 0000002h
VER_BUILDNUMBER                 equ 0000004h
VER_PLATFORMID                  equ 0000008h
VER_SERVICEPACKMINOR            equ 0000010h
VER_SERVICEPACKMAJOR            equ 0000020h
VER_SUITENAME                   equ 0000040h
VER_PRODUCT_TYPE                equ 0000080h

; RtlVerifyVersionInfo() os product type values
VER_NT_WORKSTATION              equ 0000001
VER_NT_DOMAIN_CONTROLLER        equ 0000002
VER_NT_SERVER                   equ 0000003

; dwPlatformId defines:
VER_PLATFORM_WIN32s             equ 0
VER_PLATFORM_WIN32_WINDOWS      equ 1
VER_PLATFORM_WIN32_NT           equ 2

; Processor Control Region Structure Definition
PCR_MINOR_VERSION	equ 1
PCR_MAJOR_VERSION	equ 1

; The non-volatile 387 state
KFLOATING_SAVE STRUCT
	ControlWord		DWORD	?
	StatusWord		DWORD	?
	ErrorOffset		DWORD	?
	ErrorSelector		DWORD	?
	DataOffset		DWORD	?	; Not used in wdm
	DataSelector		DWORD	?
	Cr0NpxState		DWORD	?
	Spare1			DWORD	?	; Not used in wdm
KFLOATING_SAVE ENDS
PKFLOATING_SAVE typedef ptr KFLOATING_SAVE

; i386 Specific portions of mm component
; Define the page size for the Intel 386 as 4096 (0x1000).
PAGE_SIZE	equ 1000h

; Define the number of trailing zeroes in a page aligned virtual address.
; This is used as the shift count when shifting virtual addresses to
; virtual page numbers.
PAGE_SHIFT	equ 12

; Define the number of bits to shift to right justify the Page Directory Index
; field of a PTE.
PDI_SHIFT_X86		equ 22
PDI_SHIFT_X86PAE	equ 21
PPI_SHIFT			equ 30	; X86PAE

; Define the number of bits to shift to right justify the Page Table Index
; field of a PTE.
PTI_SHIFT	equ 12

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; The lowest user address reserves the low 64k.
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Result type definition for i386.  (Machine specific enumerate type
; which is return type for portable exinterlockedincrement/decrement
; procedures.)  In general, you should use the enumerated type defined
; in ex.h instead of directly referencing these constants.
; Flags loaded into AH by LAHF instruction
EFLAG_SIGN		equ 8000h
EFLAG_ZERO		equ 4000h
EFLAG_SELECT	equ EFLAG_SIGN or EFLAG_ZERO

; Defined processor features
PF_FLOATING_POINT_PRECISION_ERRATA  equ 0
PF_FLOATING_POINT_EMULATED          equ 1
PF_COMPARE_EXCHANGE_DOUBLE          equ 2
PF_MMX_INSTRUCTIONS_AVAILABLE       equ 3
PF_PPC_MOVEMEM_64BIT_OK             equ 4
PF_ALPHA_BYTE_INSTRUCTIONS          equ 5
PF_XMMI_INSTRUCTIONS_AVAILABLE      equ 6
PF_3DNOW_INSTRUCTIONS_AVAILABLE     equ 7
PF_RDTSC_INSTRUCTION_AVAILABLE      equ 8
PF_PAE_ENABLED                      equ 9

EXCEPTION_DEBUG_INFO STRUCT
  pExceptionRecord  EXCEPTION_RECORD <?,?,?,?,?,EXCEPTION_MAXIMUM_PARAMETERS dup(?)>
  dwFirstChance     DWORD      ?
EXCEPTION_DEBUG_INFO ENDS

DEBUGSTRUCT UNION
  Exception         EXCEPTION_DEBUG_INFO <{?,?,?,?,?,EXCEPTION_MAXIMUM_PARAMETERS dup(?)},?>
  CreateThread      CREATE_THREAD_DEBUG_INFO <?,?,?>
  CreateProcessInfo CREATE_PROCESS_DEBUG_INFO <?,?,?,?,?,?,?,?,?,?>
  ExitThread        EXIT_THREAD_DEBUG_INFO <?>
  ExitProcess       EXIT_PROCESS_DEBUG_INFO <?>
  LoadDll           LOAD_DLL_DEBUG_INFO <?,?,?,?,?,?>
  UnloadDll         UNLOAD_DLL_DEBUG_INFO <?>
  DebugString       OUTPUT_DEBUG_STRING_INFO <?,?,?>
  RipInfo           RIP_INFO <?,?>
DEBUGSTRUCT ENDS

DEBUG_EVENT STRUCT
  dwDebugEventCode  DWORD       ?
  dwProcessId       DWORD       ?
  dwThreadId        DWORD       ?
  u                 DEBUGSTRUCT <>
DEBUG_EVENT ENDS

TIME_FIELDS 	typedef SYSTEMTIME
PTIME_FIELDS	typedef PSYSTEMTIME

;  Define an access token from a programmer's viewpoint.  The structure is
;  completely opaque and the programer is only allowed to have pointers
;  to tokens.

;  The following are masks for the predefined standard access types
DELETE                           equ 00010000h
READ_CONTROL                     equ 00020000h
WRITE_DAC                        equ 00040000h
WRITE_OWNER                      equ 00080000h
SYNCHRONIZE                      equ 00100000h
STANDARD_RIGHTS_REQUIRED         equ 000F0000h
STANDARD_RIGHTS_READ             equ READ_CONTROL
STANDARD_RIGHTS_WRITE            equ READ_CONTROL
STANDARD_RIGHTS_EXECUTE          equ READ_CONTROL
STANDARD_RIGHTS_ALL              equ 001F0000h
SPECIFIC_RIGHTS_ALL              equ 0000FFFFh

; AccessSystemAcl access type
ACCESS_SYSTEM_SECURITY           equ 01000000h

; MaximumAllowed access type
MAXIMUM_ALLOWED                  equ 02000000h

;  Define the generic mapping array.  This is used to denote the
;  mapping of each generic access right to a specific access mask.
GENERIC_MAPPING STRUCT				; sizeof = 010h
	GenericRead		DWORD		?	; 0000h ACCESS_MASK
	GenericWrite	DWORD		?	; 0004h ACCESS_MASK
	GenericExecute	DWORD		?	; 0008h ACCESS_MASK
	GenericAll		DWORD		?	; 000Ch ACCESS_MASK
GENERIC_MAPPING ENDS
PGENERIC_MAPPING typedef PTR GENERIC_MAPPING


; Object Manager Object Type Specific Access Rights.

OBJECT_TYPE_CREATE		equ 0001

OBJECT_TYPE_ALL_ACCESS	equ (STANDARD_RIGHTS_REQUIRED or 1)

; Object Manager Directory Specific Access Rights.

DIRECTORY_QUERY                 equ 0001
DIRECTORY_TRAVERSE              equ 0002
DIRECTORY_CREATE_OBJECT         equ 0004
DIRECTORY_CREATE_SUBDIRECTORY   equ 0008

DIRECTORY_ALL_ACCESS		equ (STANDARD_RIGHTS_REQUIRED or 0Fh)

; Object Manager Symbolic Link Specific Access Rights.

SYMBOLIC_LINK_QUERY			equ 0001

SYMBOLIC_LINK_ALL_ACCESS		equ (STANDARD_RIGHTS_REQUIRED or 1)


DUPLICATE_CLOSE_SOURCE      equ 00000001  ; winnt
DUPLICATE_SAME_ACCESS       equ 00000002  ; winnt
DUPLICATE_SAME_ATTRIBUTES   equ 00000004

SID_IDENTIFIER_AUTHORITY struct
Value	UCHAR 6 DUP (?)
SID_IDENTIFIER_AUTHORITY ends
PSID_IDENTIFIER_AUTHORITY typedef PTR SID_IDENTIFIER_AUTHORITY

SID struct
Revision			UCHAR ?
SubAuthorityCount	UCHAR ?
IdentifierAuthority SID_IDENTIFIER_AUTHORITY <>
SubAuthority		ULONG 1 DUP (?)
SID ends
PSID typedef PTR SID
;---------------------------------------------------- System Information -------------------------------------------------------
ZwQuerySystemInformation	proto SystemInformationClass:DWORD,SystemInformation:PVOID,SystemInformationLength:ULONG,ReturnLength:PULONG
comment '
ZwQuerySystemInformation(
IN SYSTEM_INFORMATION_CLASS SystemInformationClass,	;Класс системной информации
IN OUT PVOID SystemInformation,		;указатель на буфер принимающий системную информацию
IN ULONG SystemInformationLength,		;размер буфера в байтах
OUT PULONG ReturnLength OPTIONAL)		;указатель на переменную принимающую число байт возвращённых в буфере(Class=6 и 11. Может быть NULL
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_INFO_CLASS, STATUS_NOT_IMPLEMENTED or STATUS_INFO_LENGTH_MISMATCH.
' 

ZwSetSystemInformation	proto SystemInformationClass:DWORD, SystemInformation:PVOID, SystemInformationLength:ULONG
comment '
ZwSetSystemInformation(
IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
IN OUT PVOID SystemInformation,
IN ULONG SystemInformationLength);
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_INFO_CLASS, STATUS_NOT_IMPLEMENTED or STATUS_INFO_LENGTH_MISMATCH.
' 

;SYSTEM_INFORMATION_CLASS					Query	Set	Size
SystemBasicInformation				equ 0 	;Y 		N	0x002C
SystemProcessorInformation			equ 1 	;Y 		N	0x000C
SystemPerformanceInformation			equ 2 	;Y 		N	0x0138
SystemTimeOfDayInformation			equ 3 	;Y 		N	0x0020
SystemNotImplemented1				equ 4 	;Y 		N		;[SystemPathInformation]
SystemProcessesAndThreadsInformation	equ 5 	;Y 		N	0x00C8+ per process
SystemCallCounts					equ 6 	;Y 		N	0x0018 + (n * 0x0004)
SystemConfigurationInformation		equ 7 	;Y 		N	0x0018
SystemProcessorTimes				equ 8 	;Y 		N	0x0030 per cpu
SystemGlobalFlag					equ 9 	;Y 		Y	0x0004 (fails if size != 4)
SystemNotImplemented2				equ 10 	;Y 		N	
SystemModuleInformation				equ 11 	;Y 		N	0x0004 + (n * 0x011C)
SystemLockInformation				equ 12 	;Y 		N	0x0004 + (n * 0x0024)
SystemNotImplemented3				equ 13 	;Y 		N	
SystemNotImplemented4				equ 14 	;Y 		N	
SystemNotImplemented5				equ 15 	;Y 		N	
SystemHandleInformation				equ 16 	;Y 		N	0x0004  + (n * 0x0010)
SystemObjectInformation				equ 17 	;Y 		N	0x0038+ + (n * 0x0030+)
SystemPagefileInformation			equ 18 	;Y 		N	0x0018+ per page file
SystemInstructionEmulationCounts		equ 19 	;Y 		N	0x0088
SystemInvalidInfoClass1				equ 20
SystemCacheInformation				equ 21 	;Y 		Y	0x0024
SystemPoolTagInformation				equ 22 	;Y 		N	0x0004 + (n * 0x001C)
SystemProcessorStatistics			equ 23 	;Y 		N	0x0000, or 0x0018 per cpu	'SystemInterruptInformation'
SystemDpcInformation				equ 24 	;Y 		Y	0x0014
SystemNotImplemented6				equ 25 	;Y 		N
SystemLoadImage					equ 26 	;N 		Y	0x0018, set mode only
SystemUnloadImage					equ 27 	;N 		Y	0x0004, set mode only
SystemTimeAdjustment				equ 28 	;Y 		Y	0x000C, 0x0008 writeable
SystemNotImplemented7				equ 29 	;Y 		N
SystemNotImplemented8				equ 30 	;Y 		N
SystemNotImplemented9				equ 31 	;Y 		N
SystemCrashDumpInformation			equ 32 	;Y 		N	0x0004
SystemExceptionInformation			equ 33 	;Y 		N	0x0010
SystemCrashDumpStateInformation		equ 34 	;Y 		Y/N	0x0004
SystemKernelDebuggerInformation		equ 35 	;Y 		N	0x0002
SystemContextSwitchInformation		equ 36 	;Y 		N	0x0030
SystemRegistryQuotaInformation		equ 37 	;Y 		Y	0x000C
SystemLoadAndCallImage				equ 38 	;N 		Y	0x0008, set mode only
SystemPrioritySeparation				equ 39 	;N 		Y	0x0004, set mode only
SystemNotImplemented10				equ 40 	;Y 		N
SystemNotImplemented11				equ 41 	;Y 		N
SystemPowerInformation				equ 42	;			0x0060 (XP only!)
SystemProcessorSpeedInformation		equ 43	;			0x000C (XP only!)
SystemTimeZoneInformation			equ 44 	;Y 		N	0x00AC
SystemLookasideInformation			equ 45 	;Y 		N	n * 0x0020
SystemSetTimeSlipEvent				equ 46 	;N 		Y	
SystemCreateSession					equ 47 	;N 		Y
SystemDeleteSession					equ 48 	;N 		Y
SystemInvalidInfoClass4				equ 49
SystemRangeStartInformation			equ 50 	;Y 		N	0x0004 (fails if size != 4)
SystemVerifierInformation			equ 51 	;Y 		Y
SystemAddVerifier					equ 52 	;N 		Y
SystemSessionProcessesInformation		equ 53 	;Y 		N

SystemExtendedProcessesAndThreadsInformation	equ 57	;original SystemExtendedProcessInformation
SystemExtendedHandleInformation		equ 64

comment '
  SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,	;75
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
    
55/8		Kernel32.GetNumaHighestNodeNumber
60/88h	Kernel32.GetNumaAvailableMemoryNode
' 

;SystemBasicInformation (Information Class 0)
SYSTEM_BASIC_INFORMATION struct
Reserved					ULONG ?
TimerResolution			ULONG ?
PageSize					ULONG ?
NumberOfPhysicalPages		ULONG ?
LowestPhysicalPageNumber		ULONG ?
HighestPhysicalPageNumber	ULONG ?
AllocationGranularity		ULONG ?
MinimumUserModeAddress		ULONG ?
MaximumUserModeAddress		ULONG ?
ActiveProcessorsAffinityMask	ULONG ?
NumberOfProcessors			BYTE ?
_align					byte 3 dup (?)
SYSTEM_BASIC_INFORMATION ends
PSYSTEM_BASIC_INFORMATION typedef ptr SYSTEM_BASIC_INFORMATION

;SystemProcessorInformation (Information Class 1)
SYSTEM_PROCESSOR_INFORMATION struct
ProcessorArchitecture	USHORT ?		;PROCESSOR_ARCHITECTURE_* (PROCESSOR_ARCHITECTURE_INTEL)
ProcessorLevel			USHORT ?		;PROCESSOR_* (PROCESSOR_INTEL_PENTIUM)
ProcessorRevision		USHORT ?		;Pentium: H=model, L=stepping
Unknown				USHORT ?		;0
FeatureBits			ULONG ?
SYSTEM_PROCESSOR_INFORMATION ends
PSYSTEM_PROCESSOR_INFORMATION typedef PTR SYSTEM_PROCESSOR_INFORMATION 

comment '
;Intel Mnemonic Value Description
VME		equ 0001h	; Virtual-8086 Mode Enhancements
TCS		equ 0002h	; Time Stamp Counter
CR4		equ 0004h	; CR4 Register
CMOV	equ 0008h	; Conditional Mov/Cmp Instruction
PGE		equ 0010h	; PTE Global Bit
PSE		equ 0020h	; Page Size Extensions
MTRR	equ 0040h	; Memory Type Range Registers
CXS		equ 0080h	; CMPXCHGB8 Instruction
MMX		equ 0100h	; MMX Technology
PAT		equ 0400h	; Page Attribute Table
FXSR	equ 0800h	; Fast Floating Point Save and Restore
SIMD	equ 2000h	; Streaming SIMD Extension
' 

;SystemPerformanceInformation (Information Class 2)
SYSTEM_PERFORMANCE_INFORMATION struct
IdleTime				LARGE_INTEGER <>
ReadTransferCount		LARGE_INTEGER <>
WriteTransferCount		LARGE_INTEGER <>
OtherTransferCount		LARGE_INTEGER <>
ReadOperationCount		ULONG ?
WriteOperationCount		ULONG ?
OtherOperationCount		ULONG ?
AvailablePages			ULONG ?
TotalCommittedPages		ULONG ?
TotalCommitLimit		ULONG ?
PeakCommitment			ULONG ?
PageFaults			ULONG ?
WriteCopyFaults		ULONG ?
TransistionFaults		ULONG ?
Reserved1				ULONG ?
DemandZeroFaults		ULONG ?
PagesRead				ULONG ?
PageReadIos			ULONG ?
Reserved2				ULONG 2 DUP (?)
PagefilePagesWritten	ULONG ?
PagefilePageWriteIos	ULONG ?
MappedFilePagesWritten	ULONG ?
MappedFilePageWriteIos	ULONG ?
PagedPoolUsage			ULONG ?
NonPagedPoolUsage		ULONG ?
PagedPoolAllocs		ULONG ?
PagedPoolFrees			ULONG ?
NonPagedPoolAllocs		ULONG ?
NonPagedPoolFrees		ULONG ?
TotalFreeSystemPtes		ULONG ?
SystemCodePage			ULONG ?
TotalSystemDriverPages	ULONG ?
TotalSystemCodePages	ULONG ?
SmallNonPagedLookasideListAllocateHits		ULONG ?
SmallPagedLookasideListAllocateHits		ULONG ?
Reserved3				ULONG ?
MmSystemCachePage		ULONG ?
PagedPoolPage			ULONG ?
SystemDriverPage		ULONG ?
FastReadNoWait			ULONG ?
FastReadWait			ULONG ?
FastReadResourceMiss	ULONG ?
FastReadNotPossible		ULONG ?
FastMdlReadNoWait		ULONG ?
FastMdlReadWait		ULONG ?
FastMdlReadResourceMiss	ULONG ?
FastMdlReadNotPossible	ULONG ?
MapDataNoWait			ULONG ?
MapDataWait			ULONG ?
MapDataNoWaitMiss		ULONG ?
MapDataWaitMiss		ULONG ?
PinMappedDataCount		ULONG ?
PinReadNoWait			ULONG ?
PinReadWait			ULONG ?
PinReadNoWaitMiss		ULONG ?
PinReadWaitMiss		ULONG ?
CopyReadNoWait			ULONG ?
CopyReadWait			ULONG ?
CopyReadNoWaitMiss		ULONG ?
CopyReadWaitMiss		ULONG ?
MdlReadNoWait			ULONG ?
MdlReadWait			ULONG ?
MdlReadNoWaitMiss		ULONG ?
MdlReadWaitMiss		ULONG ?
ReadAheadIos			ULONG ?
LazyWriteIos			ULONG ?
LazyWritePages			ULONG ?
DataFlushes			ULONG ?
DataPages				ULONG ?
ContextSwitches		ULONG ?
FirstLevelTbFills		ULONG ?
SecondLevelTbFills		ULONG ?
SystemCalls			ULONG ?
SYSTEM_PERFORMANCE_INFORMATION ends
PSYSTEM_PERFORMANCE_INFORMATION typedef PTR SYSTEM_PERFORMANCE_INFORMATION

;SystemTimeOfDayInformation (Information Class 3)
SYSTEM_TIME_OF_DAY_INFORMATION struct 
BootTime			LARGE_INTEGER <>
CurrentTime		LARGE_INTEGER <>
TimeZoneBias		LARGE_INTEGER <>
CurrentTimeZoneId	ULONG ?
SYSTEM_TIME_OF_DAY_INFORMATION ends
PSYSTEM_TIME_OF_DAY_INFORMATION typedef PTR SYSTEM_TIME_OF_DAY_INFORMATION

;THREAD_STATE
StateInitialized	equ 0
StateReady		equ 1
StateRunning		equ 2
StateStandby		equ 3
StateTerminated	equ 4
StateWait			equ 5
StateTransition	equ 6
StateUnknown		equ 7

SYSTEM_THREADS struct 
KernelTime	LARGE_INTEGER <>	;The time spent executing in kernel mode,measured in units of 100-nanoseconds.
UserTime		LARGE_INTEGER <>	;The time spent executing in user mode,measured in units of 100-nanoseconds.
CreateTime	LARGE_INTEGER <>	;Время создания потока в 100нс
WaitTime		ULONG ?			;The time at which the thread last entered a wait state,measured in clock system boot.
StartAddress	PVOID ?			;Стартовый адрес потока
ClientId		CLIENT_ID <> 		;Идентификаторы процесса и потока
Priority		ULONG ? 			;Приоритет потока
BasePriority	ULONG ?			;Базовый приоритет потока
ContextSwitchCount	ULONG ? 		;Число переключений контекста потока
State		ULONG ?			;Состояние потока THREAD_STATE_
WaitReason	ULONG ?			;Описание причины ожидания WAIT_REASON_
;dwUnknown2	DWORD ?
SYSTEM_THREADS ends
PSYSTEM_THREADS typedef PTR SYSTEM_THREADS

QUOTA_LIMITS  STRUCT
	PagedPoolLimit			DWORD			?	; SIZE_T
	NonPagedPoolLimit		DWORD			?	; SIZE_T
	MinimumWorkingSetSize	DWORD			?	; SIZE_T
	MaximumWorkingSetSize	DWORD			?	; SIZE_T
	PagefileLimit			DWORD			?	; SIZE_T
;						DWORD			?
	TimeLimit				LARGE_INTEGER	<>
QUOTA_LIMITS ENDS
PQUOTA_LIMITS typedef ptr QUOTA_LIMITS

IO_COUNTERS STRUCT		; sizeof = 30h
	ReadOperationCount	LARGE_INTEGER	<>	; 00h
	WriteOperationCount	LARGE_INTEGER	<>	; 08h
	OtherOperationCount	LARGE_INTEGER	<>	; 10h
	ReadTransferCount	LARGE_INTEGER	<>	; 18h
	WriteTransferCount	LARGE_INTEGER	<>	; 20h
	OtherTransferCount	LARGE_INTEGER	<>	; 28h
IO_COUNTERS ENDS
PIO_COUNTERS typedef PTR IO_COUNTERS

VM_COUNTERS STRUCT
	PeakVirtualSize			DWORD	?	; SIZE_T
	VirtualSize				DWORD	?	; SIZE_T
	PageFaultCount				DWORD	?
	PeakWorkingSetSize			DWORD	?	; SIZE_T
	WorkingSetSize				DWORD	?	; SIZE_T
	QuotaPeakPagedPoolUsage		DWORD	?	; SIZE_T
	QuotaPagedPoolUsage			DWORD	?	; SIZE_T
	QuotaPeakNonPagedPoolUsage	DWORD	?	; SIZE_T
	QuotaNonPagedPoolUsage		DWORD	?	; SIZE_T
	PagefileUsage				DWORD	?	; SIZE_T
	PeakPagefileUsage			DWORD	?	; SIZE_T
VM_COUNTERS ENDS
PVM_COUNTERS typedef PTR VM_COUNTERS

KERNEL_USER_TIMES STRUCT
	CreateTime	LARGE_INTEGER	<>
	ExitTime		LARGE_INTEGER	<>
	KernelTime	LARGE_INTEGER	<>
	UserTime		LARGE_INTEGER	<>
KERNEL_USER_TIMES ENDS
PKERNEL_USER_TIMES typedef ptr KERNEL_USER_TIMES

;SystemProcessesAndThreadsInformation (Information Class 5)
SYSTEM_PROCESSES struct
NextEntryDelta	ULONG ? 		;Смещение от начала этой структуры до следующей, если ноль то эта последняя структура
ThreadCount	ULONG ?		;Число потоков в процессе
Reserved1		ULONG 6 DUP (?)
CreateTime	LARGE_INTEGER <>	;Стандартное время создания процесса(чило сотен наносекунд с January 1,1601)
UserTime		LARGE_INTEGER <>	;The sum of the time spent executing in user mode by the threads of the process, measured in units of 100-nanoseconds.
KernelTime	LARGE_INTEGER <> 	;The sum of the time spent executing in kernel mode by the threads of the process,measured in units of 100-nanoseconds.
ProcessName	UNICODE_STRING <> 	;Имя процесса (имя его исполнимого файла)
BasePriority	ULONG ? 		;Базовый приоритет по умолчанию для потоков в процессе
ProcessId		ULONG ? 		;Идентификатор процесса
InheritedFromProcessId	ULONG ? 	;The process id of the process from which handles and/or address space was inherited.
HandleCount	ULONG ? 		;Число дескрипторов открытых процессом
SessionId    	ULONG ?                      
Reserved2		ULONG 2 DUP (?)
VmCounters	VM_COUNTERS <> 	;Статистика использования виртуальной памяти процессом
IoCounters	IO_COUNTERS <>	;____Windows 2000 only! (VER_PRODUCTBUILD >= 2195). Статистика операций ввода-вывода в процессе
Threads		SYSTEM_THREADS <>	;Массив структур SYSTEM_THREADS описывающих потоки в процессе. Число структур определяется полем ThreadCount
SYSTEM_PROCESSES ends
PSYSTEM_PROCESSES typedef ptr SYSTEM_PROCESSES

;Состояния потока
ThreadStateInitialized	equ	0
ThreadStateReady		equ	1
ThreadStateRunning		equ	2
ThreadStateStandby		equ	3
ThreadStateTerminated	equ	4
ThreadStateWait		equ	5
ThreadStateTranzition	equ	6
ThreadStateUknown		equ	7

;WAIT_REASON 
Executive			equ 1
FreePage			equ 2
PageIn			equ 3
PoolAllocation		equ 4 
DelayExecution		equ 5
Suspended			equ 6
UserRequest		equ 7
WrExecutive		equ 8
WrFreePage		equ 9
WrPageIn			equ 10
WrPoolAllocation	equ 11
WrDelayExecution	equ 12
WrSuspended		equ 13
WrUserRequest		equ 14
WrEventPair		equ 15
WrQueue			equ 16
WrLpcReceive		equ 17
WrLpcReply		equ 18
WrVirtualMemory	equ 19
WrPageOut			equ 20
WrRendezvous		equ 21
Spare2			equ 22
Spare3			equ 23
Spare4			equ 24
Spare5			equ 25
Spare6			equ 26
WrKernel			equ 27

;SystemCallCounts (Information Class 6)
SYSTEM_CALLS_INFORMATION struct 
_Size		ULONG ?
NumberOfDescriptorTables	ULONG ?
NumberOfRoutinesInTable	ULONG 1 DUP (?)
;ULONG CallCounts[];
SYSTEM_CALLS_INFORMATION ends
PSYSTEM_CALLS_INFORMATION typedef PTR SYSTEM_CALLS_INFORMATION;

;SystemConfigurationInformation (Information Class 7)
SYSTEM_CONFIGURATION_INFORMATION struct
DiskCount		ULONG ?
FloppyCount	ULONG ?
CdRomCount	ULONG ?
TapeCount		ULONG ?
SerialCount	ULONG ?
ParallelCount	ULONG ?
SYSTEM_CONFIGURATION_INFORMATION ends
PSYSTEM_CONFIGURATION_INFORMATION typedef PTR SYSTEM_CONFIGURATION_INFORMATION

;SystemProcessorTimes(Information Class 8)
SYSTEM_PROCESSOR_TIMES struct
IdleTime		LARGE_INTEGER <>
KernelTime	LARGE_INTEGER <>
UserTime		LARGE_INTEGER <>
DpcTime		LARGE_INTEGER <>
InterruptTime	LARGE_INTEGER <>
InterruptCount	ULONG <>
SYSTEM_PROCESSOR_TIMES ends
PSYSTEM_PROCESSOR_TIMES typedef ptr SYSTEM_PROCESSOR_TIMES

;SystemGlobalFlag(Information Class 9)
SYSTEM_GLOBAL_FLAG struct
GlobalFlag	ULONG ?
SYSTEM_GLOBAL_FLAG ends
PSYSTEM_GLOBAL_FLAG typedef ptr SYSTEM_GLOBAL_FLAG

;SystemGlobalFlag
FLG_STOP_ON_EXCEPTION			equ 00000001h
FLG_SHOW_LDR_SNAPS				equ 00000002h
FLG_DEBUG_INITIAL_COMMAND		equ 00000004h
FLG_STOP_ON_HUNG_GUI			equ 00000008h
FLG_HEAP_ENABLE_TAIL_CHECK		equ 00000010h
FLG_HEAP_ENABLE_FREE_CHECK		equ 00000020h
FLG_HEAP_VALIDATE_PARAMETERS		equ 00000040h
FLG_HEAP_VALIDATE_ALL			equ 00000080h
FLG_POOL_ENABLE_TAIL_CHECK		equ 00000100h
FLG_POOL_ENABLE_FREE_CHECK		equ 00000200h
FLG_POOL_ENABLE_TAGGING			equ 00000400h
FLG_HEAP_ENABLE_TAGGING			equ 00000800h
FLG_USER_STACK_TRACE_DB			equ 00001000h
FLG_KERNEL_STACK_TRACE_DB		equ 00002000h
FLG_MAINTAIN_OBJECT_TYPELIST		equ 00004000h
FLG_HEAP_ENABLE_TAG_BY_DLL		equ 00008000h
FLG_IGNORE_DEBUG_PRIV			equ 00010000h
FLG_ENABLE_CSRDEBUG				equ 00020000h
FLG_ENABLE_KDEBUG_SYMBOL_LOAD		equ 00040000h
FLG_DISABLE_PAGE_KERNEL_STACKS	equ 00080000h
FLG_HEAP_ENABLE_CALL_TRACING		equ 00100000h
FLG_HEAP_DISABLE_COALESCING		equ 00200000h
FLG_ENABLE_CLOSE_EXCEPTIONS		equ 00400000h
FLG_ENABLE_EXCEPTION_LOGGING		equ 00800000h
FLG_ENABLE_DBGPRINT_BUFFERING		equ 08000000h

;SystemModuleInformation (Information Class 11)
SYSTEM_MODULE_INFORMATION struct	;
Reserved			ULONG 2 DUP (?)
Base				PVOID ?	;Базовый адрес модуля
_Size			ULONG ?	;Размер модуля
Flags			ULONG ?	;Битовый массив флагов определяющих состояние модуля
Index			USHORT ?	;Индекс модуля в массиве модулей	
Unknown			USHORT ?	;NULL
LoadCount			USHORT ?	;Число ссылок
ModuleNameOffset	USHORT ?	;Смещение конечного имени модуля в полном имени ImageName
ImageName			CHAR 256 DUP (?)	;Полное имя модуля
SYSTEM_MODULE_INFORMATION ends
PSYSTEM_MODULE_INFORMATION typedef ptr SYSTEM_MODULE_INFORMATION

;SystemLockInformation(Information Class 12)
SYSTEM_LOCK_INFORMATION struct
Address				PVOID ?
_Type				USHORT ?
Reserved1				USHORT ?
ExclusiveOwnerThreadId	ULONG ?
ActiveCount			ULONG ?
ContentionCount		ULONG ?
Reserved2				ULONG 2 DUP (?)
NumberOfSharedWaiters	ULONG ?
NumberOfExclusiveWaiters	ULONG ?
SYSTEM_LOCK_INFORMATION ends
PSYSTEM_LOCK_INFORMATION typedef ptr SYSTEM_LOCK_INFORMATION

;SystemPoolBlocksInformation(Information Class 14,15)
SYSTEM_POOL_BLOCK struct
Allocated		BOOLEAN ?
Unknown		USHORT ?
_Size		ULONG ?
Tag			CHAR 4 DUP (?)
SYSTEM_POOL_BLOCK ends
PSYSTEM_POOL_BLOCK typedef ptr SYSTEM_POOL_BLOCK

SYSTEM_POOL_BLOCKS_INFORMATION struct
PoolSize		ULONG ?
PoolBase		PVOID ?
Unknown		USHORT ?
NumberOfBlocks	ULONG ?
PoolBlocks	SYSTEM_POOL_BLOCK 1 DUP (<>)
SYSTEM_POOL_BLOCKS_INFORMATION ends
PSYSTEM_POOL_BLOCKS_INFORMATION typedef ptr SYSTEM_POOL_BLOCKS_INFORMATION

;SystemHandleInformation (Information Class 16)
SYSTEM_HANDLE_INFORMATION struct
ProcessId			ULONG ?
ObjectTypeNumber	UCHAR ?
Flags			UCHAR ?	;0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
Handle			USHORT ?
Object			PVOID ?
GrantedAccess		ACCESS_MASK ?
SYSTEM_HANDLE_INFORMATION ends
PSYSTEM_HANDLE_INFORMATION typedef PTR SYSTEM_HANDLE_INFORMATION
;Первое двойное слово в буфере:число структур в буфере
;ObjectTypeNumber:
OBJ_TYPE_TYPE			equ 1
OBJ_TYPE_DIRECTORY		equ 2
OBJ_TYPE_SYMBOLIC_LINK	equ 3
OBJ_TYPE_TOKEN			equ 4
OBJ_TYPE_PROCESS		equ 5
OBJ_TYPE_THREAD		equ 6
OBJ_TYPE_JOB			equ 7
OBJ_TYPE_DEBUG_OBJECT	equ 8
OBJ_TYPE_EVENT			equ 9
OBJ_TYPE_EVENT_PAIR		equ 10
OBJ_TYPE_MUTANT		equ 11
OBJ_TYPE_CALLBACK		equ 12
OBJ_TYPE_SEMAPHORE		equ 13
OBJ_TYPE_TIMER			equ 14
OBJ_TYPE_PROFILE		equ 15
OBJ_TYPE_KEYED_EVENT	equ 16
OBJ_TYPE_WINDOW_STATION	equ 17
OBJ_TYPE_DESKTOP		equ 18
OBJ_TYPE_SECTION		equ 19
OBJ_TYPE_KEY			equ 20
OBJ_TYPE_PORT			equ 21
OBJ_TYPE_WAITABLE_PORT	equ 22
OBJ_TYPE_ADAPTER		equ 23
OBJ_TYPE_CONTROLLER		equ 24
OBJ_TYPE_DEVICE		equ 25
OBJ_TYPE_DRIVER		equ 26
OBJ_TYPE_IO_COMPLETION	equ 27
OBJ_TYPE_FILE			equ 28
OBJ_TYPE_WMI_GUID		equ 29
OBJ_TYPE_FILTER_CONNECTION_PORT	equ 30
OBJ_TYPE_FILTER_COMMUNICATION_PORT	equ 31

NonPagedPoolSession		equ 32
PagedPoolSession 		equ NonPagedPoolSession + 1
NonPagedPoolMustSucceedSession equ PagedPoolSession + 1
DontUseThisTypeSession 	equ NonPagedPoolMustSucceedSession + 1
NonPagedPoolCacheAlignedSession equ DontUseThisTypeSession + 1
PagedPoolCacheAlignedSession 	equ NonPagedPoolCacheAlignedSession + 1
NonPagedPoolCacheAlignedMustSSession equ PagedPoolCacheAlignedSession + 1
POOL_COLD_ALLOCATION	equ 256	;Note this cannot encode into the header.

;SystemObjectInformation (Information Class 17)
SYSTEM_OBJECT_TYPE_INFORMATION struct	;SizeOf = 14h
NextEntryOffset	ULONG ?			;+00h	Смещение от начала буфера с информацией до следующей структуры SYSTEM_OBJECT_TYPE_INFORMATION[Zero->Last]
ObjectCount		ULONG ?			;+04h
HandleCount		ULONG ?			;+08h
TypeNumber		ULONG ?			;+0Ch
InvalidAttributes	ULONG ?			;+10h
GenericMapping		GENERIC_MAPPING <>	;+14h
ValidAccessMask	ACCESS_MASK ?		;+24h
PoolType			POOL_TYPE ?		;+28h
Unknown			ULONG ?			;+2Ch
_Name			UNICODE_STRING <>	;+30h	Имя типа обьекта
SYSTEM_OBJECT_TYPE_INFORMATION ends
PSYSTEM_OBJECT_TYPE_INFORMATION typedef PTR SYSTEM_OBJECT_TYPE_INFORMATION

SYSTEM_OBJECT_INFORMATION struct
NextEntryOffset	ULONG ?	;Смещение от начала буфера с информацией до следуюжей структуры SYSTEM_OBJECT_INFORMATION[Zero->Last]
Object			PVOID ?
CreatorProcessId	ULONG ?
Unknown			USHORT ?
Flags			USHORT ?
PointerCount		ULONG ?
HandleCount		ULONG ?
PagedPoolUsage		ULONG ?
NonPagedPoolUsage	ULONG ?
ExclusiveProcessId	ULONG ?
SecurityDescriptor	PSECURITY_DESCRIPTOR ?
_Name			UNICODE_STRING <>
SYSTEM_OBJECT_INFORMATION ends
PSYSTEM_OBJECT_INFORMATION typedef PTR SYSTEM_OBJECT_INFORMATION
comment '
Вначале находится структура SYSTEM_OBJECT_TYPE_INFORMATION определяющая тип обьектов.
За ней идёт имя обьекта и массив структур SYSTEM_OBJECT_INFORMATION с описанием обьектов.
' 

;Flags
SINGLE_HANDLE_ENTRY		equ 40h
DEFAULT_SECURITY_QUOTA	equ 20h
PERMANENT				equ 10h
EXCLUSIVE				equ 08h
CREATOR_INFO			equ 04h
KERNEL_MODE			equ 02h

;SystemPagefileInformation(Information Class 18)
SYSTEM_PAGEFILE_INFORMATION struct
NextEntryOffset	ULONG ?
CurrentSize		ULONG ?
TotalUsed			ULONG ?
PeakUsed			ULONG ?
FileName			UNICODE_STRING <>
SYSTEM_PAGEFILE_INFORMATION ends
PSYSTEM_PAGEFILE_INFORMATION typedef ptr SYSTEM_PAGEFILE_INFORMATION

;SystemInstructionEmulationCounts(Information Class 19)
SYSTEM_INSTRUCTION_EMULATION_INFORMATION struct
SegmentNotPresent	ULONG ?
TwoByteOpcode	ULONG ?
ESprefix		ULONG ?
CSprefix		ULONG ?
SSprefix		ULONG ?
DSprefix		ULONG ?
FSPrefix		ULONG ?
GSprefix		ULONG ?
OPER32prefix	ULONG ?
ADDR32prefix	ULONG ?
iINSB		ULONG ?
iINSW		ULONG ?
iOUTSB		ULONG ?
iOUTSW		ULONG ?
iPUSHFD		ULONG ?
iPOPFD		ULONG ?
iINTnn		ULONG ?
iINTO		ULONG ?
iIRETD		ULONG ?
iINBimm		ULONG ?
iINWimm		ULONG ?
iOUTBimm		ULONG ?
iOUTWimm		ULONG ?
iINB			ULONG ?
iINW			ULONG ?
iOUTB		ULONG ?
iOUTW		ULONG ?
LOCKprefix	ULONG ?
REPNEprefix	ULONG ?
REPprefix		ULONG ?
iHLT			ULONG ?
iCLI			ULONG ?
iSTI			ULONG ?
GenericInvalidOpcode	ULONG ?
SYSTEM_INSTRUCTION_EMULATION_INFORMATION ends
PSYSTEM_INSTRUCTION_EMULATION_INFORMATION typedef ptr SYSTEM_INSTRUCTION_EMULATION_INFORMATION

;SystemCacheInformation(Information Class 21)
SYSTEM_CACHE_INFORMATION struct
SystemCacheWsSize		ULONG ?
SystemCacheWsPeakSize	ULONG ?
SystemCacheWsFaults		ULONG ?
SystemCacheWsMinimum	ULONG ?
SystemCacheWsMaximum	ULONG ?
TransitionSharedPages	ULONG ?
TransitionSharedPagesPeak	ULONG ?
Reserved		ULONG 2 DUP (?)
SYSTEM_CACHE_INFORMATION ends
PSYSTEM_CACHE_INFORMATION typedef ptr SYSTEM_CACHE_INFORMATION

;SystemPoolTagInformation(Information Class 22)
SYSTEM_POOL_TAG_INFORMATION struct
Tag		CHAR 4 DUP (?)
PagedPoolAllocs	ULONG ?
PagedPoolFrees		ULONG ?
PagedPoolUsage		ULONG ?
NonPagedPoolAllocs	ULONG ?
NonPagedPoolFrees	ULONG ?
NonPagedPoolUsage	ULONG ?
SYSTEM_POOL_TAG_INFORMATION ends
PSYSTEM_POOL_TAG_INFORMATION typedef ptr SYSTEM_POOL_TAG_INFORMATION

;SystemProcessorStatistics(Information Class 23)
SYSTEM_PROCESSOR_STATISTICS struct
ContextSwitches	ULONG ?
DpcCount			ULONG ?
DpcRequestRate		ULONG ?
TimeIncrement		ULONG ?
DpcBypassCount		ULONG ?
ApcBypassCount		ULONG ?
SYSTEM_PROCESSOR_STATISTICS ends
PSYSTEM_PROCESSOR_STATISTICS typedef ptr SYSTEM_PROCESSOR_STATISTICS

;SystemDpcInformation(Information Class 24)
SYSTEM_DPC_INFORMATION struct
Reserved			ULONG ?
MaximumDpcQueueDepth	ULONG ?
MinimumDpcRate		ULONG ?
AdjustDpcThreshold	ULONG ?
IdealDpcRate		ULONG ?
SYSTEM_DPC_INFORMATION ends
PSYSTEM_DPC_INFORMATION typedef ptr SYSTEM_DPC_INFORMATION

;SystemMemoryUsageInformation(Information Class 25,29)
SYSTEM_MEMORY_USAGE struct
Name			PVOID ?
Valid		USHORT ?
Standby		USHORT ?
Modified		USHORT ?
PageTables	USHORT ?
SYSTEM_MEMORY_USAGE ends
PSYSTEM_MEMORY_USAGE typedef ptr SYSTEM_MEMORY_USAGE

SYSTEM_MEMORY_USAGE_INFORMATION struct
Reserved		ULONG ?
EndOfData		PVOID ?
MemoryUsage	SYSTEM_MEMORY_USAGE 1 dup (<>)
SYSTEM_MEMORY_USAGE_INFORMATION ends
PSYSTEM_MEMORY_USAGE_INFORMATION typedef ptr SYSTEM_MEMORY_USAGE_INFORMATION

;SystemLoadImage(Information Class 26)
SYSTEM_LOAD_IMAGE struct
ModuleName	UNICODE_STRING <>
ModuleBase	PVOID ?
Unknown		PVOID ?
EntryPoint	PVOID ?
ExportDirectory	PVOID ?
SYSTEM_LOAD_IMAGE ends
PSYSTEM_LOAD_IMAGE typedef ptr SYSTEM_LOAD_IMAGE

;SystemUnloadImage(Information Class 27)
SYSTEM_UNLOAD_IMAGE struct
ModuleBase	PVOID ?
SYSTEM_UNLOAD_IMAGE ends
PSYSTEM_UNLOAD_IMAGE typedef ptr SYSTEM_UNLOAD_IMAGE

;SystemTimeAdjustment(Information Class 28)
SYSTEM_QUERY_TIME_ADJUSTMENT struct
TimeAdjustment		ULONG ?
MaximumIncrement	ULONG ?
TimeSynchronization	BOOLEAN ?
SYSTEM_QUERY_TIME_ADJUSTMENT ends
PSYSTEM_QUERY_TIME_ADJUSTMENT typedef ptr SYSTEM_QUERY_TIME_ADJUSTMENT

SYSTEM_SET_TIME_ADJUSTMENT struct
TimeAdjustment		ULONG ?
TimeSynchronization	BOOLEAN ?
SYSTEM_SET_TIME_ADJUSTMENT ends
PSYSTEM_SET_TIME_ADJUSTMENT typedef ptr SYSTEM_SET_TIME_ADJUSTMENT

;SystemCrashDumpInformation(Information Class 32)
SYSTEM_CRASH_DUMP_INFORMATION struct
CrashDumpSectionHandle	HANDLE ?
;Unknown		HANDLE ?	;Windows 2000 only
SYSTEM_CRASH_DUMP_INFORMATION ends
PSYSTEM_CRASH_DUMP_INFORMATION typedef ptr SYSTEM_CRASH_DUMP_INFORMATION

;SystemExceptionInformation(Information Class 33)
SYSTEM_EXCEPTION_INFORMATION struct
AlignmentFixupCount		ULONG ?
ExceptionDispatchCount	ULONG ?
FloatingEmulationCount	ULONG ?
Reserved				ULONG ?
SYSTEM_EXCEPTION_INFORMATION ends
PSYSTEM_EXCEPTION_INFORMATION typedef ptr SYSTEM_EXCEPTION_INFORMATION

;SystemCrashDumpStateInformation(Information Class 34)
SYSTEM_CRASH_DUMP_STATE_INFORMATION struct
CrashDumpSectionExists	ULONG ?
;Unknown	ULONG ?	;Windows 2000 only
SYSTEM_CRASH_DUMP_STATE_INFORMATION ends
PSYSTEM_CRASH_DUMP_STATE_INFORMATION typedef ptr SYSTEM_CRASH_DUMP_STATE_INFORMATION

;SystemKernelDebuggerInformation(Information Class 35)
SYSTEM_KERNEL_DEBUGGER_INFORMATION struct
DebuggerEnabled		BOOLEAN ?
DebuggerNotPresent		BOOLEAN ?
SYSTEM_KERNEL_DEBUGGER_INFORMATION ends
PSYSTEM_KERNEL_DEBUGGER_INFORMATION typedef ptr SYSTEM_KERNEL_DEBUGGER_INFORMATION

;SystemContextSwitchInformation(Information Class 36)
SYSTEM_CONTEXT_SWITCH_INFORMATION struct
ContextSwitches		ULONG ?
ContextSwitchCounters	ULONG 11 DUP (?)
SYSTEM_CONTEXT_SWITCH_INFORMATION ends
PSYSTEM_CONTEXT_SWITCH_INFORMATION typedef ptr SYSTEM_CONTEXT_SWITCH_INFORMATION

;SystemRegistryQuotaInformation(Information Class 37)
SYSTEM_REGISTRY_QUOTA_INFORMATION struct
RegistryQuota		ULONG ?
RegistryQuotaInUse	ULONG ?
PagedPoolSize		ULONG ?
SYSTEM_REGISTRY_QUOTA_INFORMATION ends
PSYSTEM_REGISTRY_QUOTA_INFORMATION typedef ptr SYSTEM_REGISTRY_QUOTA_INFORMATION

;SystemLoadAndCallImage(Information Class 38)
SYSTEM_LOAD_AND_CALL_IMAGE struct
ModuleName	UNICODE_STRING <>
SYSTEM_LOAD_AND_CALL_IMAGE ends
PSYSTEM_LOAD_AND_CALL_IMAGE typedef ptr SYSTEM_LOAD_AND_CALL_IMAGE

;SystemPrioritySeparation(Information Class 39)
SYSTEM_PRIORITY_SEPARATION struct
PrioritySeparation	ULONG ?
SYSTEM_PRIORITY_SEPARATION ends
PSYSTEM_PRIORITY_SEPARATION typedef ptr SYSTEM_PRIORITY_SEPARATION

;SystemPowerInformation(Information Class 42)
SYSTEM_POWER_INFORMATION	struct
SystemSuspendSupported		BOOLEAN ?
SystemHibernateSupported		BOOLEAN ?
ResumeTimerSupportsSuspend	BOOLEAN ?
ResumeTimerSupportsHibernate	BOOLEAN ?
LidSupported			BOOLEAN ?
TurboSettingSupported	BOOLEAN ?
TurboMode			BOOLEAN ?
SystemAcOrDc		BOOLEAN ?
PowerDownDisabled	BOOLEAN ?
SpindownDrives		LARGE_INTEGER <>
SYSTEM_POWER_INFORMATION ends
PSYSTEM_POWER_INFORMATION typedef ptr SYSTEM_POWER_INFORMATION

;SystemProcessorSpeedInformation(Information Class 43)
SYSTEM_PROCESSOR_SPEED_INFORMATION struct
MaximumProcessorSpeed	ULONG ?
CurrentAvailableSpeed	ULONG ?
ConfiguredSpeedLimit	ULONG ?
PowerLimit		BOOLEAN ?
ThermalLimit		BOOLEAN ?
TurboLimit		BOOLEAN ?
SYSTEM_PROCESSOR_SPEED_INFORMATION ends
PSYSTEM_PROCESSOR_SPEED_INFORMATION typedef ptr SYSTEM_PROCESSOR_SPEED_INFORMATION

;SystemTimeZoneInformation(Information Class 44)
SYSTEM_TIME_ZONE_INFORMATION struct
Bias			LONG ?
StandardName	WCHAR 32 DUP (?)
StandardDate	SYSTEMTIME <>
StandardBias	LONG ?
DaylightName	WCHAR 32 DUP (?)
DaylightDate	SYSTEMTIME <>
DaylightBias	LONG ?
SYSTEM_TIME_ZONE_INFORMATION ends
PSYSTEM_TIME_ZONE_INFORMATION typedef ptr SYSTEM_TIME_ZONE_INFORMATION

;SystemLookasideInformation(Information Class 45)
SYSTEM_LOOKASIDE_INFORMATION struct
Depth		USHORT ?
MaximumDepth	USHORT ?
TotalAllocates	ULONG ?
AllocateMisses	ULONG ?
TotalFrees	ULONG ?
FreeMisses	ULONG ?
_Type		ULONG ?	;POOL_TYPE
Tag			ULONG ?
Size_		ULONG ?
SYSTEM_LOOKASIDE_INFORMATION ends
PSYSTEM_LOOKASIDE_INFORMATION typedef ptr SYSTEM_LOOKASIDE_INFORMATION

;enum POOL_TYPE
NonPagedPool				equ 0
PagedPool					equ 1
NonPagedPoolMustSucceed		equ 2
DontUseThisType			equ 3
NonPagedPoolCacheAligned		equ 4
PagedPoolCacheAligned		equ 5
NonPagedPoolCacheAlignedMustS	equ 6
MaxPoolType				equ 7
NonPagedPoolSession			equ 32
PagedPoolSession			equ 33
NonPagedPoolMustSucceedSession	equ 34
DontUseThisTypeSession			equ 35
NonPagedPoolCacheAlignedSession	equ 36
PagedPoolCacheAlignedSession		equ 37
NonPagedPoolCacheAlignedMustSSession	equ 38

;SystemSetTimeSlipEvent(Information Class 46)
SYSTEM_SET_TIME_SLIP_EVENT struct
TimeSlipEvent	HANDLE ?
SYSTEM_SET_TIME_SLIP_EVENT ends
PSYSTEM_SET_TIME_SLIP_EVENT typedef ptr SYSTEM_SET_TIME_SLIP_EVENT

;SystemCreateSession(Information Class 47)
SYSTEM_CREATE_SESSION struct
SessionId		ULONG ?
SYSTEM_CREATE_SESSION ends
PSYSTEM_CREATE_SESSION typedef ptr SYSTEM_CREATE_SESSION

;SystemDeleteSession(Information Class 48)
SYSTEM_DELETE_SESSION struct
SessionId		ULONG ?
SYSTEM_DELETE_SESSION ends
PSYSTEM_DELETE_SESSION typedef ptr SYSTEM_DELETE_SESSION

;SystemRangeStartInformation(Information Class 50)
SYSTEM_RANGE_START_INFORMATION struct
SystemRangeStart	PVOID ?
SYSTEM_RANGE_START_INFORMATION ends
PSYSTEM_RANGE_START_INFORMATION typedef ptr SYSTEM_RANGE_START_INFORMATION

;SystemSessionProcessesInformation(Information Class 53)
SYSTEM_SESSION_PROCESSES_INFORMATION struct
SessionId		ULONG ?
BufferSize	ULONG ?
Buffer		PVOID ?
SYSTEM_SESSION_PROCESSES_INFORMATION ends
PSYSTEM_SESSION_PROCESSES_INFORMATION typedef ptr SYSTEM_SESSION_PROCESSES_INFORMATION

ZwQuerySystemEnvironmentValue proto _Name:PUNICODE_STRING, Value:PVOID, ValueLength:ULONG, ReturnLength:PULONG
comment '
ZwQuerySystemEnvironmentValue(
IN PUNICODE_STRING Name,
OUT PVOID Value,
IN ULONG ValueLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
' 

ZwSetSystemEnvironmentValue proto _Name:PUNICODE_STRING, Value:PUNICODE_STRING
comment '
ZwSetSystemEnvironmentValue(
IN PUNICODE_STRING Name,
IN PUNICODE_STRING Value):NTSTATUS
' 

ZwShutdownSystem proto Action:ULONG
comment '
ZwShutdownSystem(
IN ULONG Action):NTSTATUS
' 

;Action
ShutdownNoReboot	equ 0
ShutdownReboot		equ 1
ShutdownPowerOff	equ 2
;------------------------------------------------------ Objects ----------------------------------------------------
ZwQueryObject proto ObjectHandle:HANDLE, ObjectInformationClass:ULONG, ObjectInformation:PVOID, ObjectInformationLength:ULONG, ReturnLength:PULONG
comment '
ZwQueryObject(
IN HANDLE ObjectHandle,
IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
OUT PVOID ObjectInformation,
IN ULONG ObjectInformationLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
' 

ZwSetInformationObject proto ObjectHandle:HANDLE, ObjectInformationClass:ULONG, ObjectInformation:PVOID, ObjectInformationLength:ULONG
comment '
ZwSetInformationObject(
IN HANDLE ObjectHandle,
IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
IN PVOID ObjectInformation,
IN ULONG ObjectInformationLength):NTSTATUS
' 

;OBJECT_INFORMATION_CLASS			Query	Set
ObjectBasicInformation		equ 0	;Y 		N
ObjectNameInformation		equ 1	;Y 		N
ObjectTypeInformation		equ 2	;Y		N
ObjectAllTypesInformation	equ 3 	;Y 		N
ObjectHandleInformation		equ 4	;Y 		Y

;ObjectBasicInformation(Information Class 0)
OBJECT_BASIC_INFORMATION struct
Attributes		ULONG ?
GrantedAccess		ACCESS_MASK ?
HandleCount		ULONG ?
PointerCount		ULONG ?
PagedPoolUsage		ULONG ?
NonPagedPoolUsage	ULONG ?
Reserved			ULONG 3 DUP (?)
NameInformationLength	ULONG ?
TypeInformationLength	ULONG ?
SecurityDescriptorLength	ULONG ?
CreateTime			LARGE_INTEGER <>
OBJECT_BASIC_INFORMATION ends
POBJECT_BASIC_INFORMATION typedef ptr OBJECT_BASIC_INFORMATION

HANDLE_FLAG_INHERIT		equ 01h
HANDLE_FLAG_PROTECT_FROM_CLOSE	equ 02h

;ObjectNameInformation(Information Class 1)
OBJECT_NAME_INFORMATION struct
_Name		UNICODE_STRING <>
OBJECT_NAME_INFORMATION ends
POBJECT_NAME_INFORMATION typedef ptr OBJECT_NAME_INFORMATION

;ObjectTypeInformation(Information Class 2)
OBJECT_TYPE_INFORMATION struct
TypeName					UNICODE_STRING <>
TotalNumberOfObjects		ULONG ?
TotalNumberOfHandles		ULONG ?
TotalPagedPoolUsage			ULONG ?
TotalNonPagedPoolUsage		ULONG ?
TotalNamePoolUsage			ULONG ?
TotalHandleTableUsage		ULONG ?
HighWaterNumberOfObjects		ULONG ?
HighWaterNumberOfHandles		ULONG ?
HighWaterPagedPoolUsage		ULONG ?
HighWaterNonPagedPoolUsage	ULONG ?
HighWaterNamePoolUsage		ULONG ?
HighWaterHandleTableUsage	ULONG ?
InvalidAttributes			ULONG ?
GenericMapping				GENERIC_MAPPING <>
ValidAccessMask			ULONG ?
SecurityRequired			BOOLEAN ?
MaintainHandleCount			BOOLEAN ?
;PoolType					ULONG ?
DefaultPagedPoolCharge		ULONG ?
DefaultNonPagedPoolCharge	ULONG ?
OBJECT_TYPE_INFORMATION ends
POBJECT_TYPE_INFORMATION typedef ptr OBJECT_TYPE_INFORMATION

;ObjectAllTypesInformation(Information Class 3)
OBJECT_ALL_TYPES_INFORMATION struct
NumberOfTypes		ULONG ?
TypeInformation	OBJECT_TYPE_INFORMATION <>
OBJECT_ALL_TYPES_INFORMATION ends
POBJECT_ALL_TYPES_INFORMATION typedef ptr OBJECT_ALL_TYPES_INFORMATION

;ObjectHandleInformation(Information Class 4)
OBJECT_HANDLE_ATTRIBUTE_INFORMATION struct
Inherit			BYTE ?
ProtectFromClose	BYTE ?
_align	db 2 dup (?)
OBJECT_HANDLE_ATTRIBUTE_INFORMATION ends
POBJECT_HANDLE_ATTRIBUTE_INFORMATION typedef ptr OBJECT_HANDLE_ATTRIBUTE_INFORMATION

ZwDuplicateObject proto SourceProcessHandle:HANDLE, SourceHandle:HANDLE, TargetProcessHandle:HANDLE, TargetHandle:PHANDLE, DesiredAccess:ULONG, Attributes:ULONG, Options:ULONG
comment '
ZwDuplicateObject(
IN HANDLE SourceProcessHandle,
IN HANDLE SourceHandle,
IN HANDLE TargetProcessHandle,
OUT PHANDLE TargetHandle OPTIONAL,
IN ACCESS_MASK DesiredAccess,
IN ULONG Attributes,
IN ULONG Options):NTSTATUS
' 

DUPLICATE_CLOSE_SOURCE		equ 1
DUPLICATE_SAME_ACCESS		equ 2
;DUPLICATE_SAME_ATTRIBUTES	equ ?

ZwMakeTemporaryObject proto Handle:HANDLE
comment '
ZwMakeTemporaryObject(
IN HANDLE Handle):NTSTATUS
' 

ZwClose proto Handle:HANDLE
comment '
ZwClose(
IN HANDLE Handle):NTSTATUS
' 

ZwQuerySecurityObject proto Handle:HANDLE, SecurityInformation:ULONG, SecurityDescriptor:PSECURITY_DESCRIPTOR, SecurityDescriptorLength:ULONG, ReturnLength:PULONG
comment '
ZwQuerySecurityObject(
IN HANDLE Handle,
IN SECURITY_INFORMATION SecurityInformation,
OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
IN ULONG SecurityDescriptorLength,
OUT PULONG ReturnLength):NTSTATUS
' 

;SecurityInformation
OWNER_SECURITY_INFORMATION		equ 01
GROUP_SECURITY_INFORMATION		equ 02
DACL_SECURITY_INFORMATION		equ 04
SACL_SECURITY_INFORMATION		equ 08

ZwSetSecurityObject proto SectionHandle:HANDLE, SecurityInformation:ULONG, SecurityDescriptor:PSECURITY_DESCRIPTOR
comment '
ZwSetSecurityObject(
IN HANDLE Handle,
IN SECURITY_INFORMATION SecurityInformation,
IN PSECURITY_DESCRIPTOR SecurityDescriptor):NTSTATUS
' 

ZwCreateDirectoryObject proto DirectoryHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwCreateDirectoryObject(
OUT PHANDLE DirectoryHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

DIRECTORY_QUERY		equ 01h	;Query access
DIRECTORY_TRAVERSE		equ 02h	;Name lookup access
DIRECTORY_CREATE_OBJECT	equ 04h	;Name creation access
DIRECTORY_CREATE_SUBDIRECTORY		equ 08h	; Subdirectory creation access
DIRECTORY_ALL_ACCESS	equ STANDARD_RIGHTS_REQUIRED or 0Fh

ZwOpenDirectoryObject proto DirectoryHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwOpenDirectoryObject(
OUT PHANDLE DirectoryHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

ZwQueryDirectoryObject proto DirectoryHandle:HANDLE, Buffer:PVOID, BufferLength:ULONG, ReturnSingleEntry:BOOLEAN, RestartScan:BOOLEAN, Context:PULONG, ReturnLength:PULONG
comment '
ZwQueryDirectoryObject(
IN HANDLE DirectoryHandle,
OUT PVOID Buffer,
IN ULONG BufferLength,
IN BOOLEAN ReturnSingleEntry,
IN BOOLEAN RestartScan,
IN OUT PULONG Context,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
' 

ZwCreateSymbolicLinkObject proto SymbolicLinkHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES, TargetName:PUNICODE_STRING
comment '
ZwCreateSymbolicLinkObject(
OUT PHANDLE SymbolicLinkHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN PUNICODE_STRING TargetName):NTSTATUS
' 

;DesiredAccess
SYMBOLIC_LINK_QUERY		equ 0001h
SYMBOLIC_LINK_ALL_ACCESS	equ STANDARD_RIGHTS_REQUIRED or 01h

ZwOpenSymbolicLinkObject proto SymbolicLinkHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwOpenSymbolicLinkObject(
OUT PHANDLE SymbolicLinkHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

ZwQuerySymbolicLinkObject proto SymbolicLinkHandle:HANDLE, TargetName:PUNICODE_STRING, ReturnLength:PULONG
comment '
ZwQuerySymbolicLinkObject(
IN HANDLE SymbolicLinkHandle,
IN OUT PUNICODE_STRING TargetName,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
' 

;---------------------------------------------------- Virtual Memory -------------------------------------------------
MEM_PHYSICAL	equ 400000h

ZwAllocateVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, ZeroBits:ULONG, AllocationSize:PULONG, AllocationType:ULONG, Protect:ULONG
comment '
ZwAllocateVirtualMemory (
IN HANDLE ProcessHandle,
IN OUT PVOID *BaseAddress,
IN ULONG ZeroBits,
IN OUT PULONG AllocationSize,
IN ULONG AllocationType,		;MEM_
IN ULONG Protect):NTSTATUS	;PAGE_
Returns STATUS_SUCCESS or an error status, such as STATUS_NO_MEMORY, STATUS_
CONFLICTING_ADDRESSES, STATUS_ALREADY_COMMITTED, STATUS_INVALID_PAGE_PROTECTION, or STATUS_PROCESS_IS_TERMINATING.
' 

ZwFreeVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, FreeSize:PULONG, FreeType:ULONG
comment '
ZwFreeVirtualMemory(
IN HANDLE ProcessHandle,
IN OUT PVOID *BaseAddress,
IN OUT PULONG FreeSize,
IN ULONG FreeType):NTSTATUS		;MEM_DECOMMIT/MEM_RELEASE
Returns STATUS_SUCCESS or an error status, such as STATUS_UNABLE_TO_FREE_VM,
STATUS_UNABLE_TO_DELETE_SECTION, STATUS_FREE_VM_NOT_AT_BASE, STATUS_MEMORY_NOT_ALLOCATED, or STATUS_PROCESS_IS_TERMINATING.
' 

ZwQueryVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, MemoryInformationClass:ULONG, MemoryInformation:PVOID, MemoryInformationLength:ULONG, ReturnLength:PULONG
comment '
ZwQueryVirtualMemory(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress,
IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
OUT PVOID MemoryInformation,
IN ULONG MemoryInformationLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_INFO_CLASS,
STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_ADDRESS, STATUS_FILE_INVALID, or STATUS_PROCESS_IS_TERMINATING.
' 

;enum MEMORY_INFORMATION_CLASS
MemoryBasicInformation		equ 0
MemoryWorkingSetList		equ 1
MemorySectionName			equ 2
MemoryBasicVlmInformation	equ 3

MEMORY_BASIC_INFORMATION struct	;Information Class 0
BaseAddress		PVOID ?
AllocationBase		PVOID ?
AllocationProtect	ULONG ?
RegionSize		ULONG ?
State			ULONG ?
Protect			ULONG ?
_Type			ULONG ?
MEMORY_BASIC_INFORMATION ends
PMEMORY_BASIC_INFORMATION typedef PTR MEMORY_BASIC_INFORMATION

comment '
AllocationProtect:
PAGE_NOACCESS
PAGE_READONLY
PAGE_READWRITE
PAGE_EXECUTE
PAGE_EXECUTE_READ
PAGE_EXECUTE_READWRITE

State:
MEM_COMMIT	;Memory is reserved and committed
MEM_RESERVE 	;Memory is reserved but not committed
MEM_FREE 		;Memory is free

_Type:
MEM_PRIVATE 	;Memory is private
MEM_MAPPED 	;Memory is shareable and mapped from a data section
MEM_IMAGE 	;Memory is shareable and mapped from an image section
' 

MEMORY_WORKING_SET_LIST struct	;Information Class 1
NumberOfPages		ULONG ?
WorkingSetList		ULONG 1 DUP (?)
MEMORY_WORKING_SET_LIST ends
PMEMORY_WORKING_SET_LIST typedef PTR MEMORY_WORKING_SET_LIST

WSLE_PAGE_READONLY			equ 001h	;Page is read only
WSLE_PAGE_EXECUTE			equ 002h	;Page is executable
WSLE_PAGE_EXECUTE_READ		equ 003h
WSLE_PAGE_READWRITE			equ 004h	;Page is writeable
WSLE_PAGE_WRITECOPY			equ 005h	;Page should be copied on write
WSLE_PAGE_EXECUTE_READWRITE	equ 006h
WSLE_PAGE_EXECUTE_WRITECOPY	equ 007h	;Page should be copied on write
WSLE_PAGE_SHARE_COUNT_MASK	equ 0E0h
WSLE_PAGE_SHAREABLE			equ 100h	;Page is shareable

MEMORY_SECTION_NAME struct	;Information Class 2
SectionFileName	UNICODE_STRING <>
MEMORY_SECTION_NAME ends
PMEMORY_SECTION_NAME typedef PTR MEMORY_SECTION_NAME

ZwLockVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, LockSize:PULONG, LockType:ULONG
comment '
ZwLockVirtualMemory(
IN HANDLE ProcessHandle,
IN OUT PVOID *BaseAddress,
IN OUT PULONG LockSize,
IN ULONG LockType):NTSTATUS
Returns STATUS_SUCCESS, STATUS_WAS_LOCKED or an error status, such as
STATUS_PRIVILEGE_NOT_HELD, STATUS_WORKING_SET_QUOTA, or STATUS_PROCESS_IS_TERMINATING.
' 

LOCK_VM_IN_WSL	equ 01	;Lock page in working set list
LOCK_VM_IN_RAM	equ 02	;Lock page in physical memory

ZwUnlockVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, LockSize:PULONG, LockType:ULONG
comment '
ZwUnlockVirtualMemory(
IN HANDLE ProcessHandle,
IN OUT PVOID *BaseAddress,
IN OUT PULONG LockSize,
IN ULONG LockType):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_PRIVILEGE_NOT_HELD, STATUS_NOT_LOCKED, or STATUS_PROCESS_IS_TERMINATING.
' 

ZwReadVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, Buffer:PVOID, BufferLength:ULONG, ReturnLength:PULONG
comment '
ZwReadVirtualMemory(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress,
OUT PVOID Buffer,
IN ULONG BufferLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_VIOLATION or STATUS_PROCESS_IS_TERMINATING.
' 

ZwWriteVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, Buffer:PVOID, BufferLength:ULONG, ReturnLength:PULONG
comment '
ZwWriteVirtualMemory(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress,
IN PVOID Buffer,
IN ULONG BufferLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_VIOLATION or STATUS_PROCESS_IS_TERMINATING.
' 

ZwProtectVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, ProtectSize:PULONG, NewProtect:ULONG, OldProtect:PULONG
comment '
ZwProtectVirtualMemory(
IN HANDLE ProcessHandle,
IN OUT PVOID *BaseAddress,
IN OUT PULONG ProtectSize,
IN ULONG NewProtect,
OUT PULONG OldProtect):NTSTATUS

PAGE_NOACCESS
PAGE_READONLY
PAGE_READWRITE
PAGE_WRITECOPY
PAGE_EXECUTE
PAGE_EXECUTE_READ
PAGE_EXECUTE_READWRITE
PAGE_EXECUTE_WRITECOPY

Returns STATUS_SUCCESS or an error status, such as STATUS_NOT_COMMITTED or STATUS_PROCESS_IS_TERMINATING.
'

ZwFlushVirtualMemory	proto ProcessHandle:HANDLE, BaseAddress:PVOID, FlushSize:PULONG, IoStatusBlock:PIO_STATUS_BLOCK
comment '
ZwFlushVirtualMemory(
IN HANDLE ProcessHandle,
IN OUT PVOID *BaseAddress,
IN OUT PULONG FlushSize,
OUT PIO_STATUS_BLOCK IoStatusBlock):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_NOT_MAPPED_DATA or STATUS_PROCESS_IS_TERMINATING.
'

ZwAllocateUserPhysicalPages	proto ProcessHandle:HANDLE, NumberOfPages:PULONG, PageFrameNumbers:PULONG
comment '
ZwAllocateUserPhysicalPages(
IN HANDLE ProcessHandle,
IN PULONG NumberOfPages,
OUT PULONG PageFrameNumbers):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_PRIVILEGE_NOT_HELD or STATUS_PROCESS_IS_TERMINATING.
'

ZwFreeUserPhysicalPages	proto ProcessHandle:HANDLE, NumberOfPages:PULONG, PageFrameNumbers:PULONG
comment '
ZwFreeUserPhysicalPages(
IN HANDLE ProcessHandle,
IN OUT PULONG NumberOfPages,
IN PULONG PageFrameNumbers):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_CONFLICTING_ADDRESSES or STATUS_PROCESS_IS_TERMINATING.
'

ZwMapUserPhysicalPages	proto ProcessHandle:HANDLE, NumberOfPages:PULONG, PageFrameNumbers:PULONG
comment '
ZwMapUserPhysicalPages(
IN PVOID BaseAddress,
IN PULONG NumberOfPages,
IN PULONG PageFrameNumbe):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_CONFLICTING_ADDRESSES or STATUS_PROCESS_IS_TERMINATING.
'

ZwMapUserPhysicalPagesScatter	proto BaseAddresses:PVOID, NumberOfPages:PULONG, PageFrameNumbers:PULONG
comment '
ZwMapUserPhysicalPagesScatter(
IN PVOID *BaseAddresses,
IN PULONG NumberOfPages,
IN PULONG PageFrameNumbers):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_CONFLICTING_ADDRESSES or STATUS_PROCESS_IS_TERMINATING.
'

ZwGetWriteWatch	proto ProcessHandle:HANDLE, Flags:ULONG, BaseAddress:PVOID, RegionSize:ULONG, Buffer:PULONG, BufferEntries:PULONG, Granularity:PULONG
comment '
ZwGetWriteWatch(
IN HANDLE ProcessHandle,
IN ULONG Flags,
IN PVOID BaseAddress ,
IN ULONG RegionSize,
OUT PULONG Buffer,
IN OUT PULONG BufferEntries,
OUT PULONG Granularity):NTSTATUS

WRITE_WATCH_RESET_FLAG	equ 01h	;Reset the write watch information

Returns STATUS_SUCCESS or an error status, such as STATUS_PROCESS_IS_TERMINATING, STATUS_INVALID_PARAMETER_1, STATUS_INVALID_PARAMETER_2,
STATUS_INVALID_PARAMETER_3, or STATUS_INVALID_PARAMETER_5.
'

ZwResetWriteWatch	proto ProcessHandle:HANDLE, BaseAddress:PVOID, RegionSize:ULONG
comment '
ZwResetWriteWatch(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress,
IN ULONG RegionSize):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_PROCESS_IS_TERMINATING, STATUS_INVALID_PARAMETER_1,
STATUS_INVALID_PARAMETER_2, or STATUS_INVALID_PARAMETER_3
'

ProbeForWrite	proto Address:PVOID, _Length:ULONG, Alignment:ULONG
comment '
ProbeForWrite (
    IN PVOID Address,
    IN ULONG Length,
    IN ULONG Alignment):VOID
'

RtlFillMemory proto Destination:PVOID, _Length:ULONG, Fill:UCHAR
comment '
RtlFillMemory (
OUT PVOID Destination,
IN ULONG Length,
IN UCHAR Fill):VOID
'

RtlFillMemoryUlong	proto Destination:PVOID, _Length:ULONG, Fill:ULONG
comment '
RtlFillMemoryUlong(
IN PVOID Destination,
IN ULONG Length,
IN ULONG Fill):VOID
'

RtlCompareMemory proto Source1:PVOID, Source2:PVOID, _Length:ULONG
comment '
RtlCompareMemory (
IN PVOID Source1,
IN PVOID Source2,
IN ULONG Length):ULONG
'

RtlCompareMemoryUlong proto Source1:PVOID, Source2:PVOID, _Length:ULONG
comment '
RtlCompareMemory (
IN PVOID Source1,
IN PVOID Source2,
IN ULONG Length):ULONG
'

RtlMoveMemory proto Destination:PVOID, Source:PVOID, _Length:ULONG
comment '
RtlMoveMemory (
OUT PVOID Destination,
IN PVOID Source,
IN ULONG Length):VOID
'

RtlZeroMemory proto Destination:PVOID, _Length:ULONG
comment '
RtlZeroMemory (
OUT PVOID Destination,
IN ULONG Length):VOID
'

COMPRESSION_FORMAT_NONE		equ 0
COMPRESSION_FORMAT_DEFAULT	equ 1
COMPRESSION_FORMAT_LZNT1		equ 2

COMPRESSION_ENGINE_STANDARD	equ 0
COMPRESSION_ENGINE_MAXIMUM	equ 100H
COMPRESSION_ENGINE_HIBER		equ 200H

; Compressed Data Information structure.
COMPRESSED_DATA_INFO struct
CompressionFormatAndEngine	USHORT ?
CompressionUnitShift	UCHAR ?
ChunkShift			UCHAR ?
ClusterShift			UCHAR ?
Reserved				UCHAR ?
NumberOfChunks			USHORT ?
CompressedChunkSizes	ULONG 1 DUP (?)
COMPRESSED_DATA_INFO ends
PCOMPRESSED_DATA_INFO typedef ptr COMPRESSED_DATA_INFO

RtlCompressBuffer	proto CompressionFormatAndEngine:USHORT, UncompressedBuffer:PUCHAR, UncompressedBufferSize:ULONG, CompressedBuffer:PUCHAR, 
CompressedBufferSize:ULONG, UncompressedChunkSize:ULONG, FinalCompressedSize:PULONG, WorkSpace:PVOID
comment '
RtlCompressBuffer(
IN USHORT   CompressionFormatAndEngine,
IN PUCHAR   UncompressedBuffer,
IN ULONG    UncompressedBufferSize,
OUT PUCHAR  CompressedBuffer,
IN ULONG    CompressedBufferSize,
IN ULONG    UncompressedChunkSize,
OUT PULONG  FinalCompressedSize,
IN PVOID    WorkSpace):NTSTATUS
' 

RtlDecompressBuffer	proto CompressionFormat:USHORT,UncompressedBuffer:PUCHAR,UncompressedBufferSize:ULONG,
CompressedBuffer:PUCHAR,CompressedBufferSize:ULONG,FinalUncompressedSize:PULONG
comment '
RtlDecompressBuffer (
IN USHORT   CompressionFormat,
OUT PUCHAR  UncompressedBuffer,
IN ULONG    UncompressedBufferSize,
IN PUCHAR   CompressedBuffer,
IN ULONG    CompressedBufferSize,
OUT PULONG  FinalUncompressedSize):NTSTATUS
'

ZwFlushInstructionCache	proto ProcessHandle:HANDLE, BaseAddress:PVOID, FlushSize:ULONG
comment '
ZwFlushInstructionCache(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress OPTIONAL,
IN ULONG FlushSize):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
'

RtlCreateHeap proto Flags:ULONG, Base:PVOID, Reserve:ULONG, Commit:ULONG, Lock_:ULONG, RtlHeapParams:PVOID
comment '
RtlCreateHeap(
IN ULONG Flags,
IN PVOID Base,
IN ULONG Reserve, 
IN ULONG Commit, 
IN ULONG Lock, 
IN PVOID RtlHeapParams):HANDLE
' 

RtlAllocateHeap proto HeapHandle:HANDLE, Flags:ULONG, _Size:ULONG
comment '
RtlAllocateHeap(
IN HANDLE  HeapHandle,
IN ULONG   Flags,	;HEAP_
IN ULONG   Size):PVOID
' 

RtlFreeHeap proto HeapHandle:HANDLE, Flags:ULONG, Address:PVOID
comment '
RtlFreeHeap(
IN HANDLE HeapHandle,
IN ULONG Flags,
IN PVOID Address	;адрес возвращённый RtlAllocateHeap
):BOOLEAN
' 

RtlDestroyHeap	proto HeapHandle:HANDLE
comment '
RtlDestroyHeap (
IN HANDLE  HeapHandle):NTSTATUS
' 

RtlEnumProcessHeaps proto CallBack:PVOID, Parameter1:ULONG
comment '
RtlEnumProcessHeaps(
IN PVOID CallBack,
IN ULONG Parameter):NTSTATUS	;Возвращается значение возвращённое из CallBack

CallBack proto HeapHandle:HANDLE, Parameter1:ULONG 
Если возвращается значение меньше нуля(NTSTATUS), то перечисление прекращается.
' 

;enum _HEAP_INFORMATION_CLASS {
HeapCompatibilityInformation	equ 0

RtlSetHeapInformation proto HeapHandle:HANDLE, HeapInformationClass:ULONG, HeapInformation:PVOID, HeapInformationLength:SIZE_T
comment '
RtlSetHeapInformation(
IN PVOID HeapHandle,
IN HEAP_INFORMATION_CLASS HeapInformationClass,
IN PVOID HeapInformation OPTIONAL,
IN SIZE_T HeapInformationLength OPTIONAL):NTSTATUS'

RtlQueryHeapInformation proto HeapHandle:HANDLE, HeapInformationClass:ULONG, HeapInformation:PVOID, HeapInformationLength:SIZE_T, ReturnLength:PSIZE_T
comment '
RtlQueryHeapInformation(
IN PVOID HeapHandle,
IN HEAP_INFORMATION_CLASS HeapInformationClass,
OUT PVOID HeapInformation OPTIONAL,
IN SIZE_T HeapInformationLength OPTIONAL,
OUT PSIZE_T ReturnLength OPTIONAL):NTSTATUS'
 
HEAP_NO_SERIALIZE			equ 00000001h     
HEAP_GROWABLE				equ 00000002h
HEAP_GENERATE_EXCEPTIONS		equ 00000004h
HEAP_ZERO_MEMORY			equ 00000008h
HEAP_REALLOC_IN_PLACE_ONLY	equ 00000010h
HEAP_TAIL_CHECKING_ENABLED	equ 00000020h
HEAP_FREE_CHECKING_ENABLED	equ 00000040h
HEAP_DISABLE_COALESCE_ON_FREE	equ 00000080h
HEAP_CREATE_ALIGN_16		equ 00010000h
HEAP_CREATE_ENABLE_TRACING	equ 00020000h
HEAP_CREATE_ENABLE_EXECUTE	equ 00040000h
HEAP_MAXIMUM_TAG			equ 0FFFh
HEAP_PSEUDO_TAG_FLAG		equ 8000h
HEAP_TAG_SHIFT				equ 18

RtlLockHeap proto HeapHandle:PVOID
comment '
RtlLockHeap(
IN PVOID HeapHandle):BOOLEAN'

RtlUnlockHeap proto HeapHandle:PVOID
comment '
RtlUnlockHeap(
IN PVOID HeapHandle):BOOLEAN'

RtlReAllocateHeap proto HeapHandle:PVOID, Flags:ULONG, BaseAddress:PVOID, _Size:SIZE_T
comment '
RtlReAllocateHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN PVOID BaseAddress,
IN SIZE_T Size):PVOID'

RtlGetUserInfoHeap proto HeapHandle:PVOID, Flags:ULONG, BaseAddress:PVOID, UserValue:PVOID, UserFlags:PULONG
comment '
RtlGetUserInfoHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN PVOID BaseAddress,
OUT PVOID *UserValue OPTIONAL,
OUT PULONG UserFlags OPTIONAL):BOOLEAN'

RtlSetUserValueHeap proto HeapHandle:PVOID, Flags:ULONG, BaseAddress:PVOID, UserValue:PVOID
comment '
RtlSetUserValueHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN PVOID BaseAddress,
IN PVOID UserValue):BOOLEAN'

RtlSetUserFlagsHeap proto HeapHandle:PVOID, Flags:ULONG, BaseAddress:PVOID, UserFlagsReset:ULONG, UserFlagsSet:ULONG
comment '
RtlSetUserFlagsHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN PVOID BaseAddress,
IN ULONG UserFlagsReset,
IN ULONG UserFlagsSet):BOOLEAN'

RTL_PERTHREAD_CURDIR struct
CurrentDirectories	PRTL_DRIVE_LETTER_CURDIR ?
ImageName			PUNICODE_STRING ?
Environment		PVOID ?
RTL_PERTHREAD_CURDIR ends
PRTL_PERTHREAD_CURDIR typedef ptr RTL_PERTHREAD_CURDIR

RTL_HEAP_TAG_INFO struct
NumberOfAllocations		ULONG ?
NumberOfFrees			ULONG ?
BytesAllocated			SIZE_T ?
RTL_HEAP_TAG_INFO ends
PRTL_HEAP_TAG_INFO typedef ptr RTL_HEAP_TAG_INFO

RtlCreateTagHeap proto HeapHandle:PVOID, Flags:ULONG, TagPrefix:PWSTR, TagNames:PWSTR
comment '
RtlCreateTagHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN PWSTR TagPrefix OPTIONAL,
IN PWSTR TagNames):ULONG'

RtlQueryTagHeap proto HeapHandle:PVOID, Flags:ULONG, TagIndex:USHORT, ResetCounters:BOOLEAN, TagInfo:PRTL_HEAP_TAG_INFO
comment '
RtlQueryTagHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN USHORT TagIndex,
IN BOOLEAN ResetCounters,
OUT PRTL_HEAP_TAG_INFO TagInfo OPTIONAL):PWSTR'

RtlExtendHeap proto HeapHandle:PVOID, Flags:ULONG, Base:PVOID, _Size:SIZE_T
comment '
RtlExtendHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN PVOID Base,
IN SIZE_T Size):NTSTATUS'

RtlCompactHeap proto HeapHandle:HANDLE, Flags:ULONG
comment '
RtlCompactHeap(
IN PVOID HeapHandle,
IN ULONG Flags):SIZE_T'

RtlValidateHeap proto HeapHandle:HANDLE, Flags:ULONG, BaseAddress:PVOID
comment '
RtlValidateHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN PVOID BaseAddress):BOOLEAN'

RtlValidateProcessHeaps proto
comment '
RtlValidateProcessHeaps():VOID'

RtlGetProcessHeaps proto NumberOfHeaps:ULONG, ProcessHeaps:PVOID
comment '
RtlGetProcessHeaps(
ULONG NumberOfHeaps,
PVOID *ProcessHeaps):ULONG'


;typedef
;NTSTATUS (NTAPI * PRTL_ENUM_HEAPS_ROUTINE)(
;    PVOID HeapHandle,
;    PVOID Parameter

RTL_HEAP_USAGE_ENTRY struct
;Next				PVOID ?
Address				PVOID ?
_Size				SIZE_T ?
AllocatorBackTraceIndex	USHORT ?
TagIndex				USHORT ?
RTL_HEAP_USAGE_ENTRY ends
PRTL_HEAP_USAGE_ENTRY typedef ptr RTL_HEAP_USAGE_ENTRY

RTL_HEAP_USAGE struct
_Length				ULONG ?
BytesAllocated			SIZE_T ?
BytesCommitted			SIZE_T ?
BytesReserved			SIZE_T ?
BytesReservedMaximum	SIZE_T ?
Entries				PRTL_HEAP_USAGE_ENTRY ?
AddedEntries			PRTL_HEAP_USAGE_ENTRY ?
RemovedEntries			PRTL_HEAP_USAGE_ENTRY ?
Reserved				ULONG_PTR 8 DUP (?)
RTL_HEAP_USAGE ends
PRTL_HEAP_USAGE typedef ptr RTL_HEAP_USAGE

HEAP_USAGE_ALLOCATED_BLOCKS 	equ HEAP_REALLOC_IN_PLACE_ONLY
HEAP_USAGE_FREE_BUFFER		equ HEAP_ZERO_MEMORY

RtlUsageHeap proto HeapHandle:PVOID, Flags:ULONG, Usage:PRTL_HEAP_USAGE
comment '
RtlUsageHeap(
IN PVOID HeapHandle,
IN ULONG Flags,
IN OUT PRTL_HEAP_USAGE Usage):NTSTATUS'

RTL_HEAP_WALK_ENTRY struct
DataAddress		PVOID ?
DataSize			SIZE_T ?
OverheadBytes		UCHAR ?
SegmentIndex		UCHAR ?
Flags			USHORT ?
Settable            SIZE_T ?
TagIndex            USHORT ?
AllocatorBackTraceIndex	USHORT ?
Reserved            ULONG 2 DUP (?)
CommittedSize		ULONG ?
UnCommittedSize	ULONG ?
FirstEntry		PVOID ?
LastEntry			PVOID ?
RTL_HEAP_WALK_ENTRY ends
PRTL_HEAP_WALK_ENTRY typedef ptr RTL_HEAP_WALK_ENTRY

RtlWalkHeap proto HeapHandle:PVOID, Entry:PRTL_HEAP_WALK_ENTRY
comment '
RtlWalkHeap(
IN PVOID HeapHandle,
IN OUT PRTL_HEAP_WALK_ENTRY Entry):NTSTATUS'

RTL_HEAP_ENTRY struct
_Size			SIZE_T ?
Flags			USHORT ?
AllocatorBackTraceIndex	USHORT ?
Settable			SIZE_T ?
Tag				ULONG ?
CommittedSize		SIZE_T ?
FirstBlock		PVOID ?
RTL_HEAP_ENTRY ends
PRTL_HEAP_ENTRY typedef ptr RTL_HEAP_ENTRY

RTL_HEAP_BUSY						equ 1h
RTL_HEAP_SEGMENT				equ 2h
RTL_HEAP_SETTABLE_VALUE		equ 10h
RTL_HEAP_SETTABLE_FLAG1		equ 20h
RTL_HEAP_SETTABLE_FLAG2		equ 40h
RTL_HEAP_SETTABLE_FLAG3		equ 80h
RTL_HEAP_SETTABLE_FLAGS		equ 0E0h
RTL_HEAP_UNCOMMITTED_RANGE		equ 100h
RTL_HEAP_PROTECTED_ENTRY		equ 200h

RTL_HEAP_TAG struct
NumberOfAllocations	ULONG ?
NumberOfFrees		ULONG ?
BytesAllocated		SIZE_T ?
TagIndex			USHORT ?
CreatorBackTraceIndex	USHORT ?
TagName			WCHAR 24 DUP (?)
RTL_HEAP_TAG ends
PRTL_HEAP_TAG typedef ptr RTL_HEAP_TAG

RTL_HEAP_INFORMATION struct
BaseAddress		PVOID ?
Flags			ULONG ?
EntryOverhead		USHORT ?
CreatorBackTraceIndex	USHORT ?
BytesAllocated		SIZE_T ?
BytesCommitted		SIZE_T ?
NumberOfTags		ULONG ?
NumberOfEntries	ULONG ?
NumberOfPseudoTags	ULONG ?
PseudoTagGranularity	ULONG ?
Reserved			ULONG 5 DUP (?)
Tags				PRTL_HEAP_TAG ?
Entries			PRTL_HEAP_ENTRY ?
RTL_HEAP_INFORMATION ends
PRTL_HEAP_INFORMATION typedef ptr RTL_HEAP_INFORMATION

RTL_PROCESS_HEAPS struct
NumberOfHeaps		ULONG ?
Heaps			RTL_HEAP_INFORMATION 1 DUP (<>)
RTL_PROCESS_HEAPS ends
PRTL_PROCESS_HEAPS typedef ptr RTL_PROCESS_HEAPS
;----------------------------------------------------- Sections ----------------------------------------------------
ZwCreateSection proto SectionHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES, SectionSize:PLARGE_INTEGER, Protect:ULONG, Attributes:ULONG, FileHandle:HANDLE
comment '
ZwCreateSection(
OUT PHANDLE SectionHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
IN PLARGE_INTEGER SectionSize OPTIONAL,
IN ULONG Protect,	;PAGE_
IN ULONG Attributes,
IN HANDLE FileHandle):NTSTATUS
' 

;DesiredAccess
SECTION_QUERY                        equ 1h
SECTION_MAP_WRITE                    equ 2h
SECTION_MAP_READ                     equ 4h
SECTION_MAP_EXECUTE                  equ 8h
SECTION_EXTEND_SIZE                  equ 10h
SECTION_ALL_ACCESS                   equ STANDARD_RIGHTS_REQUIRED OR SECTION_QUERY OR SECTION_MAP_WRITE OR SECTION_MAP_READ OR SECTION_MAP_EXECUTE OR SECTION_EXTEND_SIZE

;Attributes
SEC_BASED		equ 00200000h	;Map section at same address in each process
SEC_NO_CHANGE	equ 00400000h	;Disable changes to protection of pages
SEC_IMAGE		equ 01000000h	;Map section as an image
SEC_VLM		equ 02000000h	;Map section in VLM region
SEC_RESERVE	equ 04000000h	;Reserve without allocating pagefile storage
SEC_COMMIT	equ 08000000h	;Commit pages; the default behavior
SEC_NOCACHE	equ 10000000h	;Mark pages as non-cacheable

ZwOpenSection proto SectionHandle:HANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwOpenSection(
OUT PHANDLE SectionHandle,
IN ACCESS_MASK DesiredAccess,		;SECTION_
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

ZwQuerySection proto SectionHandle:HANDLE, SectionInformationClass:ULONG, SectionInformation:PVOID, SectionInformationLength:ULONG, ResultLength:PULONG
comment '
ZwQuerySection(
IN HANDLE SectionHandle,
IN SECTION_INFORMATION_CLASS SectionInformationClass,
OUT PVOID SectionInformation,
IN ULONG SectionInformationLength,
OUT PULONG ResultLength OPTIONAL):NTSTATUS
' 

;enum SECTION_INFORMATION_CLASS
SectionBasicInformation	equ 0
SectionImageInformation	equ 1

SECTION_BASIC_INFORMATION struct
BaseAddress	PVOID ?
Attributes	ULONG ?
_Size		LARGE_INTEGER <>
SECTION_BASIC_INFORMATION ends
PSECTION_BASIC_INFORMATION typedef ptr SECTION_BASIC_INFORMATION

;Attributes
SEC_BASED		equ 00200000h	;Section should be mapped at same address in each process
SEC_NO_CHANGE	equ 00400000h	;Changes to protection of section pages are disabled
SEC_FILE		equ 00800000h	;Section is backed by a file
SEC_IMAGE		equ 01000000h	;Section is mapped as an image
SEC_VLM		equ 02000000h	;Section maps VLM
SEC_RESERVE	equ 04000000h	;Section pages are reserved
SEC_COMMIT	equ 08000000h	;Section pages are committed
SEC_NOCACHE	equ 10000000h	;Section pages are non-cacheable

ZwExtendSection proto SectionHandle:HANDLE, SectionSize:PLARGE_INTEGER
comment '
ZwExtendSection(
IN HANDLE SectionHandle,
IN PLARGE_INTEGER SectionSize):NTSTATUS
' 

ZwMapViewOfSection proto SectionHandle:HANDLE, ProcessHandle:HANDLE, BaseAddress:PVOID, ZeroBits:ULONG, CommitSize:ULONG,
SectionOffset:PLARGE_INTEGER, ViewSize:PULONG, InheritDisposition:ULONG, AllocationType:ULONG, Protect:ULONG
comment '
ZwMapViewOfSection(
IN HANDLE SectionHandle,
IN HANDLE ProcessHandle,
IN OUT PVOID *BaseAddress,
IN ULONG ZeroBits,
IN ULONG CommitSize,
IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
IN OUT PULONG ViewSize,
IN SECTION_INHERIT InheritDisposition,
IN ULONG AllocationType,
IN ULONG Protect):NTSTATUS
' 

;InheritDisposition
ViewShare	equ 1
ViewUnmap	equ 2

;AllocationType
AT_EXTENDABLE_FILE		equ 00002000h	;Allow view to exceed section size
MEM_TOP_DOWN			equ 00100000h	;Allocate at highest possible address
SEC_NO_CHANGE			equ 00400000h	;Disable changes to protection of pages
AT_RESERVED			equ 20000000h	;Valid but ignored
AT_ROUND_TO_PAGE		equ 40000000h	;Adjust address and size if necessary


ZwUnmapViewOfSection proto ProcessHandle:HANDLE, BaseAddress:PVOID
comment '
ZwUnmapViewOfSection(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress):NTSTATUS'

ZwAreMappedFilesTheSame proto Address1:PVOID, Address2:PVOID
comment '
ZwAreMappedFilesTheSame(
IN PVOID Address1,
IN PVOID Address2):NTSTATUS'

SECTION_IMAGE_INFORMATION struct
TransferAddress		PVOID ?
ZeroBits				ULONG ?
MaximumStackSize		ULONG ?
CommittedStackSize		ULONG ?
SubSystemType			ULONG ?
; SubSystemVersion		ULONG ? ->
SubSystemMinorVersion	USHORT ?
SubSystemMajorVersion	USHORT ?
GpValue				ULONG ?
ImageCharacteristics	WORD ?
; DllCharacteristics		WORD ?
Machine				WORD ?
ImageContainsCode		WORD ?
ImageFlags			WORD ?
ImageDynamicallyRelocated	ULONG ?
LoaderFlags			ULONG ?
CheckSum				ULONG ?
SECTION_IMAGE_INFORMATION ends
PSECTION_IMAGE_INFORMATION typedef ptr SECTION_IMAGE_INFORMATION

RTL_USER_PROCESS_INFORMATION struct
_Length			ULONG <>
Process			HANDLE <>
Thread			HANDLE <>
ClientId			CLIENT_ID <>
ImageInformation	SECTION_IMAGE_INFORMATION <>
RTL_USER_PROCESS_INFORMATION ends
PRTL_USER_PROCESS_INFORMATION typedef ptr RTL_USER_PROCESS_INFORMATION

;---------------------------------------------------- Threads ---------------------------------------------------------------
ZwCreateThread	proto ThreadHandle:PHANDLE, DesiredAccess:DWORD, ObjectAttributes:PVOID, ProcessHandle:HANDLE, ClientId:PVOID, ThreadContext:PVOID, UserStack:PVOID, CreateSuspended:BOOLEAN

comment '
ZwCreateThread(
OUT PHANDLE ThreadHandle,
IN ACCESS_MASK DesiredAccess,		;THREAD_
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN HANDLE ProcessHandle,
OUT PCLIENT_ID ClientId,
IN PCONTEXT ThreadContext,
IN PUSER_STACK UserStack,
IN BOOLEAN CreateSuspended):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_INVALID_HANDLE, or STATUS_PROCESS_IS_TERMINATING.

;DesiredAccess
;THREAD_TERMINATE 		;Terminate thread
THREAD_SUSPEND_RESUME 	;Suspend or resume thread
THREAD_ALERT 			;Alert thread
THREAD_GET_CONTEXT 		;Get thread context
THREAD_SET_CONTEXT 		;Set thread context
THREAD_SET_INFORMATION 	;Set thread information
THREAD_QUERY_INFORMATION ;Get thread information
THREAD_SET_THREAD_TOKEN 	;Set thread token
THREAD_IMPERSONATE 		;Allow thread to impersonate
THREAD_DIRECT_IMPERSONATION 	;Allow thread token to be impersonated
THREAD_ALL_ACCESS 		;All of the preceding + STANDARD_RIGHTS_ALL'

comment '
NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN ULONG InitialEip,
	IN ULONG InitialValueInStack OPTIONAL,
	IN ULONG ThreadState,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit OPTIONAL,
	IN ULONG SizeOfStackReserve OPTIONAL,
	OUT PCLIENT_ID ClientId)'

USER_STACK struct
FixedStackBase			PVOID ?	;0
FixedStackLimit		PVOID ?	;0
ExpandableStackBase		PVOID ?
ExpandableStackLimit	PVOID ?
ExpandableStackBottom	PVOID ?
USER_STACK ends
PUSER_STACK typedef ptr USER_STACK

ZwOpenThread	proto ThreadHandle:PHANDLE, DesiredAccess:DWORD, ObjectAttributes:PVOID, ClientId:PVOID
comment '
ZwOpenThread(
OUT PHANDLE ThreadHandle,
IN ACCESS_MASK DesiredAccess,		;THREAD_
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN PCLIENT_ID ClientId):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_OBJECT_NAME_NOT_FOUND, STATUS_INVALID_PARAMETER_MIX, or STATUS_INVALID_PARAMETER.
' 

ZwTerminateThread	proto ThreadHandle:HANDLE, ExitStatus:NTSTATUS
comment '
ZwTerminateThread(
IN HANDLE ThreadHandle OPTIONAL,
IN NTSTATUS ExitStatus):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_CANT_TERMINATE_SELF.
' 

ZwSuspendThread	proto ThreadHandle:HANDLE,PreviousSuspendCount:PULONG
comment '
ZwSuspendThread(
IN HANDLE ThreadHandle, 
OUT PULONG PreviousSuspendCount OPTIONAL):NTSTATUS	
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_INVALID_HANDLE, STATUS_SUSPEND_COUNT_EXCEEDED, or STATUS_THREAD_IS_TERMINATING.
' 

ZwResumeThread	proto ThreadHandle:HANDLE, PreviousSuspendCount:PULONG
comment '
ZwResumeThread(
IN HANDLE ThreadHandle, 
OUT PULONG PreviousSuspendCount OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED, or STATUS_INVALID_HANDLE.
' 

ZwGetContextThread	proto ThreadHandle:HANDLE, Context:PVOID
comment '
ZwGetContextThread(		;retrieves the execution context of a thread.
IN HANDLE ThreadHandle,			;A handle to a thread object.The handle must grant THREAD_GET_CONTEXT access.
OUT PCONTEXT Context):NTSTATUS	;Points to a caller-allocated buffer or variable that receives the thread context information.
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED, or STATUS_INVALID_HANDLE.
' 

ZwSetContextThread	proto ThreadHandle:HANDLE, Context:PVOID
comment '
ZwSetContextThread(		;sets the execution context of a thread.
IN HANDLE ThreadHandle,	;A handle to a thread object.The handle must grant THREAD_SET_CONTEXT access.
IN PCONTEXT Context):NTSTATUS		;Points to a caller-allocated buffer or variable that contains the thread context information.
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED, or STATUS_INVALID_HANDLE.
' 
   
ZwQueueApcThread	proto ThreadHandle:HANDLE, ApcRoutine:PVOID, ApcContext:PVOID, Argument1:PVOID, Argument2:PVOID
comment '
ZwQueueApcThread(
IN HANDLE ThreadHandle,
IN PKNORMAL_ROUTINE ApcRoutine,
IN PVOID ApcContext OPTIONAL,
IN PVOID Argument1 OPTIONAL,
IN PVOID Argument2 OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED, or
STATUS_INVALID_HANDLE.

VOID (NTAPI *PKNORMAL_ROUTINE)(PVOID ApcContext,PVOID Argument1, PVOID Argument2);
' 

ZwTestAlert	proto
comment '
ZwTestAlert():NTSTATUS
Returns STATUS_SUCCESS or STATUS_ALERTED.
' 

ZwAlertThread	proto ThreadHandle:HANDLE
comment '
ZwAlertThread(
IN HANDLE ThreadHandle):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED, or STATUS_INVALID_HANDLE.
' 

ZwAlertResumeThread	proto ThreadHandle:HANDLE, PreviousSuspendCount:PULONG
comment '
ZwAlertResumeThread(
IN HANDLE ThreadHandle,
OUT PULONG PreviousSuspendCount OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwRegisterThreadTerminatePort	proto PortHandle:HANDLE
comment '
ZwRegisterThreadTerminatePort(
IN HANDLE PortHandle):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE.
' 

ZwImpersonateThread	proto ThreadHandle:HANDLE, TargetThreadHandle:HANDLE, SecurityQos:PVOID
comment '
ZwImpersonateThread(
IN HANDLE ThreadHandle,
IN HANDLE TargetThreadHandle,
IN PSECURITY_QUALITY_OF_SERVICE SecurityQos):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwImpersonateAnonymousToken	proto ThreadHandle:HANDLE
comment '
ZwImpersonateAnonymousToken(
IN HANDLE ThreadHandle):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwQueryInformationThread	proto ThreadHandle:HANDLE, ThreadInformationClass:ULONG, ThreadInformation:PVOID, ThreadInformationLength:ULONG, ReturnLength:PULONG
comment '
ZwQueryInformationThread(
IN HANDLE ThreadHandle,
IN THREADINFOCLASS ThreadInformationClass,
OUT PVOID ThreadInformation,
IN ULONG ThreadInformationLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,STATUS_INVALID_HANDLE,
 STATUS_INVALID_INFO_CLASS, or STATUS_INFO_LENGTH_MISMATCH.
' comment

ZwSetInformationThread proto ThreadHandle:HANDLE, ThreadInformationClass:ULONG, ThreadInformation:PVOID, ThreadInformationLength:ULONG
comment '
ZwSetInformationThread(
IN HANDLE ThreadHandle,
IN THREADINFOCLASS ThreadInformationClass,
IN PVOID ThreadInformation,
IN ULONG ThreadInformationLength):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS,
STATUS_INFO_LENGTH_MISMATCH, or STATUS_PROCESS_IS_TERMINATING.
' 

; Thread Information Classes
; typedef enum _THREADINFOCLASS
    ThreadBasicInformation			equ 0
    ThreadTimes					equ 1
    ThreadPriority					equ 2
    ThreadBasePriority				equ 3
    ThreadAffinityMask				equ 4
    ThreadImpersonationToken			equ 5
    ThreadDescriptorTableEntry		equ 6
    ThreadEnableAlignmentFaultFixup	equ 7
    ThreadEventPair_Reusable			equ 8
    ThreadQuerySetWin32StartAddress	equ 9
    ThreadZeroTlsCell				equ 10
    ThreadPerformanceCount			equ 11
    ThreadAmILastThread				equ 12
    ThreadIdealProcessor				equ 13
    ThreadPriorityBoost				equ 14
    ThreadSetTlsArrayAddress			equ 15
    ThreadIsIoPending				equ 16
    ThreadHideFromDebugger			equ 17
    ThreadBreakOnTermination			equ 18
    ThreadSwitchLegacyState			equ 19
    ThreadIsTerminated				equ 20
    
;ThreadBasicInformation(Information Class 0)
THREAD_BASIC_INFORMATION struct
ExitStatus		NTSTATUS ?
TebBaseAddress		PTEB	 ?
ClientId			CLIENT_ID	<>
AffinityMask    	ULONG ?	;KAFFINITY
Priority    		LONG	 ?	;KPRIORITY
BasePriority    	LONG	 ?	;KPRIORITY
THREAD_BASIC_INFORMATION ends
PTHREAD_BASIC_INFORMATION typedef ptr THREAD_BASIC_INFORMATION

;ThreadTimes(Information Class 1)
;	KERNEL_USER_TIMES <>

;ThreadPriority(Information Class 2)
;	Priority	KPRIORITY ?

;ThreadBasePriority (Information Class 3)
;	BasePriority	LONG ?

;ThreadAffinityMask (Information Class 4)
;	AffinityMask	KAFFINITY ? 

;ThreadImpersonationToken (Information Class 5)
;	ImpersonationToken	HANDLE ? 

;LDTBits RECORD  rBaseHi:8, Granularity:1,Default_Big : 1,Reserved_0:1,Sys:1,LimitHi:4,Pres:1, Dpl:2, S_bit:1, Type1:4,rBaseMid:8
LDT_BITS struct
rBaseHi	BYTE ?
Misc1	WORD ?
rBaseMid	BYTE ?
LDT_BITS ends

LDT_BYTES STRUCT
  BaseMid  BYTE      ?
  Flags1   BYTE      ?
  BaseHi   WORD      ?
LDT_BYTES ENDS

LDT_ENTRY STRUCT
LimitLow	WORD ?
BaseLow	WORD ?
Bytes	LDT_BYTES <>
Bits		LDT_BITS <>
LDT_ENTRY ENDS

;ThreadDescriptorTableEntry (Information Class 6)
;	LdtEntry	LDT_ENTRY <>

;ThreadEnableAlignmentFaultFixup (Information Class 7)
;	EnableAlignmentFaultFixup	BOOLEAN ?

;ThreadEventPair (Information Class 8)
;	EventPair	HANDLE ?

;ThreadQuerySetWin32StartAddress (Information Class 9)
;	Win32StartAddress	PVOID ?

;ThreadZeroTlsCell (Information Class 10)
;	ZeroTlsCell	ULONG ?

;ThreadPerformanceCount (Information Class 11)
;	PerformanceCount	LARGE_INTEGER <> 

;ThreadAmILastThread (Information Class 12)
;	AmILastThread	ULONG ?

;ThreadIdealProcessor (Information Class 13)
;	IdealProcessor	ULONG ? 

;ThreadPriorityBoost (Information Class 14)
;	PriorityBoost	ULONG ? 
;This information class can be both queried and set.

;ThreadSetTlsArrayAddress (Information Class 15)
;	SetTlsArrayAddress	PVOID ? 

;ThreadIsIoPending (Information Class 16)
;	IsIoPending	ULONG ?

;ThreadHideFromDebugger (Information Class 17)

ZwContinue	proto Context:PVOID, TestAlert:BOOLEAN
comment '
ZwContinue(
IN PCONTEXT Context,
IN BOOLEAN TestAlert):NTSTATUS
' 

ZwDelayExecution	proto Alertable:BOOLEAN, Interval:PLARGE_INTEGER
comment '
ZwDelayExecution(
IN BOOLEAN Alertable,
IN PLARGE_INTEGER Interval):NTSTATUS
;Останавливает выполнение вызывающего потока
;Alertable:A boolean specifying whether the delay can be interrupted by the delivery of a user APC.
;Interval: x100ns
Returns STATUS_SUCCESS, STATUS_ALERTED, STATUS_USER_APC, or an error status.
' 

ZwYieldExecution	proto
comment '
ZwYieldExecution(
VOID):NTSTATUS
Returns STATUS_SUCCESS or STATUS_NO_YIELD_PERFORMED.
' 

ZwSetThreadExecutionState proto ExecutionState:ULONG, PreviousExecutionState:PULONG
comment '
ZwSetThreadExecutionState(
IN EXECUTION_STATE ExecutionState,
OUT PEXECUTION_STATE PreviousExecutionState):NTSTATUS
' 

;EXECUTION_STATE
ES_SYSTEM_REQUIRED		equ 00000001h
ES_DISPLAY_REQUIRED		equ 00000002h
ES_USER_PRESENT		equ 00000004h
ES_CONTINUOUS			equ 80000000h

RtlExitUserThread	proto ExitStatus:NTSTATUS
comment '
Завершение вызывающего потока
RtlExitUserThread(
IN NTSTATUS ExitStatus):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_CANT_TERMINATE_SELF.
' 

RtlCreateUserStack proto ProcessHandle:HANDLE, SizeOfStackReserve:ULONG, SizeOfStackCommit:ULONG, ZeroBits:ULONG, UserStack:PUSER_STACK
comment '
Создаёт стек потока(выделяет под него память)
RtlCreateUserStack(
IN HANDLE ProcessHandle,
IN ULONG SizeOfStackReserve OPTIONAL,
IN ULONG SizeOfStackCommit OPTIONAL,
IN ULONG ZeroBits,
OUT PUSER_STACK UserStack):NTSTATUS
' 

RtlFreeUserThreadStack proto ProcessHandle:HANDLE, ThreadHandle:HANDLE
comment '
Уничтожает стек потока(освобождает выделенную под стек память)
RtlFreeUserThreadStack(
IN HANDLE ProcessHandle,
IN HANDLE ThreadHandle):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_UNABLE_TO_FREE_VM,STATUS_UNABLE_TO_DELETE_SECTION, STATUS_FREE_VM_NOT_AT_BASE,
STATUS_MEMORY_NOT_ALLOCATED, or STATUS_PROCESS_IS_TERMINATING.	
' 

RtlCreateUserThread	proto ProcessHandle:HANDLE,SecurityDescriptor:PSECURITY_DESCRIPTOR,CreateSuspended:BOOLEAN,ZeroBits:ULONG,SizeOfStackReserve:ULONG,
SizeOfStackCommit:ULONG,InitialEip:ULONG,InitialValueInStack:ULONG,OutThreadHandle:PHANDLE,OutClientId:PCLIENT_ID
comment '
Создаёт поток
RtlCreateUserThread(
IN HANDLE ProcessHandle,
IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
IN BOOLEAN CreateSuspended,
IN ULONG StackZeroBits,
IN ULONG SizeOfStackReserve OPTIONAL,
IN ULONG SizeOfStackCommit OPTIONAL,
IN ULONG InitialEip,
IN ULONG InitialValueInStack OPTIONAL,
OUT PHANDLE ThreadHandle,
OUT PCLIENT_ID ClientId):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, or STATUS_PROCESS_IS_TERMINATING.

[Esp]:	NULL
		InitialValueInStack
ThreadDispatcher proto stdcall InitialValueInStack:DWORD
' 

RtlInitializeContext proto ProcessHandle:HANDLE, Context:PVOID, ValueInStack:ULONG, InitialEip:PVOID, StackBase:PVOID
comment '
RtlInitializeContext(
IN HANDLE ProcessHandle,
OUT PCONTEXT Context,
IN ULONG ValueInStack OPTIONAL,	;ThreadStartParam
IN PTHREAD_START_ROUTINE InitialEip,			;ThreadStartAddress:PVOID
IN PINITIAL_TEB InitialTeb):PVOID		;PVOID StackBase
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_VIOLATION or STATUS_PROCESS_IS_TERMINATING.
' 

RtlCaptureContext proto ContextRecord:PCONTEXT
comment '
RtlCaptureContext(
OUT PCONTEXT ContextRecord):VOID 
'   
;------------------------------------------------------- Processes --------------------------------------------------------
ZwCreateProcess	proto ProcessHandle:PHANDLE, DesiredAccess:ULONG, ObjectAttributes:PVOID, InheritFromProcessHandle:HANDLE, 
InheritHandles:BOOLEAN, SectionHandle:HANDLE, DebugPort:HANDLE, ExceptionPort:HANDLE
comment '
ZwCreateProcess(
OUT PHANDLE ProcessHandle,
IN ACCESS_MASK DesiredAccess,		;PROCESS_
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN HANDLE InheritFromProcessHandle,
IN BOOLEAN InheritHandles,
IN HANDLE SectionHandle OPTIONAL,
IN HANDLE DebugPort OPTIONAL,
IN HANDLE ExceptionPort OPTIONAL):NTSTATUS

;DesiredAccess
PROCESS_TERMINATE Terminate process
PROCESS_CREATE_THREAD Create threads in process
PROCESS_SET_SESSIONID Set process session id
PROCESS_VM_OPERATION Protect and lock memory of process
PROCESS_VM_READ Read memory of process
PROCESS_VM_WRITE Write memory of process
PROCESS_DUP_HANDLE Duplicate handles of process
PROCESS_CREATE_PROCESS Bequeath address space and handles to new process
PROCESS_SET_QUOTA Set process quotas
PROCESS_SET_INFORMATION Set information about process
PROCESS_QUERY_INFORMATION Query information about process
PROCESS_SET_PORT Set process exception or debug port
PROCESS_ALL_ACCESS All of the preceding + STANDARD_RIGHTS_ALL

Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwOpenProcess	proto ProcessHandle:PHANDLE, DesiredAccess:ULONG, ObjectAttributes:PVOID, ClientId:PCLIENT_ID 
comment '
ZwOpenProcess(
OUT PHANDLE ProcessHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN PCLIENT_ID ClientId OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_OBJECT_NAME_NOT_FOUND, STATUS_INVALID_PARAMETER_MIX, or STATUS_INVALID_PARAMETER.
' 

ZwOpenProcessToken	proto ProcessHandle:HANDLE, DesiredAccess:ULONG, TokenHandle:PHANDLE
comment '
ZwOpenProcessToken (
    IN HANDLE       ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    OUT PHANDLE     TokenHandle):NTSTATUS
' 

ZwOpenProcessTokenEx	proto ProcessHandle:HANDLE, DesiredAccess:ULONG, HandleAttributes:ULONG, TokenHandle:PHANDLE
comment '
ZwOpenProcessTokenEx (
    IN HANDLE       ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN ULONG        HandleAttributes,
    OUT PHANDLE     TokenHandle):NTSTATUS
' 

ZwTerminateProcess	proto ProcessHandle:HANDLE, ExitStatus:NTSTATUS
comment '
ZwTerminateProcess(
IN HANDLE ProcessHandle OPTIONAL,
IN NTSTATUS ExitStatus):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_PROCESS_IS_TERMINATING.
'

PDI_MODULES		equ 01h		;The loaded modules of the process
PDI_BACKTRACE		equ 02h		;The heap stack back traces
PDI_HEAPS			equ 04h		;The heaps of the process
PDI_HEAP_TAGS		equ 08h		;The heap tags
PDI_HEAP_BLOCKS	equ 10h		;The heap blocks
PDI_LOCKS			equ 20h		;The locks created by the process

DEBUG_MODULE_INFORMATION struct
Reserved			ULONG 2 DUP (?)
Base				ULONG ?
_Size			ULONG ?
Flags			ULONG ?
Index			USHORT ?
Unknown			USHORT ?
LoadCount			USHORT ?	;[Для статически загруженных модулей: -1]
ModuleNameOffset	USHORT ?
ImageName			CHAR 256 DUP (?)
DEBUG_MODULE_INFORMATION ends
PDEBUG_MODULE_INFORMATION typedef PTR DEBUG_MODULE_INFORMATION
;ModuleInformation указывает на NumberOfModules:DWORD, за которым следует структура DEBUG_MODULE_INFORMATION информацией о модулях

LDRP_STATIC_LINK			equ 00000002h
LDRP_IMAGE_DLL				equ 00000004h
LDRP_LOAD_IN_PROGRESS		equ 00001000h
LDRP_UNLOAD_IN_PROGRESS		equ 00002000h
LDRP_ENTRY_PROCESSED		equ 00004000h
LDRP_ENTRY_INSERTED			equ 00008000h
LDRP_CURRENT_LOAD			equ 00010000h
LDRP_FAILED_BUILTIN_LOAD		equ 00020000h
LDRP_DONT_CALL_FOR_THREADS	equ 00040000h
LDRP_PROCESS_ATTACH_CALLED	equ 00080000h
LDRP_DEBUG_SYMBOLS_LOADED	equ 00100000h
LDRP_IMAGE_NOT_AT_BASE		equ 00200000h
LDRP_WX86_IGNORE_MACHINETYPE	equ 00400000h

DEBUG_HEAP_INFORMATION struct
Base			ULONG ?
Flags		ULONG ?
Granularity	USHORT ?
Unknown		USHORT ?
Allocated		ULONG ?
Committed		ULONG ?
TagCount		ULONG ?
BlockCount	ULONG ?
Reserved		ULONG 7 DUP (?)
Tags			PVOID ?
Blocks		PVOID ?
DEBUG_HEAP_INFORMATION ends
PDEBUG_HEAP_INFORMATION typedef ptr DEBUG_HEAP_INFORMATION

DEBUG_LOCK_INFORMATION struct
Address				PVOID ?
_Type				USHORT ?
CreatorBackTraceIndex	USHORT ?
OwnerThreadId			ULONG ?
ActiveCount			ULONG ?
ContentionCount		ULONG ?
EntryCount			ULONG ?
RecursionCount			ULONG ?
NumberOfSharedWaiters	ULONG ?
NumberOfExclusiveWaiters	ULONG ?
DEBUG_LOCK_INFORMATION ends
PDEBUG_LOCK_INFORMATION typedef ptr DEBUG_LOCK_INFORMATION

DEBUG_BUFFER struct
SectionHandle		HANDLE ?
SectionBase		PVOID ?
RemoteSectionBase	PVOID ?
SectionBaseDelta	ULONG ?
EventPairHandle	HANDLE ?
Unknown			ULONG 2 DUP (?)
RemoteThreadHandle	HANDLE ?
InfoClassMask		ULONG ?
SizeOfInfo		ULONG ?
AllocatedSize		ULONG ?
SectionSize		ULONG ?
ModuleInformation	PVOID ?		;NumberOfNodules:ULONG,<PDEBUG_MODULE_INFORMATION>*NumberOfNodules
BackTraceInformation	PVOID ?
HeapInformation	PVOID ?		;PDEBUG_HEAP_INFORMATION
LockInformation	PVOID ?		;PDEBUG_LOCK_INFORMATION
Reserved			PVOID 8 DUP (?)
DEBUG_BUFFER ends
PDEBUG_BUFFER typedef PTR DEBUG_BUFFER

RTL_DEBUG_INFORMATION struct
SectionHandleClient		HANDLE ?
ViewBaseClient			PVOID ?
ViewBaseTarget			PVOID ?
ViewBaseDelta			ULONG_PTR ?
EventPairClient		HANDLE ?
EventPairTarget		HANDLE ?
TargetProcessId		HANDLE ?
TargetThreadHandle		HANDLE ?
Flags				ULONG ?
OffsetFree			SIZE_T ?
CommitSize			SIZE_T ?
ViewSize				SIZE_T ?
Modules				PDEBUG_MODULE_INFORMATION ?	;NumberOfNodules:ULONG,<PDEBUG_MODULE_INFORMATION>*NumberOfNodules
BackTraces			PVOID ?	;PRTL_PROCESS_BACKTRACES ?
Heaps				PDEBUG_HEAP_INFORMATION ?
Locks				PDEBUG_LOCK_INFORMATION ?
SpecificHeap			PVOID ?
TargetProcessHandle		HANDLE ?
Reserved				PVOID 6 DUP (?)
RTL_DEBUG_INFORMATION ends
PRTL_DEBUG_INFORMATION typedef ptr RTL_DEBUG_INFORMATION

RtlCreateQueryDebugBuffer proto MaximumCommit:ULONG, UseEventPair:BOOLEAN
comment '
RtlCreateQueryDebugBuffer(
IN ULONG MaximumCommit OPTIONAL,	;Size,		;Zero -> Default size
IN BOOLEAN UseEventPair):PRTL_DEBUG_INFORMATION'

RtlDestroyQueryDebugBuffer proto Buffer:PRTL_DEBUG_INFORMATION
comment '
RtlDestroyQueryDebugBuffer(
IN PRTL_DEBUG_INFORMATION Buffer):NTSTATUS'

RtlQueryProcessDebugInformation proto UniqueProcessId:HANDLE, Flags:ULONG, Buffer:PRTL_DEBUG_INFORMATION
comment '
RtlQueryProcessDebugInformation(
IN HANDLE UniqueProcessId,
IN ULONG Flags,	;PDI_
IN OUT PRTL_DEBUG_INFORMATION Buffer):NTSTATUS'

ZwSuspendProcess	proto ProcessHandle:dword
comment '
ZwSuspendProcess(
IN HANDLE ProcessHandle):NTSTATUS
comment '

ZwResumeProcess	proto ProcessHandle:dword	;Запускает все потоки процесса, остановленные ZwSuspendProcess
comment '
ZwResumeProcess(
IN HANDLE ProcessHandle):NTSTATUS
comment '

ZwQueryInformationProcess	proto ProcessHandle:HANDLE, ProcessInformationClass:ULONG, ProcessInformation:PVOID, ProcessInformationLength:ULONG, ReturnLength:PULONG
comment '
ZwQueryInformationProcess(
IN HANDLE ProcessHandle,
IN PROCESSINFOCLASS ProcessInformationClass,
OUT PVOID ProcessInformation,
IN ULONG ProcessInformationLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_INFO_LENGTH_MISMATCH, or STATUS_NOT_SUPPORTED.
' 

ZwSetInformationProcess	proto ProcessHandle:HANDLE, ProcessInformationClass:ULONG, ProcessInformation:PVOID, ProcessInformationLength:ULONG
comment '
ZwSetInformationProcess(
IN HANDLE ProcessHandle,
IN PROCESSINFOCLASS ProcessInformationClass,
IN PVOID ProcessInformation,
IN ULONG ProcessInformationLength):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_INFO_LENGTH_MISMATCH,
STATUS_PORT_ALREADY_SET, STATUS_PRIVILEGE_NOT_HELD, or STATUS_PROCESS_IS_TERMINATING.
' 

; Process Information Classes
;typedef enum _PROCESSINFOCLASS
ProcessBasicInformation		equ 0
ProcessQuotaLimits			equ 1
ProcessIoCounters			equ 2
ProcessVmCounters			equ 3
ProcessTimes				equ 4
ProcessBasePriority			equ 5
ProcessRaisePriority		equ 6
ProcessDebugPort			equ 7
ProcessExceptionPort		equ 8
ProcessAccessToken			equ 9
ProcessLdtInformation		equ 10
ProcessLdtSize				equ 11
ProcessDefaultHardErrorMode	equ 12
ProcessIoPortHandlers		equ 13	;Note: this is kernel mode only
ProcessPooledUsageAndLimits	equ 14
ProcessWorkingSetWatch		equ 15
ProcessUserModeIOPL			equ 16
ProcessEnableAlignmentFaultFixup	equ 17
ProcessPriorityClass		equ 18
ProcessWx86Information		equ 19
ProcessHandleCount			equ 20
ProcessAffinityMask			equ 21
ProcessPriorityBoost		equ 22
ProcessDeviceMap			equ 23
ProcessSessionInformation	equ 24
ProcessForegroundInformation	equ 25
ProcessWow64Information		equ 26
;	Undocumented
ProcessImageFileName			equ 27	;psapi!GetProcessImageFileName()
ProcessSessionCreationUnderway	equ 29	;Size=1, BOOLEAN, EPROCESS.Flags[SessionCreationUnderway]
ProcessNoDebugInherit			equ 31	;Size=1, BOOLEAN, EPROCESS.Flags[NoDebugInherit]
ProcessSpareInformation			equ 34	;Size=1, BOOLEAN, EPROCESS.Pcb.Spare
ProcessCookie					equ 36
ProcessImageInformation		equ 37	;Size=30h, SECTION_IMAGE_INFORMATION	;ProcessImageInformation

comment '
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,	;#10
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,          // Note: this is kernel mode only
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,	;#20
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,	;#30
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessResourceManagement,
    ProcessCookie,
    ProcessImageInformation,
    MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;
'
;InfoClass=36			D(EPROCESS+258h)
;InvalidInfoClass		equ 25, 33, 35

;ProcessImageFileName(Information Class 27)
;ImageName		UNICODE_STRING ?
;"\Device\HarddiskVolume1\Ent\___ISS\__IssServer\Lpc\ProcessImage\Project.exe"

; Process Basic Information(Information Class 0)
;  NtQueryInformationProcess using ProcessBasicInfo
PROCESS_BASIC_INFORMATION STRUCT	; sizeof = 18h
	ExitStatus			NTSTATUS	?
	PebBaseAddress			PVOID		? ; PPEB
	AffinityMask			DWORD		?
	BasePriority			DWORD		? ; KPRIORITY
	UniqueProcessId		DWORD		?
	InheritedFromUniqueProcessId	DWORD		?
PROCESS_BASIC_INFORMATION ENDS
PPROCESS_BASIC_INFORMATION typedef PTR PROCESS_BASIC_INFORMATION

; Process Quotas (Information Class 1)
;QUOTA_LIMITS <>

; Process I/O Counters (Information Class 2)
;IO_COUNTERS <>

; Process Virtual Memory Counters (Information Class 3)
;VM_COUNTERS <>

; Process/Thread System and User Time (Information Class 4)
;KERNEL_USER_TIMES <>

;ProcessBasePriority (Information Class 5)
;	BasePriority	KPRIORITY ?

;ProcessRaisePriority (Information Class 6)
;	RaisePriority	ULONG ?

;ProcessDebugPort (Information Class 7)
;	DebugPort	HANDLE ? 

;ProcessExceptionPort (Information Class 8)
	;ExceptionPort 	HANDLE ?

; Process Security Context Information (Information Class 9)
;  NtSetInformationProcess using ProcessAccessToken
; PROCESS_SET_ACCESS_TOKEN access to the process is needed
; to use this info level.
PROCESS_ACCESS_TOKEN  STRUCT
	; Handle to Primary token to assign to the process.
	; TOKEN_ASSIGN_PRIMARY access to this token is needed.
	Token	HANDLE	?
	; Handle to the initial thread of the process.
	; A process's access token can only be changed if the process has
	; no threads or one thread.  If the process has no threads, this
	; field must be set to NULL.  Otherwise, it must contain a handle
	; open to the process's only thread.  THREAD_QUERY_INFORMATION access
	; is needed via this handle.
	Thread	HANDLE	?
PROCESS_ACCESS_TOKEN ENDS
PPROCESS_ACCESS_TOKEN typedef PTR PROCESS_ACCESS_TOKEN

;ProcessDefaultHardErrorMode (Information Class 12)
;	DefaultHardErrorMode	ULONG ?

SEM_FAILCRITICALERRORS		equ	0001h
SEM_NOGPFAULTERRORBOX 		equ	0002h
SEM_NOALIGNMENTFAULTEXCEPT 	equ	0004h
SEM_NOOPENFILEERRORBOX 		equ 	8000h

; Process Pooled Quota Usage and Limits (Information Class 14)
;  NtQueryInformationProcess using ProcessPooledUsageAndLimits
POOLED_USAGE_AND_LIMITS  STRUCT
	PeakPagedPoolUsage		DWORD	?	; SIZE_T
	PagedPoolUsage			DWORD	?	; SIZE_T
	PagedPoolLimit			DWORD	?	; SIZE_T
	PeakNonPagedPoolUsage	DWORD	?	; SIZE_T
	NonPagedPoolUsage		DWORD	?	; SIZE_T
	NonPagedPoolLimit		DWORD	?	; SIZE_T
	PeakPagefileUsage		DWORD	?	; SIZE_T
	PagefileUsage			DWORD	?	; SIZE_T
	PagefileLimit			DWORD	?	; SIZE_T
POOLED_USAGE_AND_LIMITS ENDS
PPOOLED_USAGE_AND_LIMITS typedef PTR POOLED_USAGE_AND_LIMITS

; PageFaultHistory Information (Information Class 15)
;  NtQueryInformationProcess using ProcessWorkingSetWatch
PROCESS_WS_WATCH_INFORMATION STRUCT	; sizeof = 8
	FaultingPc	PVOID	?
	FaultingVa	PVOID	?
PROCESS_WS_WATCH_INFORMATION ENDS
PPROCESS_WS_WATCH_INFORMATION typedef PTR PROCESS_WS_WATCH_INFORMATION

;ProcessUserModeIOPL (Information Class 16)
;	UserModeIOPL 

;ProcessEnableAlignmentFaultFixup (Information Class 17)
;	EnableAlignmentFaultFixup	BOOLEAN ?

;ProcessPriorityClass (Information Class 18)
PROCESS_PRIORITY_CLASS struct
Foreground		BOOLEAN ?
PriorityClass		ULONG ?	; BYTE!
PROCESS_PRIORITY_CLASS ends
PPROCESS_PRIORITY_CLASS typedef PTR PPROCESS_PRIORITY_CLASS 

PC_IDLE 			equ 1
PC_NORMAL 		equ 2
PC_HIGH 			equ 3
PC_REALTIME 		equ 4
PC_BELOW_NORMAL 	equ 5
PC_ABOVE_NORMAL 	equ 6

;ProcessWx86Information (Information Class 19)
;	Wx86Information	ULONG ?

;ProcessHandleCount (Information Class 20)
;	HandleCount	ULONG ?

;ProcessAffinityMask (Information Class 21)
;	AffinityMask	KAFFINITY ?

;ProcessPriorityBoost (Information Class 22)
;	PriorityBoost	ULONG ?

; Process Device Map information (Information Class 23)
;  NtQueryInformationProcess using ProcessDeviceMap
;  NtSetInformationProcess using ProcessDeviceMap
PROCESS_DEVICEMAP_INFORMATION STRUCT
;Set
;DirectoryHandle	DWORD	?	; HANDLE
;Query
			DriveMap			DWORD	?
			DriveType			BYTE 32 dup(?)
PROCESS_DEVICEMAP_INFORMATION ENDS
PPROCESS_DEVICEMAP_INFORMATION typedef ptr PROCESS_DEVICEMAP_INFORMATION

DRIVE_UNKNOWN 		equ 0
DRIVE_NO_ROOT_DIR	equ 1
DRIVE_REMOVABLE 	equ 2
DRIVE_FIXED 		equ 3
DRIVE_REMOTE 		equ 4
DRIVE_CDROM 		equ 5
DRIVE_RAMDISK 		equ 6

; Multi-User Session specific Process Information (Information Class 24)
;  NtQueryInformationProcess using ProcessSessionInformation
PROCESS_SESSION_INFORMATION STRUCT
	SessionId	DWORD	?
PROCESS_SESSION_INFORMATION ENDS
PPROCESS_SESSION_INFORMATION typedef ptr PROCESS_SESSION_INFORMATION

;ProcessForegroundInformation (Information Class 25)
;	Foreground	BOOLEAN ?

;ProcessWow64Information (Information Class 26)
;	Wow64Information	ULONG ?

;ProcessVolumeInformation 
;UNICODE_STRING	;Полное имя процесса

RtlCreateProcessParameters proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
comment '
RtlCreateProcessParameters(
OUT PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
IN PUNICODE_STRING ImageFile,
IN PUNICODE_STRING DllPath OPTIONAL,
IN PUNICODE_STRING CurrentDirectory OPTIONAL,
IN PUNICODE_STRING CommandLine OPTIONAL,
IN PVOID Environment OPTIONAL,
IN PUNICODE_STRING WindowTitle OPTIONAL,
IN PUNICODE_STRING Desktop OPTIONAL,
IN PUNICODE_STRING Reserved OPTIONAL,
IN PUNICODE_STRING Reserved2 OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status.
' 

RtlDestroyProcessParameters proto ProcessParameters:PRTL_USER_PROCESS_PARAMETERS
comment '
RtlDestroyProcessParameters(
IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters):NTSTATUS
' 

RtlNormalizeProcessParams proto ProcessParameters:PRTL_USER_PROCESS_PARAMETERS
comment '
RtlNormalizeProcessParams(
IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters):PRTL_USER_PROCESS_PARAMETERS'

RtlDeNormalizeProcessParam proto ProcessParameters:PRTL_USER_PROCESS_PARAMETERS
comment '
RtlDeNormalizeProcessParams(
IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters):PRTL_USER_PROCESS_PARAMETERS'
  
RtlCreateUserProcess                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
comment '
RtlCreateUserProcess(
IN PUNICODE_STRING ImagePath,	;NT - format, "/??/..."
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
IN HANDLE ParentProcess,
IN BOOLEAN InheritHandle,
IN HANDLE DebugPort OPTIONAL,
IN HANDLE ExceptionPort OPTIONAL,
OUT PRTL_USER_PROCESS_INFORMATION ProcessInformation):NTSTATUS
' 

ZwRemoveProcessDebug proto :HANDLE, :HANDLE
;----------------------------------------- Local Procedure Calls (Ports) ----------------------------------------------
PORT_MESSAGE struct
DataSize		USHORT ?		;+0
MessageSize	USHORT ?		;+2
MessageType	USHORT ?		;+4
VirtualRangesOffset	USHORT ?	;+6
ClientId		CLIENT_ID <>	;+8
MessageId		ULONG ?		;+10
SectionSize	ULONG ?		;+14
;Buffer		UCHAR 1 DUP (?)	;+18h
PORT_MESSAGE ends
PPORT_MESSAGE typedef PTR PORT_MESSAGE

;typedef enum _LPC_TYPE {
LPC_NEW_MESSAGE	equ 0	;A new message
LPC_REQUEST		equ 1	;A request message
LPC_REPLY			equ 2	;A reply to a request message
LPC_DATAGRAM		equ 3	;
LPC_LOST_REPLY		equ 4	;
LPC_PORT_CLOSED	equ 5	;Sent when port is deleted
LPC_CLIENT_DIED	equ 6	;Messages to thread termination ports
LPC_EXCEPTION		equ 7	;Messages to thread exception port
LPC_DEBUG_EVENT	equ 8	;Messages to thread debug port
LPC_ERROR_EVENT	equ 9	;Used by ZwRaiseHardError
LPC_CONNECTION_REQUEST	equ 10;Used by ZwConnectPort
LPC_MAX_MESSAGETYPE	equ 11

PORT_MESSAGE_DATA_MAXSIZE	equ 300

PORT_SECTION_WRITE struct
_Length		ULONG ?
SectionHandle	HANDLE ?
SectionOffset	ULONG ?
ViewSize		ULONG ?
ViewBase		PVOID ?
TargetViewBase	PVOID ?
PORT_SECTION_WRITE ends
PPORT_SECTION_WRITE typedef PTR PPORT_SECTION_WRITE

PORT_SECTION_READ struct
_Length		ULONG ?
ViewSize		ULONG ?
ViewBase		PVOID ?
PORT_SECTION_READ ends
PPORT_SECTION_READ typedef PTR PORT_SECTION_READ

PORT_CONNECT	equ 0001h

PORT_ALL_ACCESS	equ (STANDARD_RIGHTS_ALL or PORT_CONNECT)

ZwCreatePort	proto PortHandle:PHANDLE, ObjectAttributes:PVOID, MaxDataSize:ULONG, MaxMessageSize:ULONG, Reserved:ULONG
comment '
ZwCreatePort(
OUT PHANDLE PortHandle,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN ULONG MaxDataSize,
IN ULONG MaxMessageSize,
IN ULONG Reserved):NTSTATUS
Returns STATUS_SUCCESS or an error status.
' 

ZwCreateWaitablePort	proto PortHandle:PHANDLE, ObjectAttributes:PVOID, MaxDataSize:ULONG, MaxMessageSize:ULONG, Reserved:ULONG 
comment '
ZwCreateWaitablePort(
OUT PHANDLE PortHandle,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN ULONG MaxDataSize,
IN ULONG MaxMessageSize,
IN ULONG Reserved):NTSTATUS
Returns STATUS_SUCCESS or an error status.
'

ZwConnectPort	proto PortHandle:PHANDLE, PortName:PVOID, SecurityQos:PSECURITY_QUALITY_OF_SERVICE, WriteSection:PVOID, ReadSection:PVOID, MaxMessageSize:PULONG, 
ConnectData:PVOID, ConnectDataLength:PULONG
comment '
ZwConnectPort(
OUT PHANDLE PortHandle,
IN PUNICODE_STRING PortName,
IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
IN OUT PPORT_SECTION_WRITE WriteSection OPTIONAL,
IN OUT PPORT_SECTION_READ ReadSection OPTIONAL,
OUT PULONG MaxMessageSize OPTIONAL,
IN OUT PVOID ConnectData OPTIONAL,
IN OUT PULONG ConnectDataLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_OBJECT_NAME_NOT_FOUND, STATUS_PORT_CONNECTION_REFUSED, or STATUS_INVALID_PORT_HANDLE.
' 

ZwSecureConnectPort	proto PortHandle:PHANDLE, PortName:PVOID, SecurityQos:PVOID, WriteSection:PVOID, ServerSid:PSID, ReadSection:PVOID, 
MaxMessageSize:PULONG, ConnectData:PVOID, ConnectDataLength:PULONG
comment '
ZwSecureConnectPort(
OUT PHANDLE PortHandle,
IN PUNICODE_STRING PortName,
IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
IN OUT PPORT_SECTION_WRITE WriteSection OPTIONAL,
IN PSID ServerSid OPTIONAL
IN OUT PPORT_SECTION_READ ReadSection OPTIONAL,
OUT PULONG MaxMessageSize OPTIONAL,
IN OUT PVOID ConnectData OPTIONAL,
IN OUT PULONG ConnectDataLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_OBJECT_NAME_NOT_FOUND, STATUS_PORT_CONNECTION_REFUSED, STATUS_INVALID_PORT_HANDLE, or STATUS_SERVER_SID_MISMATCH.
'

ZwListenPort	proto PortHandle:HANDLE, Message:PVOID
comment '
ZwListenPort(
IN HANDLE PortHandle,
OUT PPORT_MESSAGE Message):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE.
' 

ZwAcceptConnectPort	proto PortHandle:PHANDLE, PortIdentifier:ULONG, Message:PVOID, Accept:BOOLEAN, WriteSection:PVOID, ReadSection:PVOID
comment '
ZwAcceptConnectPort(
OUT PHANDLE PortHandle,
IN ULONG PortIdentifier OPIONAL,
IN PPORT_MESSAGE Message,
IN BOOLEAN Accept,
IN OUT PPORT_SECTION_WRITE WriteSection OPTIONAL,
IN OUT PPORT_SECTION_READ ReadSection OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_REPLY_MESSAGE_MISMATCH.
' 

ZwCompleteConnectPort	proto PortHandle:HANDLE
comment '
ZwCompleteConnectPort(
IN HANDLE PortHandle):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE or STATUS_INVALID_PORT_HANDLE.
' 

ZwRequestPort	proto PortHandle:HANDLE, RequestMessage:PVOID
comment '
ZwRequestPort(
IN HANDLE PortHandle,
IN PPORT_MESSAGE RequestMessage):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE or STATUS_PORT_DISCONNECTED.
' 

ZwRequestWaitReplyPort	proto PortHandle:HANDLE, RequestMessage:PVOID, ReplyMessage:PVOID
comment '
ZwRequestWaitReplyPort(
IN HANDLE PortHandle,
IN PPORT_MESSAGE RequestMessage,
OUT PPORT_MESSAGE ReplyMessage):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE,
STATUS_PORT_DISCONNECTED, STATUS_THREAD_IS_TERMINATING, STATUS_REPLY_MESSAGE_MISMATCH or STATUS_LPC_REPLY_LOST.
' 

ZwReplyPort	proto PortHandle:HANDLE, ReplyMessage:PVOID
comment '
ZwReplyPort(
IN HANDLE PortHandle,
IN PPORT_MESSAGE ReplyMessage):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE or STATUS_REPLY_MESSAGE_MISMATCH.
' 

ZwReplyWaitReplyPort	proto PortHandle:HANDLE, ReplyMessage:PVOID
comment '
ZwReplyWaitReplyPort(
IN HANDLE PortHandle,
IN OUT PPORT_MESSAGE ReplyMessage):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE or STATUS_REPLY_MESSAGE_MISMATCH.
' 

ZwReplyWaitReceivePort	proto PortHandle:HANDLE, PortIdentifier:PULONG, ReplyMessage:PVOID, Message:PVOID
comment '
ZwReplyWaitReceivePort(
IN HANDLE PortHandle,
OUT PULONG PortIdentifier OPTIONAL,
IN PPORT_MESSAGE ReplyMessage OPTIONAL,
OUT PPORT_MESSAGE Message):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE or STATUS_REPLY_MESSAGE_MISMATCH.
' 

ZwReplyWaitReceivePortEx	proto PortHandle:HANDLE, PortIdentifier:PULONG, ReplyMessage:PVOID, Message:PVOID, Timeout:PVOID
comment '
ZwReplyWaitReceivePortEx(
IN HANDLE PortHandle,
OUT PULONG PortIdentifier OPTIONAL,
IN PPORT_MESSAGE ReplyMessage OPTIONAL,
OUT PPORT_MESSAGE Message,
IN PLARGE_INTEGER Timeout):NTSTATUS
Returns STATUS_SUCCESS, STATUS_TIMEOUT or an error status, such as STATUS_INVALID_HANDLE or STATUS_REPLY_MESSAGE_MISMATCH.
' 

ZwReadRequestData	proto PortHandle:HANDLE, Message:PVOID, Index:ULONG, Buffer:PVOID, BufferLength:ULONG, ReturnLength:PULONG
comment '
ZwReadRequestData(
IN HANDLE PortHandle,
IN PPORT_MESSAGE Message,
IN ULONG Index,
OUT PVOID Buffer,
IN ULONG BufferLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE.
' 

ZwWriteRequestData	proto PortHandle:HANDLE, Message:PVOID, Index:ULONG, Buffer:PVOID, BufferLength:ULONG, ReturnLength:PULONG
comment '
ZwWriteRequestData(
IN HANDLE PortHandle,
IN PPORT_MESSAGE Message,
IN ULONG Index,
OUT PVOID Buffer,
IN ULONG BufferLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE.
' 

ZwQueryInformationPort	proto PortHandle:HANDLE, PortInformationClass:ULONG, PortInformation:PVOID, PortInformationLength:ULONG, ReturnLength:PULONG
comment '
ZwQueryInformationPort(
IN HANDLE PortHandle,
IN PORT_INFORMATION_CLASS PortInformationClass,
OUT PVOID PortInformation,
IN ULONG PortInformationLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE or STATUS_INVALID_INFO_CLASS.'

;typedef enum _PORT_INFORMATION_CLASS {
PortBasicInformation	equ 0

ZwImpersonateClientOfPort	proto PortHandle:HANDLE, Message:PVOID
comment '
ZwImpersonateClientOfPort(
IN HANDLE PortHandle,
IN PPORT_MESSAGE Message):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_INVALID_HANDLE, STATUS_INVALID_PORT_HANDLE, or STATUS_PORT_DISCONNECTED.'

RtlImpersonateLpcClient                            proto stdcall :DWORD, :DWORD

;-------------------------------------------------- Loader ------------------------------------------------
LdrSetAppCompatDllRedirectionCallback proto IsValid:BOOLEAN, CallbackFunction:PVOID, CallbackData:PVOID
comment '
NTSTATUS
LdrSetAppCompatDllRedirectionCallback(
IN ULONG IsValid,    ; Должен быть ноль.
IN PVOID CallbackFunction,
IN PVOID CallbackData
);'

LdrEnumerateLoadedModules proto Flag:BOOLEAN, Callback:PVOID, Parameter:ULONG	;Flag=NULL
comment '
;Перечисляет все модули спроецированные в адресное пространство текущего процесса, вызывая процедуру обратного вызова.
LdrEnumerateLoadedModules(
IN BOOLEAN Flag,
IN POINTER Callback,
IN ULONG Parameter):DWORD

Callback proto ModuleInformation:PLDR_DATA_TABLE_ENTRY, Parameter:dword, ByteFlagEnd:PCHAR
Callback(
IN PLDR_DATA_TABLE_ENTRY ModuleInformation,
IN DWORD Parameter,
OUT PCHAR ByteFlagEnd):NTSTATUS
;Если флаг (BYTE) по адресу ByteFlagEnd установить в 1 то перечисление прекращается.'

LdrFindEntryForAddress proto Address:PVOID, TableEntry:PLDR_DATA_TABLE_ENTRY
comment '
;Определяет в проекции какого модуля находится адрес
LdrFindEntryForAddress(
IN PVOID Address,
OUT PLDR_DATA_TABLE_ENTRY TableEntry):NTSTATUS
;TableEntry:Указатель на переменную, принимающую адрес структуры LDR_DATA_TABLE_ENTRY с информацией о модуле
Return STATUS_NO_MORE_ENTRIES'

LdrGetDllHandle proto szcwPath:PWCHAR, pdwLdrErr:ULONG, pUniModuleName:PVOID, pResultInstance:PHANDLE
comment '
Определяет адрес проекции модуля по его имени
LdrGetDllHandle(
IN PWIDECHAR pwPath,
IN ULONG pdwLdrErr,
IN PUNICODE_STRING pUniModuleName,
OUT HANDLE pResultInstance):NTSTATUS'

LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT	equ 1
LDR_GET_DLL_HANDLE_EX_PIN	equ 2

LdrGetDllHandleEx proto Flags:ULONG, DllPath:PWSTR, DllCharacteristics:PULONG, DllName:PUNICODE_STRING, DllHandle:PVOID
comment '
LdrGetDllHandleEx(
IN ULONG Flags,
IN PCWSTR DllPath OPTIONAL,
IN PULONG DllCharacteristics OPTIONAL,
IN PCUNICODE_STRING DllName,
OUT PVOID *DllHandle OPTIONAL):NTSTATUS'

LdrLoadDll proto szcwPath:PWCHAR, pdwLdrErr:ULONG, pUniModuleName:PVOID, pResultInstance:PHANDLE
comment '
Загружает модуль
LdrLoadDll(
IN PWIDECHAR PathToFile OPTIONAL,	;Список каталогов разделённых запятыми, где будет выполнен поиск модуля.
IN PULONG pdwLdrErr OPTIONAL,	;Флаги; DONT_RESOLVE_DLL_REFERENCES:D[pdwLdrErr]=2
IN PUNICODE_STRING pUniModuleName,
OUT HANDLE pResultInstance):NTSTATUS
;szcwPath=1,pdwLdrErr=NULL'

LDR_DONT_RESOLVE_DLL_REFERENCES	EQU 2	;Загрузка модуля без вызова DllEntry

LdrUnloadDll proto ModuleHandle:HANDLE
comment '
Выгружает модуль
LdrUnloadDll(
IN HANDLE ModuleHandle):NTSTATUS'

LdrGetProcedureAddress proto ModuleHnadle:HANDLE, psNamed:PVOID, dOrdinal:ULONG, ppProcedure:PVOID
comment '
Определяет адрес процедуры в модуле по её имени или ординалу
LdrGetProcedureAddress(
IN HANDLE ModuleHandle,
IN PANSI_STRING FunctionName OPTIONAL,
IN ULONG Ordinal OPTIONAL,
OUT PPOINTER ProcedureAddress):NTSTATUS'

LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS	equ 1
LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY			equ 2
LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID	equ 0
LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED	equ 1
LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED	equ 2

LdrLockLoaderLock proto Flag:BOOLEAN, Param:PULONG, LoaderLock:PULONG
comment '
Вход загрузчика в критическую секцию. Пока загрузчик находится в критической секции, 
потоки загружающие/выгружающие модули будут находится в состоянии ожидания.
LdrLockLoaderLock(
IN BOOLEAN Flag,
IN PULONG Parameter,
OUT PULONG LoaderLock):NTSTATUS'

LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS	equ 1

LdrUnlockLoaderLock	proto Flag:BOOLEAN, LoaderLock:PULONG
comment '
Выход загрузчика из критической секции
LdrUnlockLoaderLock(
IN BOOLEAN Flag,
IN PULONG LoaderLock):NTSTATUS
LoaderLock-указатель на значение, возвращаемое LdrLockLoaderLock()'

LdrShutdownProcess proto
comment '
Подготавливает процесс к завершению, в частности вызывает DllEntry(DLL_PROCESS_DETACH) во всех загруженных модулях.
LdrShutdownProcess():NTSTATUS'

LdrShutdownThread proto
comment '
Подготавливает поток к завершению, в частности вызывает DllEntry(DLL_THREAD_DETACH) во всех загруженных модулях.
LdrShutdownThread():NTSTATUS'

LdrDisableThreadCalloutsForDll proto ModuleHandle:HANDLE
comment '
Запрещает вызов DllEntry с причинами DLL_THREAD_ для динамически загруженных модулей(через LdrLoadDll).
Для статически-подключённых библиотек возвращает ошибку.
LdrDisableThreadCalloutsForDll(
IN HANDLE ModuleHandle):NTSTATUS'

LdrInitializeThunk                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD

LdrQueryProcessModuleInformation proto InformationBuffer:PVOID, BufferSize:ULONG, ReturnLength:PULONG
comment '
Получение информации о загруженных модулях.
LdrQueryProcessModuleInformation(
OUT PVOID InformationBuffer,	;()->NumberOfModules:ULONG, DEBUG_MODULE_INFORMATION <>
IN ULONG BufferSize,
OUT PULONG ReturnLength):NTSTATUS
Return value: STATUS_SUCCESS, STATUS_INFO_LENGTH_MISMATCH'

RESOURCE_INFORMATION struct
ResourceType	ULONG ?	;Тип ресурса RT_ или указатель на UNICODE-строку с типом ресурса
ResourceName	ULONG ?	;Идентификатор ресурса или указатель на UNICODE-строку с именем ресурса
RESOURCE_INFORMATION ends
PRESOURCE_INFORMATION typedef ptr RESOURCE_INFORMATION

LdrFindResource_U proto ModuleHandle:HANDLE, ResourceInformation:PRESOURCE_INFORMATION, LanguageId:ULONG, ResourceHandle:PHANDLE
comment '
Ищет ресурс в модуле по имени и типу. Возвращает адрес заголовка ресурса.
По умолчанию LanguageId=SUBLANG_DEFAULT or SUBLANG_SYS_DEFAULT
LdrFindResource_U(
IN HANDLE ModuleHandle,
IN PRESOURCE_INFORMATION ResourceInformation,	;IN const ULONG_PTR* ResourceIdPath,	;Supplies a pointer to an array of 32-bit resource identifiers(PRESOURCE_INFORMATION).
IN ULONG LanguageId,	;IN ULONG ResourceIdPathLengthSupplies the number of elements in the ResourceIdPath
OUT PHANDLE ResourceHandle	;OUT PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry
):NTSTATUS'

LdrFindResourceEx_U proto Flags:ULONG, ModuleHandle:HANDLE, ResourceIdPath:PVOID, ResourceIdPathLength:ULONG, ResourceDataEntry:PIMAGE_RESOURCE_DATA_ENTRY
comment '
LdrFindResourceEx_U(
IN ULONG Flags,
IN PVOID DllHandle,
IN const ULONG_PTR* ResourceIdPath,	;Supplies a pointer to an array of 32-bit resource identifiers(PRESOURCE_INFORMATION).
IN ULONG ResourceIdPathLength,		;Supplies the number of elements in the ResourceIdPath
OUT PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry):NTSTATUS
Flags -
LDRP_FIND_RESOURCE_DIRECTORY
searching for a resource directory, otherwise the caller is searching for a resource data entry.
LDR_FIND_RESOURCE_LANGUAGE_EXACT
searching for a resource with, and only with, the language id specified in ResourceIdPath, otherwise the caller wants the routine to come up with default when specified langid is not found.
LDR_FIND_RESOURCE_LANGUAGE_REDIRECT_VERSION
searching for a resource version in both main and alternative module paths'

LdrAccessResource proto ModuleHandle:HANDLE, ResourceHandle:HANDLE, ResourceAddress:PULONG, SizeOfResource:PULONG
comment '
Возвращает адрес ресурса и его размер по указателю на его заголовок.
LdrAccessResource(
IN HANDLE ModuleHandle,
IN HANDLE ResourceHandle,	;IN const IMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry
OUT *PVOID ResourceAddress,
OUT PULONG SizeOfResource OPTIONAL):NTSTATUS'

LdrFindResourceDirectory_U proto ModuleHandle:HANDLE, ResourceIdPath:ULONG, ResourceIdPathLength:ULONG, ResourceDirectory:PULONG
comment '
Ищет секцию .RSRC в модуле
LdrFindResourceDirectory(
IN HANDLE ModuleHandle,
IN const ULONG_PTR* ResourceIdPath,	;Supplies a pointer to an array of 32-bit resource identifiers.(PRESOURCE_INFORMATION).
IN ULONG ResourceIdPathLength,		;Supplies the number of elements in the ResourceIdPath array.
OUT PIMAGE_RESOURCE_DIRECTORY *ResourceDirectory):NTSTATUS'

LdrEnumResources proto ModuleHandle:HANDLE, ResourceIdPath:PVOID, ResourceIdPathLength:ULONG, NumberOfResources:PULONG, Resources:PVOID
comment '
LdrEnumResources(
IN PVOID DllHandle,
IN const ULONG_PTR* ResourceIdPath,
IN ULONG ResourceIdPathLength,
IN OUT PULONG NumberOfResources,
OUT PLDR_ENUM_RESOURCE_ENTRY Resources OPTIONAL):NTSTATUS'

LdrProcessRelocationBlock proto VA:ULONG_PTR, SizeOfBlock:ULONG, NextOffset:USHORT, Diff:LONG_PTR
comment '
LdrProcessRelocationBlock(
IN ULONG_PTR VA,
IN ULONG SizeOfBlock,
IN PUSHORT NextOffset,
IN LONG_PTR Diff):PIMAGE_BASE_RELOCATION'

LdrVerifyImageMatchesChecksum proto FileHandle:HANDLE, CallbackRoutine:PVOID, CallbackParameter:DWORD, Characteristics:PUSHORT
comment '
LdrVerifyImageMatchesChecksum(
IN HANDLE FileHandle,
IN PVOID CallBack,
IN ULONG UserParameter,
OUT PWORD Characteristics OPTIONAL) 	;IMAGE_NT_HEADER.FileHeader.Characteristics
CallBack(
IN ULONG UserParameter,
IN Result_RtlImageRvaToVa()):VOID
' 

LdrInitShimEngineDynamic proto ModuleHandle:HANDLE
comment '
LdrInitShimEngineDynamic(
IN PVOID ModuleHandle):NTSTATUS'

comment '
LdrAccessOutOfProcessResource
LdrAddRefDll
LdrCreateOutOfProcessImage
LdrDestroyOutOfProcessImage
LdrFindCreateProcessManifest
LdrFindResourceEx_U
LdrHotPatchRoutine
LdrInitShimEngineDynamic
LdrSetAppCompatDllRedirectionCallback
LdrSetDllManifestProber'
LdrAlternateResourcesEnabled                       proto stdcall
LdrFlushAlternateResourceModules                   proto stdcall
LdrLoadAlternateResourceModule                     proto stdcall :DWORD, :DWORD
LdrQueryImageFileExecutionOptions                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
LdrUnloadAlternateResourceModule                   proto stdcall :DWORD
;----------------------------------------------------- Miscellaneous -----------------------------------------------------
;enum _HARDERROR_RESPONSE_OPTION {
OptionAbortRetryIgnore	equ 0
OptionOk				equ 1
OptionOkCancel			equ 2
OptionRetryCancel		equ 3
OptionYesNo			equ 4
OptionYesNoCancel		equ 5
OptionShutdownSystem	equ 6
OptionOkNoWait			equ 7
OptionCancelTryContinue	equ 8

;enum _HARDERROR_RESPONSE {
ResponseReturnToCaller	equ 0
ResponseNotHandled		equ 1
ResponseAbort			equ 2
ResponseCancel			equ 3
ResponseIgnore			equ 4
ResponseNo			equ 5
ResponseOk			equ 6
ResponseRetry			equ 7
ResponseYes			equ 8
ResponseTryAgain		equ 9
ResponseContinue		equ 10

HARDERROR_RESPONSE 			typedef ULONG
HARDERROR_RESPONSE_OPTION	typedef ULONG
PHARDERROR_RESPONSE 		typedef PULONG
PHARDERROR_RESPONSE_OPTION	typedef PULONG

ZwRaiseHardError proto Status:NTSTATUS, NumberOfArguments:ULONG, StringArgumentsMask:ULONG, Arguments:PULONG, ResponseOption:ULONG, Response:PULONG
comment '
ZwRaiseHardError(
IN NTSTATUS Status,
IN ULONG NumberOfArguments,
IN ULONG StringArgumentsMask,
IN PULONG Arguments,
IN HARDERROR_RESPONSE_OPTION ResponseOption,
OUT PHARDERROR_RESPONSE Response):NTSTATUS'

RtlImageNtHeader proto ImageBase:PVOID
comment '
RtlImageNtHeader(
IN PVOID ImageBase):PIMAGE_NT_HEADERS
' 

RtlImageRvaToSection proto ImageHeader:PIMAGE_NT_HEADERS, Reserved1:ULONG, SectionRva:ULONG
comment '
RtlImageRvaToSection(
IN PIMAGE_NT_HEADERS ImageHeader,
IN ULONG Reserved1,		;ModuleHandle:HANDLE
IN ULONG SectionRva):PIMAGE_SECTION_HEADER
' 

RtlAddressInSectionTable proto ImageHeader:PIMAGE_NT_HEADERS, ModuleHandle:HANDLE, SectionRva:ULONG
comment '
RtlAddressInSectionTable(
IN PIMAGE_NT_HEADERS ImageHeader,
IN HANDLE ModuleHandle,
IN ULONG SectionRva):PVOID	;ModuleHandle + Section.PointerToRawData
' 

RtlImageDirectoryEntryToData proto ModuleHandle:HANDLE, Reserved1:ULONG, ImageDirectory:ULONG, DirectorySize:PULONG
comment '
Возвращает адрес и размер директории
RtlImageDirectoryEntryToData(
IN HANDLE ModuleHandle,
IN Reserved1:ULONG,
IN ImageDirectory:ULONG,		;IMAGE_DIRECTORY_ENTRY_
OUT PULONG DirectorySize):PVOID
' 

RtlPcToFileHeader proto Address:PVOID, ImageHeader:PVOID
comment '
Определяет в проекции какого модуля находится адрес.
RtlPcToFileHeader(
IN PVOID Address,
OUT PVOID ImageBase):PVOID
' 

RtlImageRvaToVa                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
comment '
IN PIMAGE_NT_HEADERS ImageHeader,
IN PVOID ModuleBase,
IN ULONG Rva,
IN OUT PIMAGE_SECTION_HEADER pLastSection OPTIONAL):PVOID
'
 
 
RtlRandom proto Seed:PULONG
comment '
Генератор псевдослучайных чисел
RtlRandom(
IN OUT PULONG Seed):ULONG
' 

RtlRandomEx proto Seed:PULONG
comment '
RtlRandomEx(
IN OUT PULONG Seed):ULONG
' 

RtlRemoteCall proto ProcessHandle:HANDLE, ThreadHandle:HANDLE, ProcedureAddress:DWORD, NumberArguments:ULONG, ArgumentList:PVOID, ContextSaveFlag:BOOLEAN, ThreadSuspendStatus:BOOLEAN
comment '
Удалённый вызов процедуры
RtlRemoteCall(
IN HANDLE ProcessHandle,
IN HANDLE ThreadHandle,
IN DWORD ProcedureAddress,		;regEip
IN ULONG NumberArguments OPTIONAL,	;[NumberArguments<5]
IN PULONG ArgumentList,
IN BOOLEAN ContextSaveFlag,
IN BOOLEAN ThreadSuspendStatus	;FALSE -> Остановка потока
):NTSTATUS	
................................................................................................
Если NumberArguments=0 и ContextSaveFlag=FALSE, то стек и регистр Esp не изменяются.
................................................................................................
Если NumberArguments=0 и ContextSaveFlag=TRUE:
[Esp+00h]:	pContext	PCONTEXT
[Esp+04h]:	Context	CONTEXT
Context.regEsp:	;Значение регистра Esp в момент остановки потока(до удалённого вызова). 
		-----...-----
................................................................................................
Если ContextSaveFlag=TRUE и 5>NumberArguments>0, то в стеке передаётся контекст потока:
[Esp+00h]:	pContext	PCONTEXT
[Esp+04h]:	[Parameters list]	;SizeOf,bytes=DWORD*NumberArguments;в порядке следования в списке. 
			Context	CONTEXT
Context.regEsp:	;Значение регистра Esp в момент остановки потока(до удалённого вызова). 
		-----...-----
................................................................................................
Если ContextSaveFlag=FALSE и 5>NumberArguments>0:
[Esp+00h]:	[Parameters list]	
regEsp:	;Значение регистра Esp в момент остановки потока(до удалённого вызова). 
		-----...-----
' 

RtlEncodePointer proto Pointer:PVOID
comment '
RtlEncodePointer(
IN PVOID Pointer'

RtlDecodePointer proto Pointer:PVOID
comment '
RtlDecodePointer(
IN PVOID Pointer):PVOID'

RtlEncodeSystemPointer proto Pointer:PVOID
comment '
RtlEncodeSystemPointer(
IN PVOID Pointer):PVOID'

RtlDecodeSystemPointer proto Pointer:PVOID
comment '
RtlDecodeSystemPointer(
IN PVOID Pointer):PVOID'

RtlGetNtGlobalFlags	proto
comment '
RtlGetNtGlobalFlags(
IN VOID):ULONG
' 

RtlComputeImportTableHash proto FileHandle:HANDLE, HashData:PVOID, Revision:ULONG
comment '
RtlComputeImportTableHash(
IN HANDLE FileHandle,
OUT PVOID HashData,	;16 Bytes
IN ULONG Revision):	;Revision = SECURITY_DESCRIPTOR_REVISION
' 

RtlAbsoluteToSelfRelativeSD	proto AbsoluteSecurityDescriptor:PVOID, SelfRelativeSecurityDescriptor:PVOID, BufferLength:PULONG
comment '
RtlAbsoluteToSelfRelativeSD(
    IN PSECURITY_DESCRIPTOR     AbsoluteSecurityDescriptor,
    IN OUT PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    IN PULONG                   BufferLength):NTSTATUS
    
RtlAbsoluteToSelfRelativeSD proto AbsoluteSD:PSECURITY_DESCRIPTOR, SelfRelativeSD:PSECURITY_DESCRIPTOR, BufferLength:PULONG
Advapi32.MakeSelfRelativeSD
RtlAbsoluteToSelfRelativeSD(
IN PSECURITY_DESCRIPTOR AbsoluteSD,
OUT PSECURITY_DESCRIPTOR SelfRelativeSD,
OUT PULONG BufferLength):NTSTATUS
'  

RtlCompressChunks	proto UncompressedBuffer:PUCHAR, UncompressedBufferSize:ULONG , CompressedBuffer:PUCHAR, CompressedBufferSize:ULONG, 
CompressedDataInfo:PVOID, CompressedDataInfoLength:ULONG, WorkSpace:PVOID 
comment '
RtlCompressChunks (
    IN PUCHAR                       UncompressedBuffer,
    IN ULONG                        UncompressedBufferSize,
    OUT PUCHAR                      CompressedBuffer,
    IN ULONG                        CompressedBufferSize,
    IN OUT PCOMPRESSED_DATA_INFO    CompressedDataInfo,
    IN ULONG                        CompressedDataInfoLength,
    IN PVOID                        WorkSpace):NTSTATUS
' 

RtlDecompressChunks	proto UncompressedBuffer:PUCHAR,UncompressedBufferSize:ULONG,CompressedBuffer:PUCHAR,CompressedBufferSize:ULONG,
CompressedTail:PUCHAR,CompressedTailSize:ULONG,CompressedDataInfo:PVOID
comment '
RtlDecompressChunks (
    OUT PUCHAR                  UncompressedBuffer,
    IN ULONG                    UncompressedBufferSize,
    IN PUCHAR                   CompressedBuffer,
    IN ULONG                    CompressedBufferSize,
    IN PUCHAR                   CompressedTail,
    IN ULONG                    CompressedTailSize,
    IN PCOMPRESSED_DATA_INFO    CompressedDataInfo):NTSTATUS
' 

RtlDecompressFragment	proto CompressionFormat:USHORT, UncompressedFragment:PUCHAR, UncompressedFragmentSize:ULONG, CompressedBuffer:PUCHAR,  
CompressedBufferSize:ULONG, FragmentOffset:ULONG, FinalUncompressedSize:PULONG, WorkSpace:PVOID
comment '
RtlDecompressFragment (
    IN USHORT   CompressionFormat,
    OUT PUCHAR  UncompressedFragment,
    IN ULONG    UncompressedFragmentSize,
    IN PUCHAR   CompressedBuffer,
    IN ULONG    CompressedBufferSize,
    IN ULONG    FragmentOffset,
    OUT PULONG  FinalUncompressedSize,
    IN PVOID    WorkSpace):NTSTATUS
' 

RtlDescribeChunk	proto CompressionFormat:USHORT, CompressedBuffer:PUCHAR, EndOfCompressedBufferPlus1:PUCHAR, ChunkBuffer:PUCHAR, ChunkSize:PULONG
comment '
RtlDescribeChunk (
    IN USHORT       CompressionFormat,
    IN OUT PUCHAR   *CompressedBuffer,
    IN PUCHAR       EndOfCompressedBufferPlus1,
    OUT PUCHAR      *ChunkBuffer,
    OUT PULONG      ChunkSize):NTSTATUS
' 

RtlGenerate8dot3Name	proto _Name:PVOID, AllowExtendedCharacters:BOOLEAN, Context:PVOID, Name8dot3:PVOID
comment '
RtlGenerate8dot3Name (
    IN PUNICODE_STRING              Name,
    IN BOOLEAN                      AllowExtendedCharacters,
    IN OUT PGENERATE_NAME_CONTEXT   Context,
    OUT PUNICODE_STRING             Name8dot3):VOID
' 

RtlGetCompressionWorkSpaceSize	proto CompressionFormatAndEngine:USHORT, CompressBufferWorkSpaceSize:PULONG, CompressFragmentWorkSpaceSize:PULONG
comment '
RtlGetCompressionWorkSpaceSize (
    IN USHORT   CompressionFormatAndEngine,
    OUT PULONG  CompressBufferWorkSpaceSize,
    OUT PULONG  CompressFragmentWorkSpaceSize):NTSTATUS
' 

RtlIsNameLegalDOS8Dot3	proto UnicodeName:PVOID, AnsiName:PVOID, Unknown:PBOOLEAN
comment '
RtlIsNameLegalDOS8Dot3 (
    IN PUNICODE_STRING UnicodeName,
    IN PANSI_STRING    AnsiName,
    PBOOLEAN           Unknown):BOOLEAN
' 

RtlReserveChunk	proto CompressionFormat:USHORT, CompressedBuffer:PUCHAR, EndOfCompressedBufferPlus1:PUCHAR, ChunkBuffer:PUCHAR, ChunkSize:ULONG
comment '
RtlReserveChunk (
    IN USHORT       CompressionFormat,
    IN OUT PUCHAR   *CompressedBuffer,
    IN PUCHAR       EndOfCompressedBufferPlus1,
    OUT PUCHAR      *ChunkBuffer,
    IN ULONG        ChunkSize):NTSTATUS
'  

ACL_REVISION		equ 2
ACL_REVISION_DS	equ 4

ACL_REVISION1		equ 1
ACL_REVISION2		equ 2
MIN_ACL_REVISION	equ ACL_REVISION2
ACL_REVISION3		equ 3
ACL_REVISION4		equ 4
MAX_ACL_REVISION	equ ACL_REVISION4

ACL STRUCT		; sizeof = 08h
	AclRevision	BYTE		?	; 0000h
	Sbz1			BYTE		?	; 0001h
	AclSize		WORD		?	; 0002h
	AceCount		WORD		?	; 0004h
	Sbz2			WORD		?	; 0006h
ACL ENDS
PACL typedef PTR ACL

RtlSelfRelativeToAbsoluteSD	proto SelfRelativeSD:PVOID, AbsoluteSD:PVOID, AbsoluteSDSize:PULONG, Dacl:PACL, DaclSize:PULONG, Sacl:PACL, 
SaclSize:PULONG, Owner:PSID, OwnerSize:PULONG, PrimaryGroup:PSID, PrimaryGroupSize:PULONG
comment '
RtlSelfRelativeToAbsoluteSD (
    IN PSECURITY_DESCRIPTOR     SelfRelativeSD,
    OUT PSECURITY_DESCRIPTOR    AbsoluteSD,
    IN PULONG                   AbsoluteSDSize,
    IN PACL                     Dacl,
    IN PULONG                   DaclSize,
    IN PACL                     Sacl,
    IN PULONG                   SaclSize,
    IN PSID                     Owner,
    IN PULONG                   OwnerSize,
    IN PSID                     PrimaryGroup,
    IN PULONG                   PrimaryGroupSize):NTSTATUS
' 

RtlGetCallersAddress proto CallersAddress:PVOID, CallersCaller:PVOID
comment '
RtlGetCallersAddress(
OUT PVOID *CallersAddress,
OUT PVOID *CallersCaller):VOID
' 

RtlWalkFrameChain proto Callers:PVOID, Count:ULONG, Flags:ULONG
comment '
RtlWalkFrameChain(
    OUT PVOID *Callers,
    IN ULONG Count,
    IN ULONG Flags):ULONG
' 

;------------------------------------------------------ Synchronization ---------------------------------------------------
RtlEnterCriticalSection	proto CriticalSection:PRTL_CRITICAL_SECTION
comment '
RtlEnterCriticalSection(
IN PRTL_CRITICAL_SECTION CriticalSection):NTSTATUS
' 

RtlLeaveCriticalSection	proto CriticalSection:PRTL_CRITICAL_SECTION
comment '
RtlLeaveCriticalSection(
IN PRTL_CRITICAL_SECTION CriticalSection):NTSTATUS
' 

RtlTryEnterCriticalSection proto CriticalSection:PRTL_CRITICAL_SECTION
comment '
RtlTryEnterCriticalSection(
IN PRTL_CRITICAL_SECTION CriticalSection):BOOLEAN
' 

RtlInitializeCriticalSection	proto CriticalSection:PRTL_CRITICAL_SECTION
comment '
RtlInitializeCriticalSection(
OUT PRTL_CRITICAL_SECTION CriticalSection):NTSTATUS'

RtlEnableEarlyCriticalSectionEventCreation proto
comment '
RtlEnableEarlyCriticalSectionEventCreation():VOID'

RtlInitializeCriticalSectionAndSpinCount proto CriticalSection:PRTL_CRITICAL_SECTION, SpinCount:ULONG
comment '
RtlInitializeCriticalSectionAndSpinCount(
IN PRTL_CRITICAL_SECTION CriticalSection,
IN ULONG SpinCount):NTSTATUS'

RtlSetCriticalSectionSpinCount proto CriticalSection:PRTL_CRITICAL_SECTION, SpinCount:ULONG
comment '
RtlSetCriticalSectionSpinCount(
IN OUT PRTL_CRITICAL_SECTION CriticalSection,
IN ULONG SpinCount):ULONG'

RtlDeleteCriticalSection	proto CriticalSection:PRTL_CRITICAL_SECTION
comment '
RtlDeleteCriticalSection(
IN PRTL_CRITICAL_SECTION CriticalSection):NTSTATUS'

RtlpWaitForCriticalSection proto CriticalSection:PRTL_CRITICAL_SECTION
comment '
RtlpWaitForCriticalSection(
IN PRTL_CRITICAL_SECTION CriticalSection):BOOLEAN
' 

RtlCheckForOrphanedCriticalSections proto ThreadHandle:HANDLE
comment '
RtlCheckForOrphanedCriticalSections(
IN HANDLE hThread):VOID'

;RtlpNotOwnerCriticalSection
;RtlpUnWaitCriticalSection

RTL_RESOURCE struct
CriticalSection		RTL_CRITICAL_SECTION <>
SharedSemaphore		HANDLE ?
NumberOfWaitingShared	ULONG ?
ExclusiveSemaphore		HANDLE ?
NumberOfWaitingExclusive	ULONG ?
;The following indicates the current state of the resource
;<0 the resource is acquired for exclusive access with the absolute value indicating the number of recursive accesses to the resource
;0 the resource is available
;>0 the resource is acquired for shared access with the value indicating the number of shared accesses to the resource
NumberOfActive			LONG ?
ExclusiveOwnerThread	HANDLE ?
Flags				ULONG ?	;RTL_RESOURCE_FLAG_
DebugInfo				PVOID ?	;PRTL_RESOURCE_DEBUG ?
RTL_RESOURCE ends
PRTL_RESOURCE typedef ptr RTL_RESOURCE

RTL_RESOURCE_FLAG_LONG_TERM	equ 1

RtlInitializeResource proto Resource:PRTL_RESOURCE
comment '
RtlInitializeResource(
OUT PRTL_RESOURCE Resource):VOID'

RtlAcquireResourceShared proto Resource:PRTL_RESOURCE, _Wait:BOOLEAN
comment '
RtlAcquireResourceShared(
IN OUT PRTL_RESOURCE Resource,
IN BOOLEAN Wait):BOOLEAN'

RtlAcquireResourceExclusive proto Resource:PRTL_RESOURCE, _Wait:BOOLEAN
comment '
RtlAcquireResourceExclusive(
IN OUT PRTL_RESOURCE Resource,
IN BOOLEAN Wait):BOOLEAN'

RtlReleaseResource proto Resource:PRTL_RESOURCE
comment '
RtlReleaseResource(
IN OUT PRTL_RESOURCE Resource):VOID'

RtlConvertSharedToExclusive proto Resource:PRTL_RESOURCE
comment '
RtlConvertSharedToExclusive(
IN OUT PRTL_RESOURCE Resource):VOID'

RtlConvertExclusiveToShared proto Resource:PRTL_RESOURCE
comment '
RtlConvertExclusiveToShared(
IN OUT PRTL_RESOURCE Resource):VOID'

RtlDeleteResource proto Resource:PRTL_RESOURCE
comment '
RtlDeleteResource(
IN OUT PRTL_RESOURCE Resource):VOID'

RtlAcquirePebLock	proto	;Вход в критическую секцию
comment '
RtlAcquirePebLock proc
	_setseh_
	assume fs:nothing
	mov eax,dword ptr fs:[18h]
	assume eax:PTEB
	mov eax,[eax].Peb
	assume eax:PPEB
	push [eax].FastPebLock
	Call [eax].FastPebLockRoutine
	_endseh_
	ret
RtlAcquirePebLock endp
' 

RtlReleasePebLock	proto	;Выход из критической секции
comment '
	_setseh_
	assume fs:nothing
	mov eax,dword ptr fs:[18h]
	assume eax:PTEB
	mov eax,[eax].Peb
	assume eax:PPEB
	push [eax].FastPebLock
	Call [eax].FastPebUnlockRoutine
	_endseh_
	ret
' 

ZwWaitForSingleObject	proto Handle:HANDLE, Alertable:BOOLEAN, Timeout:PLARGE_INTEGER
comment '
ZwWaitForSingleObject(
IN HANDLE Handle,
IN BOOLEAN Alertable,
IN PLARGE_INTEGER Timeout OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS, STATUS_ALERTED, STATUS_USER_APC, STATUS_TIMEOUT, STATUS_ABANDONED, 
or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwSignalAndWaitForSingleObject	proto HandleToSignal:HANDLE, HandleToWait:HANDLE, Alertable:BOOLEAN, Timeout:PLARGE_INTEGER
comment '
ZwSignalAndWaitForSingleObject(
IN HANDLE HandleToSignal,
IN HANDLE HandleToWait,
IN BOOLEAN Alertable,
IN PLARGE_INTEGER Timeout OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS, STATUS_ALERTED, STATUS_USER_APC, STATUS_TIMEOUT, STATUS_ABANDONED, 
or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwWaitForMultipleObjects	proto HandleCount:ULONG,Handles:PHANDLE,WaitType:DWORD,Alertable:BOOLEAN, Timeout:PLARGE_INTEGER
comment '
NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForMultipleObjects(
IN ULONG HandleCount,
IN PHANDLE Handles,
IN WAIT_TYPE WaitType,
IN BOOLEAN Alertable,
IN PLARGE_INTEGER Timeout OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS, STATUS_ALERTED, STATUS_USER_APC, STATUS_TIMEOUT,
STATUS_ABANDONED, STATUS_ABANDONED_WAIT_0 to STATUS_ABANDONED_WAIT_63,
STATUS_WAIT_0 to STATUS_WAIT_63, or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

;typedef enum _WAIT_TYPE
WaitAll	equ 0	;Wait for any handle to be signaled
WaitAny	equ 1	;Wait for all handles to be signaled

ZwCreateTimer	proto TimerHandle:PHANDLE, DesiredAccess:DWORD, ObjectAttributes:DWORD, TimerType:DWORD
comment '
ZwCreateTimer(
OUT PHANDLE TimerHandle,
IN ACCESS_MASK DesiredAccess,		;TIMER_
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN TIMER_TYPE TimerType):NTSTATUS

TIMER_QUERY_STATE Query access
TIMER_MODIFY_STATE Modify access
TIMER_ALL_ACCESS All of the preceding + STANDARD_RIGHTS

Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED.
' 

;typedef enum _TIMER_TYPE {
NotificationTimer		equ 0	;A manual-reset timer
SynchronizationTimer	equ 1	;An auto-reset timer

ZwOpenTimer	proto TimerHandle:PHANDLE, DesiredAccess:DWORD, ObjectAttributes:DWORD
comment '
ZwOpenTimer(
OUT PHANDLE TimerHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS

TIMER_QUERY_STATE Query access
TIMER_MODIFY_STATE Modify access
TIMER_ALL_ACCESS All of the preceding + STANDARD_RIGHTS_ALL

Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or
STATUS_OBJECT_NAME_NOT_FOUND.
' 

ZwCancelTimer	proto TimerHandle:HANDLE, PreviousState:PBOOLEAN
comment '
ZwCancelTimer(
IN HANDLE TimerHandle,
OUT PBOOLEAN PreviousState OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwSetTimer	proto TimerHandle:HANDLE,DueTime:PLARGE_INTEGER,TimerApcRoutine:DWORD,TimerContext:PVOID,Resume:BOOLEAN,Period:LONG,PreviousState:PBOOLEAN
comment '
ZwSetTimer(
IN HANDLE TimerHandle,
IN PLARGE_INTEGER DueTime,
IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
IN PVOID TimerContext,
IN BOOLEAN Resume,
IN LONG Period,
OUT PBOOLEAN PreviousState OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS, STATUS_TIMER_RESUME_IGNORED or an error status, such as
STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwQueryTimer	proto TimerHandle:HANDLE, TimerInformationClass:DWORD, TimerInformation:PVOID, TimerInformationLength:ULONG, ResultLength:PULONG
comment '
ZwQueryTimer(
IN HANDLE TimerHandle,
IN TIMER_INFORMATION_CLASS TimerInformationClass,
OUT PVOID TimerInformation,
IN ULONG TimerInformationLength,
OUT PULONG ResultLength OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, or STATUS_INFO_LENGTH_MISMATCH.
' 

;typedef enum _TIMER_INFORMATION_CLASS {
TimerBasicInformation	equ 0

;TimerBasicInformation
TIMER_BASIC_INFORMATION  struct
TimeRemaining		equ LARGE_INTEGER <>
SignalState		equ BOOLEAN ?
TIMER_BASIC_INFORMATION ends
PTIMER_BASIC_INFORMATION typedef PTR TIMER_BASIC_INFORMATION

ZwCreateEvent	proto EventHandle:HANDLE, DesiredAccess:DWORD, ObjectAttributes:PVOID, EventType:DWORD, InitialState:BOOLEAN
comment '
ZwCreateEvent(
OUT PHANDLE EventHandle,
IN ACCESS_MASK DesiredAccess,		;EVENT_
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN EVENT_TYPE EventType,
IN BOOLEAN InitialState):NTSTATUS

EVENT_QUERY_STATE Query access
EVENT_MODIFY_STATE Modify access
EVENT_ALL_ACCESS All of the preceding + STANDARD_RIGHTS_ALL

Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED.
' 

;typedef enum _EVENT_TYPE {
NotificationEvent		equ 0	;A manual-reset event
SynchronizationEvent	equ 1	;An auto-reset event

ZwOpenEvent	proto EventHandle:HANDLE, DesiredAccess:DWORD, ObjectAttributes:PVOID
comment '
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenEvent(
OUT PHANDLE EventHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_OBJECT_NAME_NOT_FOUND.
' 

EVENT_QUERY_STATE		equ 0001
EVENT_MODIFY_STATE		equ 0002  ; winnt
EVENT_ALL_ACCESS		equ (STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or 3) ; winnt

ZwSetEvent	proto EventHandle:HANDLE, PreviousState:PULONG
comment '
ZwSetEvent(
IN HANDLE EventHandle,
OUT PULONG PreviousState OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or
STATUS_INVALID_HANDLE.
' 

ZwPulseEvent	proto EventHandle:HANDLE, PreviousState:PULONG
comment '
ZwPulseEvent(
IN HANDLE EventHandle,
OUT PULONG PreviousState OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwResetEvent	proto EventHandle:HANDLE, PreviousState:PULONG
comment '
ZwResetEvent(
IN HANDLE EventHandle,
OUT PULONG PreviousState OPTIONAL):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwClearEvent	proto EventHandle:HANDLE, PreviousState:PULONG
comment '
ZwClearEvent(
IN HANDLE EventHandle):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE.
' 

ZwQueryEvent	proto EventHandle:HANDLE,EventInformationClass:dword,EventInformation:PVOID,EventInformationLength:ULONG,ResultLength:PULONG
comment '
ZwQueryEvent(
IN HANDLE EventHandle,
IN EVENT_INFORMATION_CLASS EventInformationClass,
OUT PVOID EventInformation,
IN ULONG EventInformationLength,
OUT PULONG ResultLength OPTIONAL):NTSTATUS
;Возвращает информацию об обьекте событие
;Хэндл должен иметь тип доступа  EVENT_QUERY_STATE
Returns STATUS_SUCCESS or an error status, such as STATUS_ACCESS_DENIED,
STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, or STATUS_INFO_LENGTH_MISMATCH.
' 

;typedef enum _EVENT_INFORMATION_CLASS
EventBasicInformation	equ 0

EVENT_BASIC_INFORMATION struct 
EventType		LONG ?	;NotificationEvent(manual-reset) or SynchronizationEvent(auto-reset)
SignalState	LONG ?	;Если не ноль то событие находится в сигнализирующем состоянии
EVENT_BASIC_INFORMATION ends
PEVENT_BASIC_INFORMATION typedef EVENT_BASIC_INFORMATION

ZwCreateSemaphore proto SemaphoreHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES, InitialCount:LONG, MaximumCount:LONG
comment '
ZwCreateSemaphore(
OUT PHANDLE SemaphoreHandle,
IN ACCESS_MASK DesiredAccess,		;SEMAPHORE_
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN LONG InitialCount,
IN LONG MaximumCount):NTSTATUS
' 

;DesiredAccess
;SEMAPHORE_QUERY_STATE 	equ 0001		;Query access
SEMAPHORE_MODIFY_STATE	equ 0002h		;Modify access
SEMAPHORE_ALL_ACCESS 	equ (STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or 3) 

ZwOpenSemaphore proto SemaphoreHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwOpenSemaphore(
OUT PHANDLE SemaphoreHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

ZwReleaseSemaphore proto SemaphoreHandle:HANDLE, ReleaseCount:LONG, PreviousCount:PLONG
comment '
ZwReleaseSemaphore(
IN HANDLE SemaphoreHandle,
IN LONG ReleaseCount,
OUT PLONG PreviousCount OPTIONAL):NTSTATUS
' 

ZwQuerySemaphore proto SemaphoreHandle:HANDLE, SemaphoreInformationClass:ULONG, SemaphoreInformation:PVOID, SemaphoreInformationLength:ULONG, ResultLength:PULONG
comment '
ZwQuerySemaphore(
IN HANDLE SemaphoreHandle,
IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
OUT PVOID SemaphoreInformation,
IN ULONG SemaphoreInformationLength,
OUT PULONG ResultLength OPTIONAL):NTSTATUS
' 

SemaphoreBasicInformation	equ 0

SEMAPHORE_BASIC_INFORMATION struct
CurrentCount	LONG ?
MaximumCount	LONG	?
SEMAPHORE_BASIC_INFORMATION ends
PSEMAPHORE_BASIC_INFORMATION typedef ptr SEMAPHORE_BASIC_INFORMATION

ZwCreateMutant proto MutantHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES, InitialOwner:BOOLEAN
comment '
ZwCreateMutant(
OUT PHANDLE MutantHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN BOOLEAN InitialOwner):NTSTATUS
' 

ZwOpenMutant proto MutantHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwOpenMutant(
OUT PHANDLE MutantHandle,
IN ACCESS_MASK DesiredAccess,		;MUTANT_
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

;DesiredAccess
MUTANT_QUERY_STATE 		equ 0001h		;Query access
MUTANT_ALL_ACCESS equ (STANDARD_RIGHTS_REQUIRED+SYNCHRONIZE+ MUTANT_QUERY_STATE)

ZwReleaseMutant proto MutantHandle:HANDLE, PreviousState:PULONG
comment '
ZwReleaseMutant(
IN HANDLE MutantHandle,
OUT PULONG PreviousState):NTSTATUS
' 

ZwQueryMutant proto MutantHandle:HANDLE, MutantInformationClass:ULONG, MutantInformation:PVOID, MutantInformationLength:ULONG, ResultLength:PULONG
comment '
ZwQueryMutant(
IN HANDLE MutantHandle,
IN MUTANT_INFORMATION_CLASS MutantInformationClass,
OUT PVOID MutantInformation,
IN ULONG MutantInformationLength,
OUT PULONG ResultLength OPTIONAL):NTSTATUS
' 

MutantBasicInformation	equ 0

MUTANT_BASIC_INFORMATION struct
SignalState	LONG ?
Owned		BOOLEAN ?
Abandoned		BOOLEAN ?
MUTANT_BASIC_INFORMATION ends
PMUTANT_BASIC_INFORMATION typedef ptr MUTANT_BASIC_INFORMATION

ZwCreateIoCompletion proto IoCompletionHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES, NumberOfConcurrentThreads:ULONG
comment '
ZwCreateIoCompletion(
OUT PHANDLE IoCompletionHandle,
IN ACCESS_MASK DesiredAccess,		;IO_COMPLETION_
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN ULONG NumberOfConcurrentThreads):NTSTATUS
' 

;DesiredAccess
;QUERY_STATE Query access
;IO_COMPLETION_MODIFY_STATE Modify access
;IO_COMPLETION_ALL_ACCESS All of the preceding + STANDARD_RIGHTS_ALL

ZwOpenIoCompletion proto IoCompletionHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwOpenIoCompletion(
OUT PHANDLE IoCompletionHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

;DesiredAccess
;IO_COMPLETION_QUERY_STATE 	;Query access
IO_COMPLETION_MODIFY_STATE	equ 2h		;Modify access
IO_COMPLETION_ALL_ACCESS 	equ STANDARD_RIGHTS_REQUIRED OR SYNCHRONIZE OR 3h	;All of the preceding + STANDARD_RIGHTS_ALL

ZwSetIoCompletion proto IoCompletionHandle:HANDLE, CompletionKey:ULONG, CompletionValue:ULONG, Status:NTSTATUS, Information:ULONG
comment '
ZwSetIoCompletion(
IN HANDLE IoCompletionHandle,
IN ULONG CompletionKey,
IN ULONG CompletionValue,
IN NTSTATUS Status,
IN ULONG Information):NTSTATUS
' 

ZwRemoveIoCompletion proto IoCompletionHandle:HANDLE, CompletionKey:PULONG, CompletionValue:PULONG, IoStatusBlock:PIO_STATUS_BLOCK, Timeout:PLARGE_INTEGER
comment '
ZwRemoveIoCompletion(
IN HANDLE IoCompletionHandle,
OUT PULONG CompletionKey,
OUT PULONG CompletionValue,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PLARGE_INTEGER Timeout OPTIONAL):NTSTATUS
' 

ZwQueryIoCompletion proto IoCompletionHandle:HANDLE, IoCompletionInformationClass:ULONG, IoCompletionInformation:PVOID, IoCompletionInformationLength:ULONG, ResultLength:PULONG
comment '
ZwQueryIoCompletion(
IN HANDLE IoCompletionHandle,
IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
OUT PVOID IoCompletionInformation,
IN ULONG IoCompletionInformationLength,
OUT PULONG ResultLength OPTIONAL):NTSTATUS
' 

IoCompletionBasicInformation	equ 0

IO_COMPLETION_BASIC_INFORMATION struct
SignalState	LONG ?
IO_COMPLETION_BASIC_INFORMATION ends
PIO_COMPLETION_BASIC_INFORMATION typedef ptr IO_COMPLETION_BASIC_INFORMATION

ZwCreateEventPair proto EventPairHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwCreateEventPair(
OUT PHANDLE EventPairHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

ZwOpenEventPair proto EventPairHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwOpenEventPair(
OUT PHANDLE EventPairHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS
' 

ZwWaitLowEventPair proto EventPairHandle:HANDLE
comment '
ZwWaitLowEventPair(
IN HANDLE EventPairHandle):NTSTATUS
' 

ZwWaitHighEventPair proto EventPairHandle:HANDLE
comment '
ZwWaitHighEventPair(
IN HANDLE EventPairHandle):NTSTATUS
' 

ZwSetLowWaitHighEventPair proto EventPairHandle:HANDLE
comment '
ZwSetLowWaitHighEventPair(
IN HANDLE EventPairHandle):NTSTATUS
' 

ZwSetHighWaitLowEventPair proto EventPairHandle:HANDLE
comment '
ZwSetHighWaitLowEventPair(
IN HANDLE EventPairHandle):NTSTATUS
' 

ZwSetLowEventPair proto EventPairHandle:HANDLE
comment '
ZwSetLowEventPair(
IN HANDLE EventPairHandle):NTSTATUS
' 

ZwSetHighEventPair proto EventPairHandle:HANDLE
comment '
ZwSetHighEventPair(
IN HANDLE EventPairHandle):NTSTATUS
' 

;----------------------------------------------------------- Strings -------------------------------------------------------
RtlInitString	proto DestinationString:PVOID, SourceString:PVOID
comment ' 
RtlInitString(
    IN OUT PSTRING  DestinationString,
    IN PCSZ  SourceString):VOID
' 

RtlInitUnicodeString	proto DestinationString:PUNICODE_STRING, SourceString:PVOID
comment ' 
RtlInitUnicodeString(
    IN OUT PUNICODE_STRING  DestinationString,
    IN PCWSTR  SourceString):VOID
'     
    
RtlInitAnsiString	proto DestinationString:PANSI_STRING, SourceString:PVOID
comment '
RtlInitAnsiString(
    IN OUT PANSI_STRING  DestinationString,
    IN PCSZ  SourceString):VOID
'     
    
RtlFreeAnsiString	proto AnsiString:PANSI_STRING
comment '
RtlFreeAnsiString(
    IN PANSI_STRING  AnsiString):VOID 
'     
    
RtlFreeUnicodeString proto UnicodeString:PUNICODE_STRING
comment '
RtlFreeUnicodeString(
IN PUNICODE_STRING UnicodeString):NTSTATUS
'     
    
RtlFreeOemString	proto OemString:PVOID
comment '
RtlFreeOemString(
IN POEM_STRING  OemString):VOID
'     
    
RtlUnicodeStringToOemString	proto DestinationString:PVOID,SourceString:PVOID,AllocateDestinationString:BOOLEAN
comment '
RtlUnicodeStringToOemString (
    OUT POEM_STRING     DestinationString,
    IN PUNICODE_STRING  SourceString,
    IN BOOLEAN          AllocateDestinationString):NTSTATUS
'     
    
RtlOemStringToUnicodeString	proto DestinationString:PVOID, SourceString:PVOID, AllocateDestinationString:BOOLEAN
comment '
RtlOemStringToUnicodeString (
    OUT PUNICODE_STRING DestinationString,
    IN POEM_STRING      SourceString,
    IN BOOLEAN          AllocateDestinationString):NTSTATUS
'     

RtlUnicodeStringToAnsiString	proto DestinationString:PANSI_STRING, SourceString:PUNICODE_STRING, AllocateDestinationString:BOOLEAN
comment '
RtlUnicodeStringToAnsiString(
    IN OUT PANSI_STRING  DestinationString,
    IN PUNICODE_STRING  SourceString,
    IN BOOLEAN  AllocateDestinationString):NTSTATUS 
' 

RtlUnicodeStringToAnsiSize	proto UnicodeString:PUNICODE_STRING
comment '
RtlUnicodeStringToAnsiSize(
    IN PUNICODE_STRING  UnicodeString):ULONG
' 

RtlOemStringToUnicodeSize	proto OemString:PVOID
comment '
RtlOemStringToUnicodeSize(
	IN POEM_STRING  OemString):ULONG
' 

RtlUnicodeStringToOemSize	proto UnicodeString:PUNICODE_STRING
comment '
    IN PUNICODE_STRING  UnicodeString):ULONG
' 

RtlxOemStringToUnicodeSize	proto OemString:PVOID
comment '
RtlxOemStringToUnicodeSize (
    IN POEM_STRING OemString):ULONG
' 

RtlxUnicodeStringToAnsiSize	proto UnicodeString:PVOID
comment '
RtlxUnicodeStringToAnsiSize (
    IN PCUNICODE_STRING UnicodeString):ULONG
' 

RtlxUnicodeStringToOemSize	proto  UnicodeString:PVOID
comment '
RtlxUnicodeStringToOemSize (
    IN PUNICODE_STRING UnicodeString
):ULONG
' 

RtlEqualUnicodeString proto stdcall :DWORD, :DWORD, :DWORD
comment '
RtlEqualUnicodeString(
    IN CONST UNICODE_STRING  *String1,
    IN CONST UNICODE_STRING  *String2,
    IN BOOLEAN  CaseInSensitive):BOOLEAN 
Returns TRUE if the two Unicode strings are equal.
' 

RtlCompareString	proto String1:PVOID, String2:PVOID, CaseInSensitive:BOOLEAN
comment '
RtlCompareString(
    IN PSTRING  String1,
    IN PSTRING  String2,
    BOOLEAN  CaseInSensitive):LONG
RtlCompareString returns a signed value that gives the results of the comparison: 
Zero: 	String1 equals String2. 
< Zero: 	String1 is less than String2. 
> Zero: 	String1 is greater than String2.
' 

RtlCompareUnicodeString	proto String1:PUNICODE_STRING, String2:PUNICODE_STRING, CaseInSensitive:BOOLEAN
comment 'RtlCompareUnicodeString(
    IN PUNICODE_STRING  String1,
    IN PUNICODE_STRING  String2,
    IN BOOLEAN  CaseInSensitive:LONG
Zero:	String1 equals String2. 
< Zero:	String1 is less than String2. 
> Zero:	String1 is greater than String2. 
' 

RtlEqualString	proto String1:PVOID, String1:PVOID, CaseInSensitive:BOOLEAN
comment ' 
RtlEqualString(
    IN PSTRING  String1,
    IN PSTRING  String2,
    IN BOOLEAN  CaseInSensitive):BOOLEAN
Returns TRUE if the two strings are equal, otherwise it returns FALSE.
' 

RtlCopyUnicodeString	proto DestinationString:PVOID, SourceString:PVOID
comment '
RtlCopyUnicodeString(
    IN OUT PUNICODE_STRING  DestinationString,
    IN PUNICODE_STRING  SourceString):VOID 
' 

RtlCopyString	proto DestinationString:PVOID, SourceString:PVOID
comment '
RtlCopyString(
    IN OUT PSTRING  DestinationString,
    IN PSTRING  SourceString  OPTIONAL):VOID
' 

RtlUpcaseUnicodeString	proto DestinationString:PUNICODE_STRING, SourceString:PUNICODE_STRING, AllocateDestinationString:BOOLEAN
comment '
RtlUpcaseUnicodeString(
    IN OUT PUNICODE_STRING  DestinationString  OPTIONAL,
    IN PUNICODE_STRING  SourceString,
    IN BOOLEAN  AllocateDestinationString):NTSTATUS 
' 

RtlUnicodeStringToInteger	proto String:PUNICODE_STRING, Base:ULONG, Value:PULONG
comment '
RtlUnicodeStringToInteger(
    IN PUNICODE_STRING  String,
    IN ULONG  Base  OPTIONAL,
    OUT PULONG  Value):NTSTATUS
' 

RtlIntegerToUnicodeString	proto Value:ULONG, Base:ULONG, String:PUNICODE_STRING
comment '
RtlIntegerToUnicodeString(
    IN ULONG  Value,
    IN ULONG  Base  OPTIONAL,
    IN OUT PUNICODE_STRING  String):NTSTATUS
' 

RtlInt64ToUnicodeString	proto ValueH:ULONG, ValueL:ULONG, Base:ULONG, String:PUNICODE_STRING
comment '
RtlInt64ToUnicodeString (
    IN ULONGLONG  Value,
    IN ULONG  Base OPTIONAL,
    IN OUT PUNICODE_STRING  String):NTSTATUS
Value Base:
16		Hexadecimal 
8		Octal 
2		Binary 
0 or 10	Decimal 
' 

RtlStringFromGUID	proto Guid:DWORD, GuidString:PUNICODE_STRING
comment '
RtlStringFromGUID( 
    IN REFGUID  Guid, 
    OUT PUNICODE_STRING  GuidString):NTSTATUS
' 

RtlCreateUnicodeStringFromAsciiz	proto Destination:PUNICODE_STRING, String:PCHAR
comment '
RtlCreateUnicodeStringFromAsciiz(
OUT PUNICODE_STRING Destination,
IN PCHAR String)
' 

RtlAppendUnicodeToString	proto Destination:PUNICODE_STRING, String:PVOID	;PWIDECHAR
comment '
RtlAppendUnicodeToString(
OUT PUNICODE_STRING Destination,
IN PWIDECHAR String)
' 

RtlCharToInteger proto String:PCHAR, Base:ULONG, Value:PULONG
comment '
RtlCharToInteger(
    PCSZ String,
    ULONG Base,
    PULONG Value):NTSTATUS
' 

RtlUpperChar proto Character:CHAR
comment '
RtlUpperChar (
    CHAR Character):CHAR
' 

RtlUpperString proto DestinationString:PSTRING, SourceString:PSTRING
comment '
RtlUpperString(
    PSTRING DestinationString,
    const STRING * SourceString):VOID
' 

RtlAppendUnicodeStringToString proto Destination:PUNICODE_STRING, Source:PUNICODE_STRING
comment '
RtlAppendUnicodeStringToString (
    PUNICODE_STRING Destination,
    PCUNICODE_STRING Source):NTSTATUS
' 

RtlAnsiStringToUnicodeString proto DestinationString:PUNICODE_STRING, SourceString:PANSI_STRING, AllocateDestinationString:BOOLEAN
comment '
RtlAnsiStringToUnicodeString(
    PUNICODE_STRING DestinationString,
    PCANSI_STRING SourceString,
    BOOLEAN AllocateDestinationString):NTSTATUS
' 

HASH_STRING_ALGORITHM_DEFAULT		equ (0)
HASH_STRING_ALGORITHM_X65599		equ (1)
HASH_STRING_ALGORITHM_INVALID		equ (0ffffffffh)

RtlHashUnicodeString proto String:DWORD, CaseInSensitive:BOOLEAN, HashAlgorithm:ULONG, HashValue:PULONG
comment '
RtlHashUnicodeString(
    IN const UNICODE_STRING *String,
    IN BOOLEAN CaseInSensitive,
    IN ULONG HashAlgorithm,
    OUT PULONG HashValue):NTSTATUS
' 

RtlPrefixUnicodeString proto String1:PUNICODE_STRING, String2:PUNICODE_STRING, CaseInSensitive:BOOLEAN
comment '
RtlPrefixUnicodeString(
    IN PUNICODE_STRING String1,
    IN PUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive):BOOLEAN
' 

RtlUpcaseUnicodeChar proto SourceCharacter:WCHAR
comment '
RtlUpcaseUnicodeChar(
    WCHAR SourceCharacter):WCHAR
' 

RtlDowncaseUnicodeChar proto SourceCharacter:WCHAR
comment '
RtlDowncaseUnicodeChar(
    WCHAR SourceCharacter):WCHAR
' 

RtlxAnsiStringToUnicodeSize proto AnsiString:PANSI_STRING
comment '
RtlxAnsiStringToUnicodeSize(
    PCANSI_STRING AnsiString):ULONG
' 

RtlAnsiStringToUnicodeSize proto AnsiString:PANSI_STRING
comment '
RtlAnsiStringToUnicodeSize(
      PANSI_STRING AnsiString):ULONG
' 

RtlGUIDFromString proto GuidString:PUNICODE_STRING, Guid:DWORD
comment '
RtlGUIDFromString(
    IN PUNICODE_STRING GuidString,
    OUT GUID* Guid):NTSTATUS
' 

RtlIntegerToChar                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlLargeIntegerToChar                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD

RtlCreateUnicodeString                             proto stdcall :DWORD, :DWORD
RtlRunDecodeUnicodeString                          proto stdcall :DWORD, :DWORD
RtlRunEncodeUnicodeString                          proto stdcall :DWORD, :DWORD
RtlAnsiCharToUnicodeChar                           proto stdcall :DWORD
RtlAppendAsciizToString                            proto stdcall :DWORD, :DWORD
RtlAppendStringToString                            proto stdcall :DWORD, :DWORD
RtlUnicodeStringToCountedOemString                 proto stdcall :DWORD, :DWORD, :DWORD


RtlUnicodeToCustomCPN                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlUnicodeToMultiByteN                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlUnicodeToMultiByteSize                          proto stdcall :DWORD, :DWORD, :DWORD
RtlUnicodeToOemN                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlUpcaseUnicodeStringToAnsiString                 proto stdcall :DWORD, :DWORD, :DWORD
RtlUpcaseUnicodeStringToCountedOemString           proto stdcall :DWORD, :DWORD, :DWORD
RtlUpcaseUnicodeStringToOemString                  proto stdcall :DWORD, :DWORD, :DWORD
RtlUpcaseUnicodeToCustomCPN                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlUpcaseUnicodeToMultiByteN                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlUpcaseUnicodeToOemN                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlMultiByteToUnicodeN                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlMultiByteToUnicodeSize                          proto stdcall :DWORD, :DWORD, :DWORD
RtlConsoleMultiByteToUnicodeN                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlDowncaseUnicodeString                           proto stdcall :DWORD, :DWORD, :DWORD
RtlEraseUnicodeString                              proto stdcall :DWORD
RtlInitCodePageTable                               proto stdcall :DWORD, :DWORD
RtlInitNlsTables                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlOemToUnicodeN                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlPrefixString                                    proto stdcall :DWORD, :DWORD, :DWORD

;-----------------------------------------------------------------------------------------------------------------------
SLIST_ENTRY struct
Next		PVOID ?	;PSLIST_ENTRY
SLIST_ENTRY ends
PSLIST_ENTRY typedef ptr SLIST_ENTRY

SLIST_HEADER struct
Alignment		ULONGLONG ?
Next			SLIST_ENTRY <>
Depth		USHORT ?
Sequence		USHORT ?
SLIST_HEADER ends
PSLIST_HEADER typedef ptr SLIST_HEADER

RtlInitializeSListHead proto ListHead:PSLIST_HEADER
comment '
RtlInitializeSListHead(
	IN PSLIST_HEADER ListHead):VOID
' 

RtlFirstEntrySList proto ListHead:DWORD
comment '
RtlFirstEntrySList(
	IN const SLIST_HEADER *ListHead):PSLIST_ENTRY
' 

RtlInterlockedPopEntrySList proto ListHead:PSLIST_HEADER
comment '
RtlInterlockedPopEntrySList(
	IN PSLIST_HEADER ListHead):PSLIST_ENTRY
' 

RtlInterlockedPushEntrySList proto ListHead:PSLIST_HEADER, ListEntry:PSLIST_ENTRY
comment '
RtlInterlockedPushEntrySList(
    IN PSLIST_HEADER ListHead,
    IN PSLIST_ENTRY ListEntry):PSLIST_ENTRY
' 

RtlInterlockedFlushSList proto ListHead:PSLIST_HEADER
comment '
RtlInterlockedFlushSList(
    IN PSLIST_HEADER ListHead):PSLIST_ENTRY
' 

RtlQueryDepthSList proto ListHead:PSLIST_HEADER
comment '
RtlQueryDepthSList(
    IN PSLIST_HEADER ListHead):WORD 
'     

RtlVerifyVersionInfo proto VersionInfo:PRTL_OSVERSIONINFOEXW, TypeMask:ULONG, ConditionMask:ULONGLONG
comment '
RtlVerifyVersionInfo(
IN PRTL_OSVERSIONINFOEXW VersionInfo,
IN ULONG TypeMask,
IN ULONGLONG  ConditionMask):NTSTATUS
' 

VER_EQUAL			equ 1
VER_GREATER		equ 2
VER_GREATER_EQUAL	equ 3
VER_LESS			equ 4
VER_LESS_EQUAL		equ 5
VER_AND			equ 6
VER_OR			equ 7

VER_CONDITION_MASK	equ 7
VER_NUM_BITS_PER_CONDITION_MASK	equ 3

;RtlVerifyVersionInfo() type mask bits
VER_MINORVERSION		equ 0000001h
VER_MAJORVERSION		equ 0000002h
VER_BUILDNUMBER		equ 0000004h
VER_PLATFORMID			equ 0000008h
VER_SERVICEPACKMINOR	equ 0000010h
VER_SERVICEPACKMAJOR	equ 0000020h
VER_SUITENAME			equ 0000040h
VER_PRODUCT_TYPE		equ 0000080h

;RtlVerifyVersionInfo() os product type values
VER_NT_WORKSTATION			equ 0000001h
VER_NT_DOMAIN_CONTROLLER		equ 0000002h
VER_NT_SERVER				equ 0000003h

;dwPlatformId defines:
VER_PLATFORM_WIN32s			equ 0
VER_PLATFORM_WIN32_WINDOWS	equ 1
VER_PLATFORM_WIN32_NT		equ 2

VerSetConditionMask proto ConditionMask:ULONGLONG, TypeMask:ULONG, Condition:UCHAR
comment '
VerSetConditionMask(
IN ULONGLONG ConditionMask,
IN ULONG TypeMask,
IN UCHAR Condition):ULONGLONG
' 

RtlGetVersion proto lpVersionInformation:PRTL_OSVERSIONINFOW
comment '
RtlGetVersion(
OUT PRTL_OSVERSIONINFOW lpVersionInformation):NTSTATUS
' 

RtlAssert proto FailedAssertion:PVOID, FileName:PVOID, LineNumber:ULONG, Message:PCHAR
comment '
RtlAssert(
PVOID FailedAssertion,
PVOID FileName,
ULONG LineNumber,
PCHAR Message):VOID
' 
;**************************************************************DBG******************************************************************
DbgBreakPoint proto

DbgBreakPointWithStatus proto Status:ULONG
comment '
DbgBreakPointWithStatus(
    IN ULONG Status):VOID
' 

DBG_STATUS_CONTROL_C        equ 1
DBG_STATUS_SYSRQ            equ 2
DBG_STATUS_BUGCHECK_FIRST   equ 3
DBG_STATUS_BUGCHECK_SECOND  equ 4
DBG_STATUS_FATAL            equ 5
DBG_STATUS_DEBUG_CONTROL    equ 6
DBG_STATUS_WORKER           equ 7

comment '
DbgPrint(
    PCH Format,
    ...
    );

ULONG
__cdecl
DbgPrintEx(
    IN ULONG ComponentId,
    IN ULONG Level,
    IN PCH Format,
    ...
    );
    
ULONG
vDbgPrintEx(
    IN ULONG ComponentId,
    IN ULONG Level,
    IN PCH Format,
    va_list arglist
    );

ULONG
vDbgPrintExWithPrefix(
    IN PCH Prefix,
    IN ULONG ComponentId,
    IN ULONG Level,
    IN PCH Format,
    va_list arglist
    );    
    
ULONG
__cdecl
DbgPrintReturnControlC(
    PCH Format,
    ...
    );

NTSYSAPI
NTSTATUS
DbgQueryDebugFilterState(
    IN ULONG ComponentId,
    IN ULONG Level
    );

NTSYSAPI
NTSTATUS
DbgSetDebugFilterState(
    IN ULONG ComponentId,
    IN ULONG Level,
    IN BOOLEAN State
    );    
' 

DbgPrompt                                          proto stdcall :DWORD, :DWORD, :DWORD
DbgSsHandleKmApiMsg                                proto stdcall :DWORD, :DWORD
DbgSsInitialize                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
DbgUiConnectToDbg                                  proto stdcall
DbgUiContinue                                      proto stdcall :DWORD, :DWORD
DbgUiWaitStateChange                               proto stdcall :DWORD, :DWORD
DbgUserBreakPoint                                  proto stdcall
;************************************************************MATCH*******************************************************************

;ACTIVATION_CONTEXT_INFO_CLASS {
ActivationContextBasicInformation			equ 1
ActivationContextDetailedInformation		equ 2
AssemblyDetailedInformationInActivationContext		equ 3
FileInformationInAssemblyOfAssemblyInActivationContext	equ 4

ACTIVATION_CONTEXT_QUERY_INDEX struct
ulAssemblyIndex		DWORD ? 
ulFileIndexInAssembly	DWORD ?
ACTIVATION_CONTEXT_QUERY_INDEX ends
PACTIVATION_CONTEXT_QUERY_INDEX typedef ptr ACTIVATION_CONTEXT_QUERY_INDEX

ACTIVATION_CONTEXT_PATH_TYPE_NONE			equ 1
ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE		equ 2
ACTIVATION_CONTEXT_PATH_TYPE_URL			equ 3
ACTIVATION_CONTEXT_PATH_TYPE_ASSEMBLYREF	equ 4
 
ASSEMBLY_FILE_DETAILED_INFORMATION struct
ulFlags			DWORD ?
ulFilenameLength	DWORD ?
ulPathLength		DWORD ? 
lpFileName		PCWSTR ?
lpFilePath		PCWSTR ?  
ASSEMBLY_FILE_DETAILED_INFORMATION ends
PASSEMBLY_FILE_DETAILED_INFORMATION typedef ptr ASSEMBLY_FILE_DETAILED_INFORMATION

ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION struct
ulFlags				DWORD ?
ulEncodedAssemblyIdentityLength	DWORD ?
ulManifestPathType		DWORD ?	;ACTIVATION_CONTEXT_PATH_TYPE_*
ulManifestPathLength	DWORD ?
liManifestLastWriteTime	LARGE_INTEGER <>	;FILETIME
ulPolicyPathType		DWORD ?	;ACTIVATION_CONTEXT_PATH_TYPE_*
ulPolicyPathLength		DWORD ?
liPolicyLastWriteTime	LARGE_INTEGER <>	;FILETIME
ulMetadataSatelliteRosterIndex	DWORD ?    
ulManifestVersionMajor	DWORD ?	;1
ulManifestVersionMinor	DWORD ?	;0
ulPolicyVersionMajor	DWORD ?	;0
ulPolicyVersionMinor	DWORD ?	;0
ulAssemblyDirectoryNameLength	DWORD ?
lpAssemblyEncodedAssemblyIdentity	PCWSTR ?
lpAssemblyManifestPath		PCWSTR ?
lpAssemblyPolicyPath		PCWSTR ?
lpAssemblyDirectoryName		PCWSTR ?
ulFileCount				DWORD ?
ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION ends
PACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION typedef ptr ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION 
 
ACTIVATION_CONTEXT_DETAILED_INFORMATION struct
dwFlags				DWORD ?
ulFormatVersion		DWORD ?
ulAssemblyCount		DWORD ?
ulRootManifestPathType		DWORD ?
ulRootManifestPathChars		DWORD ?
ulRootConfigurationPathType	DWORD ?
ulRootConfigurationPathChars	DWORD ?
ulAppDirPathType		DWORD ?
ulAppDirPathChars		DWORD ?
lpRootManifestPath		PCWSTR ?
lpRootConfigurationPath	PCWSTR ?
lpAppDirPath		PCWSTR ?
ACTIVATION_CONTEXT_DETAILED_INFORMATION ends
PACTIVATION_CONTEXT_DETAILED_INFORMATION typedef ptr ACTIVATION_CONTEXT_DETAILED_INFORMATION

DLL_PROCESS_ATTACH		equ 1    
DLL_THREAD_ATTACH		equ 2    
DLL_THREAD_DETACH		equ 3    
DLL_PROCESS_DETACH		equ 0    
DLL_PROCESS_VERIFIER	equ 4     
 
;***********************************************************Ki*****************************************************************
KiTrap03				equ 03h	;->Exception=STATUS_BREAKPOINT
KiTrap04				equ 04h	;->Exception=STATUS_INTEGER_OVERFLOW
KiGetTickCount			equ 2Ah	;Return: Eax=Ticks
KiCallbackReturn		equ 2Bh	;->ZwCallbackReturn
KiRaiseAssertion		equ 2Ch
KiDebugService			equ 2Dh
KiSystemService		equ 2Eh	;SystemService

comment '
KiTrap03
EXCEPTION_RECORD
ExceptionCode = STATUS_BREAKPOINT;
ExceptionFlags = 0;
ExceptionRecord = 0;
ExceptionAddress = Eip;
NumberParameters = 3;
ExceptionParameters[0] = 0;
ExceptionParameters[1] = Ecx;
ExceptionParameters[2] = Edx;


KiDebugService constructs an EXCEPTION_RECORD and then dispatches the exception.
The EXCEPTION_RECORD contains:
ExceptionCode = STATUS_BREAKPOINT;
ExceptionFlags = 0;
ExceptionRecord = 0;
ExceptionAddress = Eip;
NumberParameters = 3;
ExceptionParameters[0] = Eax;
ExceptionParameters[1] = Ecx;
ExceptionParameters[2] = Edx;
Eax is set to the debug service code drawn from the enumeration DEBUG_SERVICE_CODE.
typedef enum _DEBUG_SERVICE_CODE {
DebugPrint = 1,
DebugPrompt,
DebugLoadImageSymbols,
DebugUnLoadImageSymbols
} DEBUG_SERVICE_CODE;
Ecx points to a STRING that contains either a string to print or the name of an image.
Edx contains or points to additional information, such as the base of an image or a prompt reply STRING.
When the kernel debugger is informed of a STATUS_BREAKPOINT exception, it checks ExceptionParameters[0].
If this value is zero, the exception was caused by an int3 instruction; otherwise, the value should be one of the enumerated values in DEBUG_SERVICE_CODE.
If no remote debugger is present, DebugPrint, DebugLoadImageSymbols, and DebugUnLoadImageSymbols exceptions are ignored;
DebugPrompt and int3 exceptions are left to be handled by the standard exception-handling mechanisms.
'

KiUserApcDispatcher proto :dword, :dword, :dword, :dword

APC_DISPATCHER struct
ApcRoutine	PVOID ?	;ZwQueueApcThread(ApcRoutine)
ApcContext	ULONG ?	;ZwQueueApcThread(ApcContext)
Argument1		ULONG ?	;ZwQueueApcThread(Argument1)
Argument2		ULONG ?	;ZwQueueApcThread(Argument2)
Context		CONTEXT <>
APC_DISPATCHER ends	
PAPC_DISPATCHER typedef ptr APC_DISPATCHER

KiRaiseUserExceptionDispatcher proto

KiUserExceptionDispatcher proto XcptInfo:PEXCEPTION_RECORD, Context:PCONTEXT

KiUserCallbackDispatcher proto stdcall ApiNumber:ULONG, InputBuffer:PVOID, InputLength:ULONG

RtlRaiseException proto ExceptionRecord:PEXCEPTION_RECORD

RtlRaiseStatus proto Status:NTSTATUS

RtlGetLastNtStatus proto

KiFastSystemCall proto

KiFastSystemCallRet proto
;***********************************************************************SID******************************************************************
;#define SECURITY_WORLD_SID_AUTHORITY    {0,0,0,0,0,1}
;#define SECURITY_WORLD_RID              (0x00000000L)

SID_REVISION	equ 1

TOKEN_ASSIGN_PRIMARY	equ (0001h)
TOKEN_DUPLICATE		equ (0002h)
TOKEN_IMPERSONATE		equ (0004h)
TOKEN_QUERY			equ (0008h)
TOKEN_QUERY_SOURCE		equ (0010h)
TOKEN_ADJUST_PRIVILEGES	equ (0020h)
TOKEN_ADJUST_GROUPS		equ (0040h)
TOKEN_ADJUST_DEFAULT	equ (0080h)

RtlConvertSidToUnicodeString	proto DestinationString:PVOID, Sid:PSID, AllocateDestinationString:BOOLEAN
comment '
RtlConvertSidToUnicodeString(
OUT PUNICODE_STRING DestinationString,
IN PSID Sid,
IN BOOLEAN AllocateDestinationString):NTSTATUS'

RtlCopySid proto _Length:ULONG, Destination:PSID, Source:PSID
comment '
RtlCopySid(
IN ULONG Length,
IN PSID Destination,
IN PSID Source):NTSTATUS'

RtlEqualSid proto Sid1:PSID, Sid2:PSID
comment '
RtlEqualSid(
IN PSID Sid1,
IN PSID Sid2):BOOLEAN'

RtlSetGroupSecurityDescriptor	proto SecurityDescriptor:PVOID, Group_:PSID, GroupDefaulted:BOOLEAN
comment '
RtlSetGroupSecurityDescriptor(
IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
IN PSID Group OPTIONAL,
IN BOOLEAN GroupDefaulted):NTSTATUS'

RtlSetOwnerSecurityDescriptor proto SecurityDescriptor:PVOID, Group_:PSID, GroupDefaulted:BOOLEAN
comment '
RtlSetOwnerSecurityDescriptor(
IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
IN PSID OPTIONAL Owner,
IN BOOLEAN OwnerDefaulted):NTSTATUS'

RtlSetDaclSecurityDescriptor proto SecurityDescriptor:PSECURITY_DESCRIPTOR, DaclPresent:BOOLEAN, Dacl:PACL, DaclDefaulted:BOOLEAN
comment '
RtlSetDaclSecurityDescriptor(
IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
IN BOOLEAN DaclPresent,
IN PACL Dacl,
IN BOOLEAN DaclDefaulted):NTSTATUS
;advapi32!SetSecurityDescriptorDacl'

RtlSetSaclSecurityDescriptor proto SecurityDescriptor:PSECURITY_DESCRIPTOR, SaclPresent:BOOLEAN, Sacl:PACL, SaclDefaulted:BOOLEAN
comment '
RtlSetSaclSecurityDescriptor(
IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
IN BOOLEAN SaclPresent,
IN PACL Sacl,
IN BOOLEAN SaclDefaulted):NTSTATUS
;advapi32!SetSecurityDescriptorSacl'

RtlGetDaclSecurityDescriptor proto SecurityDescriptor:PSECURITY_DESCRIPTOR, DaclPresent:PBOOLEAN, Dacl:PACL, DaclDefaulted:PBOOLEAN
comment '
RtlGetDaclSecurityDescriptor(
IN PSECURITY_DESCRIPTOR SecurityDescriptor,
OUT PBOOLEAN            DaclPresent,
OUT PACL                *Dacl,
OUT PBOOLEAN            DaclDefaulted):NTSTATUS'

RtlGetGroupSecurityDescriptor proto SecurityDescriptor:PSECURITY_DESCRIPTOR, Group_:PSID, GroupDefaulted:PBOOLEAN
comment '
RtlGetGroupSecurityDescriptor(
IN PSECURITY_DESCRIPTOR SecurityDescriptor,
OUT PSID *Group,
OUT PBOOLEAN GroupDefaulted):NTSTATUS'

RtlGetOwnerSecurityDescriptor proto SecurityDescriptor:PSECURITY_DESCRIPTOR, Owner:PSID, OwnerDefaulted:PBOOLEAN
comment '
RtlGetOwnerSecurityDescriptor(
IN PSECURITY_DESCRIPTOR SecurityDescriptor,
OUT PSID *Owner,
OUT PBOOLEAN OwnerDefaulted):NTSTATUS'

RtlInitializeSid proto Sid:PSID, IdentifierAuthority:PVOID , SubAuthorityCount:UCHAR
comment '
RtlInitializeSid(
IN OUT PSID Sid,
IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
IN UCHAR SubAuthorityCount):NTSTATUS'

RtlSubAuthorityCountSid	proto Sid:PSID
comment '
RtlSubAuthorityCountSid (
IN PSID Sid):PUCHAR'

RtlSubAuthoritySid proto Sid:PSID, SubAuthority:ULONG
comment '
RtlSubAuthoritySid(
IN PSID Sid,
IN ULONG SubAuthority):PULONG'

RtlValidSid	proto Sid:PSID
comment '
RtlValidSid(
IN PSID Sid):BOOLEAN'

RtlLengthRequiredSid proto SubAuthorityCount:UCHAR
comment '
RtlLengthRequiredSid(
IN UCHAR SubAuthorityCount):ULONG'

RtlLengthSid proto Sid:PSID
comment '
RtlLengthSid (
IN PSID Sid):ULONG'

RtlCreateSecurityDescriptor proto SecurityDescriptor:PSECURITY_DESCRIPTOR, Revision:ULONG
comment '
RtlCreateSecurityDescriptor(
IN PSECURITY_DESCRIPTOR SecurityDescriptor,
IN ULONG Revision):NTSTATUS	;Revision = SECURITY_DESCRIPTOR_REVISION'

RtlFirstFreeAce proto Acl:PACL, Ace:PVOID
comment '
RtlFirstFreeAce(
IN PACL Acl,
OUT PVOID Ace):NTSTATUS
;advapi32!FirstFreeAce'

RtlNewSecurityObject proto ParentDescriptor:PSECURITY_DESCRIPTOR, CreatorDescriptor:PSECURITY_DESCRIPTOR, NewDescriptor:PSECURITY_DESCRIPTOR,
 IsDirectoryObject:BOOLEAN, Token:HANDLE, GenericMapping:GENERING_MAPPING
comment '
RtlNewSecurityObject(
IN PSECURITY_DESCRIPTOR ParentDescriptor,
IN PSECURITY_DESCRIPTOR CreatorDescriptor,
OUT PSECURITY_DESCRIPTOR NewDescriptor,
IN BOOLEAN IsDirectoryObject,
IN HANDLE Token,
IN GENERING_MAPPING GenericMapping):NTSTATUS
;advapi32!CreatePrivateObjectSecurity'

RtlSetSecurityObject proto InfoClass:ULONG, ModificationDescriptor:PSECURITY_DESCRIPTOR, ObjectsSecurityDescriptor:PSECURITY_DESCRIPTOR,
 GenericMapping:PGENERIC_MAPPING, Token:HANDLE
comment '
RtlSetSecurityObject(
IN ULONG InfoClass,	;SECURITY_INFORMATION
IN PSECURITY_DESCRIPTOR ModificationDescriptor,
OUT PSECURITY_DESCRIPTOR* ObjectsSecurityDescriptor,
IN PGENERIC_MAPPING GenericMapping,
IN HANDLE Token):NTSTATUS
;advapi32!SetPrivateObjectSecurity'

RtlSetInformationAcl proto Acl:PACL, AclInformation:PVOID, AclInformationLength:ULONG, AclInfoClass:ULONG
comment '
RtlSetInformationAcl(
IN OUT PACL Acl,
IN PVOID AclInformation,
IN ULONG AclInformationLength,
IN ULONG AclInfoClass):NTSTATUS'

RtlValidAcl proto Acl:PACL
comment '
RtlValidAcl(
IN PACL Acl):BOOLEAN'

comment '
*RtlGetDaclSecurityDescriptor(
IN PSECURITY_DESCRIPTOR SecurityDescriptor,
OUT PULONG lpbDaclPresent,	;PBYTE
OUT PACL Dacl,
OUT PULONG lpbDaclDefaulted	;PBYTE
):NTSTATUS	

RtlCreateAndSetSD(
IN PSECURITY_DESCRIPTOR,	?
IN ULONG AceCount,
IN PSID OPTIONAL Owner,
IN PSID OPTIONAL Group,
OUT PSECURITY_DESCRIPTOR* SecurityDescriptor ?)

RtlCreateUserSecurityObject(
IN PSECURITY_DESCRIPTOR,	?
IN ULONG AceCount,
IN PSID Owner,
IN PSID Group,
OUT PSECURITY_DESCRIPTOR* SecurityDescriptor ?
IN BOOLEAN IsDirectoryObject,
OUT PSECURITY_DESCRIPTOR NewDescriptor)'

RtlGetControlSecurityDescriptor                    proto stdcall :DWORD, :DWORD, :DWORD
;***********************************************************************TIME******************************************************************

RtlSecondsSince1970ToTime	proto SecondsSince1970:ULONG, Time:PVOID
comment '
RtlSecondsSince1970ToTime (
IN ULONG SecondsSince1970,
OUT PLARGE_INTEGER Time):VOID'

RtlSecondsSince1980ToTime proto SecondsSince1980:ULONG, Time:PVOID
comment '
RtlSecondsSince1970ToTime (
IN ULONG SecondsSince1980,
OUT PLARGE_INTEGER Time):VOID'

RtlTimeToSecondsSince1970 proto Time:PVOID, SecondsSince1970:PULONG
comment '
RtlTimeToSecondsSince1970(
IN PLARGE_INTEGER Time,
OUT PULONG SecondsSince1970):BOOLEAN'

RtlTimeToSecondsSince1980 proto Time:PVOID, SecondsSince1980:PULONG
comment '
RtlTimeToSecondsSince1980 (
IN PLARGE_INTEGER   Time,
OUT PULONG          SecondsSince1980):BOOLEAN'

RtlTimeToTimeFields proto Time:PLARGE_INTEGER, TimeFields:PTIME_FIELDS
comment '
RtlTimeToTimeFields(
IN PLARGE_INTEGER Time,
OUT PTIME_FIELDS TimeFields):VOID'

RtlTimeFieldsToTime proto TimeFields:PTIME_FIELDS, Time:PLARGE_INTEGER
comment '
RtlTimeFieldsToTime(
IN PTIME_FIELDS TimeFields,
OUT PLARGE_INTEGER Time):VOID'
;*********************************************************************Registry Keys**************************************************************
ZwCreateKey proto KeyHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES, TitleIndex:ULONG, Class:PUNICODE_STRING, CreateOptions:ULONG, Disposition:PULONG
comment '
ZwCreateKey(
OUT PHANDLE KeyHandle,
IN ACCESS_MASK DesiredAccess,		;KEY_
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN ULONG TitleIndex,
IN PUNICODE_STRING Class OPTIONAL,
IN ULONG CreateOptions,	;REG_OPTION_
OUT PULONG Disposition OPTIONAL):NTSTATUS
' 

KEY_QUERY_VALUE                      equ 1h
KEY_SET_VALUE                        equ 2h
KEY_CREATE_SUB_KEY                   equ 4h
KEY_ENUMERATE_SUB_KEYS               equ 8h
KEY_NOTIFY                           equ 10h
KEY_CREATE_LINK                      equ 20h
KEY_READ                             equ (STANDARD_RIGHTS_READ OR KEY_QUERY_VALUE OR KEY_ENUMERATE_SUB_KEYS OR KEY_NOTIFY) AND NOT SYNCHRONIZE
KEY_WRITE                            equ (STANDARD_RIGHTS_WRITE OR KEY_SET_VALUE OR KEY_CREATE_SUB_KEY) AND NOT SYNCHRONIZE
KEY_EXECUTE                          equ KEY_READ
KEY_ALL_ACCESS                       equ (STANDARD_RIGHTS_ALL OR KEY_QUERY_VALUE OR KEY_SET_VALUE OR KEY_CREATE_SUB_KEY OR KEY_ENUMERATE_SUB_KEYS OR KEY_NOTIFY OR KEY_CREATE_LINK) AND NOT SYNCHRONIZE

REG_OPTION_VOLATILE 		equ 00000001h
REG_OPTION_CREATE_LINK 		equ 00000002h
REG_OPTION_BACKUP_RESTORE 	equ 00000004h
REG_OPTION_OPEN_LINK 		equ 00000008h
REG_OPTION_RESERVED			equ 0h
REG_OPTION_NON_VOLATILE		equ 0h

REG_CREATED_NEW_KEY 		equ 00000001h
REG_OPENED_EXISTING_KEY 		equ 00000002h

ZwOpenKey proto KeyHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwOpenKey(
OUT PHANDLE KeyHandle,
IN ACCESS_MASK DesiredAccess,	;KEY_
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS'

ZwDeleteKey proto KeyHandle:HANDLE
comment '
ZwDeleteKey(
IN HANDLE KeyHandle):NTSTATUS'

ZwFlushKey proto KeyHandle:HANDLE
comment '
ZwFlushKey(
IN HANDLE KeyHandle):NTSTATUS'

ZwSaveKey proto KeyHandle:HANDLE, FileHandle:HANDLE
comment '
ZwSaveKey(
IN HANDLE KeyHandle,
IN HANDLE FileHandle):NTSTATUS'

ZwSaveMergedKeys proto KeyHandle1:HANDLE, KeyHandle2:HANDLE, FileHandle:HANDLE
comment '
ZwSaveMergedKeys(
IN HANDLE KeyHandle1,
IN HANDLE KeyHandle2,
IN HANDLE FileHandle):NTSTATUS'

ZwRestoreKey proto KeyHandle:HANDLE, FileHandle:HANDLE, Flags:ULONG
comment '
ZwRestoreKey(
IN HANDLE KeyHandle,
IN HANDLE FileHandle,
IN ULONG Flags):NTSTAUS'

REG_WHOLE_HIVE_VOLATILE              equ 1h
REG_REFRESH_HIVE                     equ 2h

ZwLoadKey proto KeyObjectAttributes:POBJECT_ATTRIBUTES, FileObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwLoadKey(
IN POBJECT_ATTRIBUTES KeyObjectAttributes,
IN POBJECT_ATTRIBUTES FileObjectAttributes):NTSTAUS'

ZwLoadKey2 proto KeyObjectAttributes:POBJECT_ATTRIBUTES, FileObjectAttributes:POBJECT_ATTRIBUTES, Flags:ULONG
comment '
ZwLoadKey2(
IN POBJECT_ATTRIBUTES KeyObjectAttributes,
IN POBJECT_ATTRIBUTES FileObjectAttributes
IN ULONG Flags):NTSTATUS'

REG_NO_LAZY_FLUSH equ 00000004h   

ZwUnloadKey proto KeyObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwUnloadKey(
IN POBJECT_ATTRIBUTES KeyObjectAttributes):NTSTAUS'

ZwQueryOpenSubKeys proto KeyObjectAttributes:POBJECT_ATTRIBUTES, NumberOfKeys:PULONG
comment '
ZwQueryOpenSubKeys(
IN POBJECT_ATTRIBUTES KeyObjectAttributes,
OUT PULONG NumberOfKeys):NTSTAUS'

ZwReplaceKey proto NewFileObjectAttributes:POBJECT_ATTRIBUTES, KeyHandle:HANDLE, OldFileObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwReplaceKey(
IN POBJECT_ATTRIBUTES NewFileObjectAttributes,
IN HANDLE KeyHandle,
IN POBJECT_ATTRIBUTES OldFileObjectAttributes):NTSTAUS'

ZwSetInformationKey proto KeyHandle:HANDLE, KeyInformationClass:ULONG, KeyInformation:PVOID, KeyInformationLength:ULONG
comment '
ZwSetInformationKey(
IN HANDLE KeyHandle,
IN KEY_SET_INFORMATION_CLASS KeyInformationClass,
IN PVOID KeyInformation,
IN ULONG KeyInformationLength):NTSTAUS'

;enum KEY_SET_INFORMATION_CLASS {
KeyWriteTimeInformation	equ 0
KeyUserFlagsInformation	equ 1

KEY_WRITE_TIME_INFORMATION struct
LastWriteTime	LARGE_INTEGER <>
KEY_WRITE_TIME_INFORMATION ends
PKEY_WRITE_TIME_INFORMATION typedef ptr KEY_WRITE_TIME_INFORMATION

KEY_USER_FLAGS_INFORMATION struct
UserFlags	ULONG ?
KEY_USER_FLAGS_INFORMATION ends
PKEY_USER_FLAGS_INFORMATION typedef ptr KEY_USER_FLAGS_INFORMATION

ZwQueryKey proto KeyHandle:HANDLE, KeyInformationClass:ULONG, KeyInformation:PVOID, KeyInformationLength:ULONG, ResultLength:PULONG
comment '
ZwQueryKey(
IN HANDLE KeyHandle,
IN KEY_INFORMATION_CLASS KeyInformationClass,
OUT PVOID KeyInformation,
IN ULONG KeyInformationLength,
OUT PULONG ResultLength):NTSTAUS'

;enum KEY_INFORMATION_CLASS
KeyBasicInformation		equ 1
KeyNodeInformation		equ 2
KeyFullInformation		equ 3
KeyNameInformation		equ 4
KeyCachedInformation	equ 5
KeyFlagsInformation		equ 6

KEY_BASIC_INFORMATION struct
LastWriteTime	LARGE_INTEGER <>
TitleIndex	ULONG ?
NameLength	ULONG <>
;_Name		WCHAR 1 DUP (?)
KEY_BASIC_INFORMATION ends
PKEY_BASIC_INFORMATION typedef ptr KEY_BASIC_INFORMATION

KEY_NODE_INFORMATION struct
LastWriteTime	LARGE_INTEGER <>
TitleIndex	ULONG ?
ClassOffset	ULONG ?
ClassLength	ULONG ?
NameLength	ULONG ?
;_Name		WCHAR 1 DUP (?)
KEY_NODE_INFORMATION ends
PKEY_NODE_INFORMATION typedef ptr KEY_NODE_INFORMATION

KEY_FULL_INFORMATION struct
LastWriteTime	LARGE_INTEGER <>
TitleIndex	ULONG ?
ClassOffset	ULONG ?
ClassLength	ULONG ?
SubKeys		ULONG ?
MaxNameLen	ULONG ?
MaxClassLen	ULONG ?
Values		ULONG ?
MaxValueNameLen	ULONG ?
MaxValueDataLen	ULONG ?
;Class		WCHAR 1 DUP (?)
KEY_FULL_INFORMATION ends
PKEY_FULL_INFORMATION typedef ptr KEY_FULL_INFORMATION

KEY_NAME_INFORMATION struct
NameLength	ULONG ?
;_Name		WCHAR 1 DUP (?)
KEY_NAME_INFORMATION ends
PKEY_NAME_INFORMATION typedef ptr KEY_NAME_INFORMATION

KEY_CACHED_INFORMATION struct
LastWriteTime	LARGE_INTEGER <>
TitleIndex	ULONG ?
SubKeys		ULONG ?
MaxNameLen	ULONG ?
Values		ULONG ?
MaxValueNameLen	ULONG ?
MaxValueDataLen	ULONG ?
NameLength	ULONG ?
;_Name		WCHAR 1 DUP (?)
KEY_CACHED_INFORMATION ends
PKEY_CACHED_INFORMATION typedef ptr KEY_CACHED_INFORMATION

KEY_FLAGS_INFORMATION struct
UserFlags	ULONG ?
KEY_FLAGS_INFORMATION ends
PKEY_FLAGS_INFORMATION typedef ptr KEY_FLAGS_INFORMATION

ZwEnumerateKey proto KeyHandle:HANDLE, Index:ULONG, KeyInformationClass:ULONG, KeyInformation:PVOID, KeyInformationLength:ULONG, ResultLength:PULONG
comment '
ZwEnumerateKey(
IN HANDLE KeyHandle,
IN ULONG Index,
IN KEY_INFORMATION_CLASS KeyInformationClass,
OUT PVOID KeyInformation,
IN ULONG KeyInformationLength,
OUT PULONG ResultLength):NTSTATUS'

ZwNotifyChangeKey proto KeyHandle:HANDLE, EventHandle:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK, 
NotifyFilter:ULONG, WatchSubtree :BOOLEAN, Buffer:PVOID, BufferLength:ULONG, Asynchronous:BOOLEAN
comment '
ZwNotifyChangeKey(
IN HANDLE KeyHandle,
IN HANDLE EventHandle OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN ULONG NotifyFilter,		;REG_NOTIFY_CHANGE_
IN BOOLEAN WatchSubtree,
IN PVOID Buffer,
IN ULONG BufferLength,
IN BOOLEAN Asynchronous):NTSTATUS'

REG_NOTIFY_CHANGE_NAME               equ 1h
REG_NOTIFY_CHANGE_ATTRIBUTES         equ 2h
REG_NOTIFY_CHANGE_LAST_SET           equ 4h
REG_NOTIFY_CHANGE_SECURITY           equ 8h

ZwNotifyChangeMultipleKeys proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
comment '
ZwNotifyChangeMultipleKeys (
IN HANDLE KeyHandle,
IN ULONG Flags,		;REG_MONITOR_
IN POBJECT_ATTRIBUTES KeyObjectAttributes,
IN HANDLE EventHandle OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN ULONG NotifyFilter,	;REG_NOTIFY_CHANGE_
IN BOOLEAN WatchSubtree,
IN PVOID Buffer,
IN ULONG BufferLength,
IN BOOLEAN Asynchronous):NTSTAUS'

REG_MONITOR_SINGLE_KEY	equ 00h
REG_MONITOR_SECOND_KEY	equ 01h

ZwDeleteValueKey proto KeyHandle:HANDLE, ValueName:PUNICODE_STRING
comment '
ZwDeleteValueKey(
IN HANDLE KeyHandle,
IN PUNICODE_STRING ValueName):NTSTATUS'

ZwSetValueKey proto KeyHandle:HANDLE, ValueName:PUNICODE_STRING, TitleIndex:ULONG, _Type:ULONG, _Data:PVOID, DataSize:ULONG
comment '
ZwSetValueKey(
IN HANDLE KeyHandle,
IN PUNICODE_STRING ValueName,
IN ULONG TitleIndex,
IN ULONG Type,		;REG_
IN PVOID Data,
IN ULONG DataSize):NTSTATUS'

REG_NONE						equ 0 ; No value type
REG_SZ						equ 1 ; Unicode nul terminated string
REG_EXPAND_SZ					equ 2 ; Unicode nul terminated string (with environment variable references)
REG_BINARY					equ 3 ; Free form binary
REG_DWORD						equ 4 ; 32-bit number
REG_DWORD_LITTLE_ENDIAN			equ 4 ; 32-bit number (same as REG_DWORD)
REG_DWORD_BIG_ENDIAN			equ 5 ; 32-bit number
REG_LINK						equ 6 ; Symbolic Link (unicode)
REG_MULTI_SZ					equ 7 ; Multiple Unicode strings
REG_RESOURCE_LIST				equ 8 ; Resource list in the resource map
REG_FULL_RESOURCE_DESCRIPTOR		equ 9 ; Resource list in the hardware description
REG_RESOURCE_REQUIREMENTS_LIST	equ 10
REG_QWORD						equ 11 ; 64-bit number
REG_QWORD_LITTLE_ENDIAN			equ 11 ; 64-bit number (same as REG_QWORD)

ZwQueryValueKey proto KeyHandle:HANDLE, ValueName:PUNICODE_STRING, KeyValueInformationClass:ULONG, KeyValueInformation:PVOID, KeyValueInformationLength:ULONG, ResultLength:PULONG
comment '
ZwQueryValueKey(
IN HANDLE KeyHandle,
IN PUNICODE_STRING ValueName,
IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
OUT PVOID KeyValueInformation,
IN ULONG KeyValueInformationLength,
OUT PULONG ResultLength):NTSTATUS'

;enum KEY_VALUE_INFORMATION_CLASS
KeyValueBasicInformation			equ 0
KeyValueFullInformation			equ 1
KeyValuePartialInformation		equ 2
KeyValueFullInformationAlign64	equ 3
KeyValuePartialInformationAlign64	equ 4

KEY_VALUE_BASIC_INFORMATION struct
TitleIndex	ULONG ?
_Type		ULONG ?
NameLength	ULONG ?
;_Name		WCHAR 1 DUP (?)
KEY_VALUE_BASIC_INFORMATION ends
PKEY_VALUE_BASIC_INFORMATION typedef ptr KEY_VALUE_BASIC_INFORMATION

KEY_VALUE_FULL_INFORMATION struct
TitleIndex	ULONG ?
_Type		ULONG ?
DataOffset	ULONG ?
DataLength	ULONG ?
NameLength	ULONG ?
;Name			WCHAR 1 DUP (?)
KEY_VALUE_FULL_INFORMATION ends
PKEY_VALUE_FULL_INFORMATION typedef ptr KEY_VALUE_FULL_INFORMATION

KEY_VALUE_PARTIAL_INFORMATION struct
TitleIndex	ULONG ?
_Type		ULONG ?
DataLength	ULONG ?
;_Data		UCHAR 1 DUP (?)
KEY_VALUE_PARTIAL_INFORMATION ends
PKEY_VALUE_PARTIAL_INFORMATION typedef ptr KEY_VALUE_PARTIAL_INFORMATION

KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 struct
  _Type		ULONG ?
DataLength	ULONG ?
_Data		UCHAR 1 DUP (?)
KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 ends
PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 typedef ptr KEY_VALUE_PARTIAL_INFORMATION_ALIGN64

KEY_VALUE_ENTRY struct
ValueName		PUNICODE_STRING ?
DataLength	ULONG ?
DataOffset	ULONG ?
_Type		ULONG ?
KEY_VALUE_ENTRY ends
PKEY_VALUE_ENTRY typedef ptr PKEY_VALUE_ENTRY

ZwEnumerateValueKey proto KeyHandle:HANDLE, Index:ULONG, KeyValueInformationClass:ULONG, KeyValueInformation:PVOID, KeyValueInformationLength:ULONG, ResultLength:PULONG
comment '
ZwEnumerateValueKey(
IN HANDLE KeyHandle,
IN ULONG Index,
IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
OUT PVOID KeyValueInformation,
IN ULONG KeyValueInformationLength,
OUT PULONG ResultLength):NTSTATUS'

ZwInitializeRegistry proto Setup:BOOLEAN
comment '
ZwInitializeRegistry(
IN BOOLEAN Setup):NTSTATUS'

; The following flags specify how the Name field of a RTL_QUERY_REGISTRY_TABLE entry is interpreted.  A NULL name indicates the end of the table.
RTL_QUERY_REGISTRY_SUBKEY   equ 00000001h
;Name is a subkey and remainder of table or until next subkey are value ames for that subkey to look at.

RTL_QUERY_REGISTRY_TOPKEY   equ 00000002h	; Reset current key to original key for this and all following table entries.
RTL_QUERY_REGISTRY_REQUIRED equ 00000004h	; Fail if no match found for this table entry.
RTL_QUERY_REGISTRY_NOVALUE  equ 00000008h
;Used to mark a table entry that has no value name, just wants a call out, not an enumeration of all values.
RTL_QUERY_REGISTRY_NOEXPAND equ 00000010h
;Used to suppress the expansion of REG_MULTI_SZ into multiple callouts or to prevent the expansion of environment variable values in REG_EXPAND_SZ
RTL_QUERY_REGISTRY_DIRECT   equ 00000020h	; QueryRoutine field ignored.  
;EntryContext field points to location to store value.
;For null terminated strings, EntryContext points to UNICODE_STRING structure that that describes maximum size of buffer.
;If .Buffer field is NULL then a buffer is allocated.
RTL_QUERY_REGISTRY_DELETE   equ 00000040h
;Used to delete value keys after they are queried.

; The following values for the RelativeTo parameter determine what the
; Path parameter to RtlQueryRegistryValues is relative to.
RTL_REGISTRY_ABSOLUTE     equ 0		; Path is a full path
RTL_REGISTRY_SERVICES     equ 1		; \Registry\Machine\System\CurrentControlSet\Services
RTL_REGISTRY_CONTROL      equ 2		; \Registry\Machine\System\CurrentControlSet\Control
RTL_REGISTRY_WINDOWS_NT   equ 3		; \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
RTL_REGISTRY_DEVICEMAP    equ 4		; \Registry\Machine\Hardware\DeviceMap
RTL_REGISTRY_USER         equ 5		; \Registry\User\CurrentUser
RTL_REGISTRY_MAXIMUM      equ 6
RTL_REGISTRY_HANDLE       equ 40000000h	; Low order bits are registry handle
RTL_REGISTRY_OPTIONAL     equ 80000000h	; Indicates the key node is optional

RtlOpenCurrentUser	proto DesiredAccess:ULONG, RootDirectoryHandle:PHANDLE
comment '
RtlOpenCurrentUser(
IN ULONG DesiredAccess,
OUT PHANDLE RootDirectoryHandle):NTSTATUS
Раздел: HKEY_CURRENT_USER'

RTL_QUERY_REGISTRY_ROUTINE struct
ValueName		PWSTR ?
ValueType		ULONG ?
ValueData		PVOID ?
ValueLength	ULONG ?
Context		PVOID ?
EntryContext	PVOID ?
RTL_QUERY_REGISTRY_ROUTINE ends
PRTL_QUERY_REGISTRY_ROUTINE typedef ptr RTL_QUERY_REGISTRY_ROUTINE
    
;Subroutines for dealing with the Registry
RTL_QUERY_REGISTRY_TABLE struct
QueryRoutine	PRTL_QUERY_REGISTRY_ROUTINE ?
Flags		ULONG ?
_Name		PWSTR ?
EntryContext	PVOID ?
DefaultType	ULONG ?
DefaultData	PVOID ?
DefaultLength	ULONG ?
RTL_QUERY_REGISTRY_TABLE ends
PRTL_QUERY_REGISTRY_TABLE typedef ptr RTL_QUERY_REGISTRY_TABLE
;The following flags specify how the Name field of a RTL_QUERY_REGISTRY_TABLE
;entry is interpreted.  A NULL name indicates the end of the table.

RTL_QUERY_REGISTRY_SUBKEY		equ 00000001h	
;Name is a subkey and remainder of table or until next subkey are value names for that subkey to look at.
RTL_QUERY_REGISTRY_TOPKEY		equ 00000002h
;Reset current key to original key for this and all following table entries.
RTL_QUERY_REGISTRY_REQUIRED		equ 00000004h
;Fail if no match found for this table entry.
RTL_QUERY_REGISTRY_NOVALUE		equ 00000008h
;Used to mark a table entry that has no value name, just wants a call out, not an enumeration of all values.
RTL_QUERY_REGISTRY_NOEXPAND		equ 00000010h
;Used to suppress the expansion of REG_MULTI_SZ into multiple callouts or to prevent the expansion of environment variable values in REG_EXPAND_SZ
RTL_QUERY_REGISTRY_DIRECT		equ 00000020h
;QueryRoutine field ignored.  EntryContext field points to location to store value.
;For null terminated strings, EntryContext points to UNICODE_STRING structure that that describes maximum size of buffer.
;If .Buffer field is NULL then a buffer is allocated.
RTL_QUERY_REGISTRY_DELETE		equ 00000040h
;Used to delete value keys after they are queried.

RtlQueryRegistryValues proto RelativeTo:ULONG, Path:PCWSTR, QueryTable:PRTL_QUERY_REGISTRY_TABLE, Context:PVOID, Environment:PVOID
comment '    
RtlQueryRegistryValues(
IN ULONG RelativeTo,
IN PCWSTR Path,
IN PRTL_QUERY_REGISTRY_TABLE QueryTable,
IN PVOID Context,
IN PVOID Environment OPTIONAL):NTSTATUS'

RtlWriteRegistryValue proto RelativeTo:ULONG, Path:PCWSTR, ValueName:PCWSTR, ValueType:ULONG, ValueData:PVOID, ValueLength:ULONG
comment '
RtlWriteRegistryValue(
IN ULONG RelativeTo,
IN PCWSTR Path,
IN PCWSTR ValueName,
IN ULONG ValueType,
IN PVOID ValueData,
IN ULONG ValueLength):NTSTATUS'

RtlDeleteRegistryValue proto RelativeTo:ULONG, Path:PCWSTR, ValueName:PCWSTR
comment '
RtlDeleteRegistryValue(
IN ULONG RelativeTo,
IN PCWSTR Path,
IN PCWSTR ValueName):NTSTATUS'

RtlCreateRegistryKey proto RelativeTo:ULONG, Path:PWSTR
comment '
RtlCreateRegistryKey(
IN ULONG RelativeTo,
IN PWSTR Path):NTSTATUS'

RtlCheckRegistryKey proto RelativeTo:ULONG, Path:PWSTR
comment '
RtlCheckRegistryKey(
IN ULONG RelativeTo,
IN PWSTR Path):NTSTATUS'

;The following values for the RelativeTo parameter determine what the
;Path parameter to RtlQueryRegistryValues is relative to.
RTL_REGISTRY_ABSOLUTE		equ 0	;Path is a full path
RTL_REGISTRY_SERVICES		equ 1	;Registry\Machine\System\CurrentControlSet\Services
RTL_REGISTRY_CONTROL		equ 2	;Registry\Machine\System\CurrentControlSet\Control
RTL_REGISTRY_WINDOWS_NT		equ 3	;Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
RTL_REGISTRY_DEVICEMAP		equ 4	;Registry\Machine\Hardware\DeviceMap
RTL_REGISTRY_USER			equ 5	;Registry\User\CurrentUser
RTL_REGISTRY_MAXIMUM		equ 6
RTL_REGISTRY_HANDLE			equ 40000000h	;Low order bits are registry handle
RTL_REGISTRY_OPTIONAL		equ 80000000h	;Indicates the key node is optional
;************************************************************* Timers *****************************************************
RtlRegisterWait proto WaitHandle:PHANDLE, Handle:HANDLE, Function:PVOID, Context:PVOID, Milliseconds:ULONG, Flags:ULONG
comment '
RtlRegisterWait(
OUT PHANDLE WaitHandle,
IN HANDLE Handle,
IN WAITORTIMERCALLBACKFUNC Function,
IN PVOID Context,
IN ULONG Milliseconds,
IN ULONG Flags):NTSTATUS'

RtlDeregisterWait proto WaitHandle:HANDLE
comment '
RtlDeregisterWait(
IN HANDLE WaitHandle):NTSTATUS'

RtlDeregisterWaitEx proto WaitHandle:HANDLE, Event:HANDLE
comment '
RtlDeregisterWaitEx(
IN HANDLE WaitHandle,
IN HANDLE Event):NTSTATUS'

RtlQueueWorkItem proto Function:PVOID, Context:PVOID, Flags:ULONG
comment '
RtlQueueWorkItem(
IN WORKERCALLBACKFUNC Function,
IN PVOID Context,
IN ULONG Flags):NTSTATUS'

RtlSetIoCompletionCallback proto FileHandle:HANDLE, CompletionProc:PVOID, Flags:ULONG
comment '
RtlSetIoCompletionCallback(
IN HANDLE FileHandle,
IN APC_CALLBACK_FUNCTION CompletionProc,
IN ULONG Flags):NTSTATUS'

RtlCreateTimerQueue proto TimerQueueHandle:PHANDLE
comment '
RtlCreateTimerQueue(
OUT PHANDLE TimerQueueHandle):NTSTATUS'

RtlCreateTimer proto TimerQueueHandle:HANDLE, Handle:HANDLE, Function:PVOID, DueTime:ULONG, Period:ULONG, Flags:ULONG
comment '
RtlCreateTimer(
IN HANDLE TimerQueueHandle,
OUT HANDLE *Handle,
IN WAITORTIMERCALLBACKFUNC Function,
IN PVOID Context,
IN ULONG DueTime,
IN ULONG Period,
IN ULONG Flags):NTSTATUS'		;WT_

RtlDeleteTimer proto TimerQueueHandle:HANDLE, TimerToCancel:HANDLE, Event:HANDLE
comment '
RtlDeleteTimer(
IN HANDLE TimerQueueHandle,
IN HANDLE TimerToCancel,
IN HANDLE Event):NTSTATUS'

RtlDeleteTimerQueue proto TimerQueueHandle:HANDLE
comment '
RtlDeleteTimerQueue(
IN HANDLE TimerQueueHandle):NTSTATUS'

RtlDeleteTimerQueueEx proto TimerQueueHandle:HANDLE, Event:HANDLE
comment '
RtlDeleteTimerQueueEx(
IN HANDLE TimerQueueHandle,
IN HANDLE Event):NTSTATUS'

RtlDllShutdownInProgress proto
comment '
RtlDllShutdownInProgress():BOOLEAN'

RtlSetTimer proto TimerQueueHandle:HANDLE, Handle:HANDLE, Function:PVOID, Context:PVOID, DueTime:ULONG, Period:ULONG, Flags:ULONG
comment '
RtlSetTimer(
IN HANDLE TimerQueueHandle,
OUT HANDLE *Handle,
IN  WAITORTIMERCALLBACKFUNC Function,
IN  PVOID Context,
IN  ULONG  DueTime,
IN  ULONG  Period,
IN  ULONG  Flags):NTSTATUS'

WT_EXECUTEINLONGTHREAD	equ 10h
WT_EXECUTEDELETEWAIT	equ 8

RtlCancelTimer proto TimerQueueHandle:HANDLE, TimerToCancel:HANDLE
comment '
RtlCancelTimer(
IN HANDLE TimerQueueHandle,
IN HANDLE TimerToCancel):NTSTATUS'

RtlUpdateTimer                                     proto stdcall :DWORD, :DWORD, :DWORD, :DWORD

;Routines for thread pool.
WT_EXECUTEDEFAULT				equ 0h
WT_EXECUTEINIOTHREAD			equ 1h
WT_EXECUTEINUITHREAD			equ 2h
WT_EXECUTEINWAITTHREAD			equ 4h
WT_EXECUTEONLYONCE				equ 8h
WT_EXECUTEINTIMERTHREAD			equ 20h
WT_EXECUTELONGFUNCTION			equ 10h
WT_EXECUTEINPERSISTENTIOTHREAD	equ 40h
WT_EXECUTEINPERSISTENTTHREAD		equ 80h
WT_TRANSFER_IMPERSONATION		equ 100h

RtlCaptureStackBackTrace                           proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlDebugPrintTimes                                 proto stdcall

;ZwQueryTimerResolution                             proto stdcall :DWORD, :DWORD, :DWORD

WT_EXECUTEDEFAULT				equ 00000000h
WT_EXECUTEINIOTHREAD			equ 00000001h
WT_EXECUTEINUITHREAD			equ 00000002h
WT_EXECUTEINWAITTHREAD			equ 00000004h
WT_EXECUTEONLYONCE				equ 00000008h
WT_EXECUTEINTIMERTHREAD			equ 00000020h
WT_EXECUTELONGFUNCTION			equ 00000010h
WT_EXECUTEINPERSISTENTIOTHREAD	equ 00000040h
WT_EXECUTEINPERSISTENTTHREAD		equ 00000080h
WT_TRANSFER_IMPERSONATION		equ 00000100h
 
WT_EXECUTEINLONGTHREAD		equ 00000010h                           
WT_EXECUTEDELETEWAIT		equ 00000008h     
;******************************************************************** *************************************************************
;NT Defined Privileges
SE_CREATE_TOKEN_NAME		equ "SeCreateTokenPrivilege",0
SE_ASSIGNPRIMARYTOKEN_NAME	equ "SeAssignPrimaryTokenPrivilege",0
SE_LOCK_MEMORY_NAME			equ "SeLockMemoryPrivilege",0
SE_INCREASE_QUOTA_NAME		equ "SeIncreaseQuotaPrivilege",0
SE_UNSOLICITED_INPUT_NAME	equ "SeUnsolicitedInputPrivilege",0
SE_MACHINE_ACCOUNT_NAME		equ "SeMachineAccountPrivilege",0
SE_TCB_NAME				equ "SeTcbPrivilege",0
SE_SECURITY_NAME			equ "SeSecurityPrivilege",0
SE_TAKE_OWNERSHIP_NAME		equ "SeTakeOwnershipPrivilege",0
SE_LOAD_DRIVER_NAME			equ "SeLoadDriverPrivilege")
SE_SYSTEM_PROFILE_NAME		equ "SeSystemProfilePrivilege",0
SE_SYSTEMTIME_NAME			equ "SeSystemtimePrivilege",0
SE_PROF_SINGLE_PROCESS_NAME	equ "SeProfileSingleProcessPrivilege",0
SE_INC_BASE_PRIORITY_NAME	equ "SeIncreaseBasePriorityPrivilege",0
SE_CREATE_PAGEFILE_NAME		equ "SeCreatePagefilePrivilege",0
SE_CREATE_PERMANENT_NAME		equ "SeCreatePermanentPrivilege",0
SE_BACKUP_NAME				equ "SeBackupPrivilege",0
SE_RESTORE_NAME			equ "SeRestorePrivilege",0
SE_SHUTDOWN_NAME			equ "SeShutdownPrivilege",0
SE_DEBUG_NAME				equ "SeDebugPrivilege",0
SE_AUDIT_NAME				equ "SeAuditPrivilege",0
SE_SYSTEM_ENVIRONMENT_NAME	equ "SeSystemEnvironmentPrivilege",0
SE_CHANGE_NOTIFY_NAME		equ "SeChangeNotifyPrivilege",0
SE_REMOTE_SHUTDOWN_NAME		equ "SeRemoteShutdownPrivilege",0
SE_UNDOCK_NAME				equ "SeUndockPrivilege",0
SE_SYNC_AGENT_NAME			equ "SeSyncAgentPrivilege",0
SE_ENABLE_DELEGATION_NAME	equ "SeEnableDelegationPrivilege",0
SE_MANAGE_VOLUME_NAME		equ "SeManageVolumePrivilege",0
SE_IMPERSONATE_NAME			equ "SeImpersonatePrivilege",0
SE_CREATE_GLOBAL_NAME		equ "SeCreateGlobalPrivilege",0

SE_MACHINE_ACCOUNT_PRIVILEGE	equ 6
SE_TCB_PRIVILEGE			equ 7
SE_SECURITY_PRIVILEGE		equ 8
SE_TAKE_OWNERSHIP_PRIVILEGE	equ 9
SE_LOAD_DRIVER_PRIVILEGE		equ 10
SE_SYSTEM_PROFILE_PRIVILEGE	equ 11
SE_SYSTEMTIME_PRIVILEGE		equ 12
SE_PROF_SINGLE_PROCESS_PRIVILEGE	equ 13
SE_INC_BASE_PRIORITY_PRIVILEGE	equ 14
SE_CREATE_PAGEFILE_PRIVILEGE		equ 15
SE_CREATE_PERMANENT_PRIVILEGE		equ 16
SE_BACKUP_PRIVILEGE				equ 17
SE_RESTORE_PRIVILEGE			equ 18
SE_SHUTDOWN_PRIVILEGE			equ 19
SE_DEBUG_PRIVILEGE				equ 20
SE_AUDIT_PRIVILEGE				equ 21
SE_SYSTEM_ENVIRONMENT_PRIVILEGE	equ 22
SE_CHANGE_NOTIFY_PRIVILEGE		equ 23
SE_REMOTE_SHUTDOWN_PRIVILEGE		equ 24
SE_UNDOCK_PRIVILEGE				equ 25
SE_SYNC_AGENT_PRIVILEGE			equ 26
SE_ENABLE_DELEGATION_PRIVILEGE	equ 27
SE_MANAGE_VOLUME_PRIVILEGE		equ 28
SE_IMPERSONATE_PRIVILEGE			equ 29
SE_CREATE_GLOBAL_PRIVILEGE		equ 30
SE_MAX_WELL_KNOWN_PRIVILEGE		equ (SE_CREATE_GLOBAL_PRIVILEGE)
;******************************************************************** Path *************************************************************
RTL_RELATIVE_NAME_U struct
RelativeName		UNICODE_STRING <>
ContainingDirectory	HANDLE ?
CurDirRef			PVOID ?	;RTLP_CURDIR_REF ?
RTL_RELATIVE_NAME_U ends
PRTL_RELATIVE_NAME_U typedef ptr RTL_RELATIVE_NAME_U

;enum _RTL_PATH_TYPE {
RtlPathTypeUnknown			equ 0
RtlPathTypeUncAbsolute		equ 1
RtlPathTypeDriveAbsolute		equ 2
RtlPathTypeDriveRelative		equ 3
RtlPathTypeRooted			equ 4
RtlPathTypeRelative			equ 5
RtlPathTypeLocalDevice		equ 6
RtlPathTypeRootLocalDevice	equ 7

RtlDetermineDosPathNameType_U proto DosFileName:PCWSTR
comment '
RtlDetermineDosPathNameType_U(
IN PCWSTR DosFileName):RTL_PATH_TYPE'

RtlIsDosDeviceName_U proto DosFileName:PCWSTR
comment '
RtlIsDosDeviceName_U(
IN PCWSTR DosFileName):ULONG'

RtlGetFullPathName_U proto lpFileName:PCWSTR, nBufferLength:ULONG, lpBuffer:PWSTR, lpFilePart:PWSTR
comment '
RtlGetFullPathName_U(
IN PCWSTR lpFileName,
IN ULONG nBufferLength,
OUT PWSTR lpBuffer,
OUT PWSTR *lpFilePart OPTIONAL):ULONG'

RtlGetCurrentDirectory_U proto nBufferLength:ULONG, lpBuffer:PWSTR
comment '
RtlGetCurrentDirectory_U(
IN ULONG nBufferLength,
OUT PWSTR lpBuffer):ULONG'

RtlSetCurrentDirectory_U proto PathName:PCUNICODE_STRING
comment '
RtlSetCurrentDirectory_U(
IN PCUNICODE_STRING PathName):NTSTATUS'

RtlGetLongestNtPathLength proto	;115h

RtlDosPathNameToNtPathName_U proto DosFileName:PCWSTR, NtFileName:PUNICODE_STRING, FilePart:PWSTR, Reserved:PVOID
comment '
RtlDosPathNameToNtPathName_U(
IN PCWSTR DosFileName,
OUT PUNICODE_STRING NtFileName,
OUT PWSTR *FilePart OPTIONAL,
IN PVOID Reserved):BOOLEAN'

RtlDosSearchPath_U proto lpPath:PCWSTR, lpFileName:PCWSTR, lpExtension:PCWSTR, nBufferLength:ULONG, lpBuffer:PWSTR, lpFilePart:PWSTR 
comment '
RtlDosSearchPath_U(
IN PCWSTR lpPath,
IN PCWSTR lpFileName,
IN PCWSTR lpExtension OPTIONAL,
IN ULONG nBufferLength,
OUT PWSTR lpBuffer,
OUT PWSTR *lpFilePart OPTIONAL):ULONG'

RTL_DOS_SEARCH_PATH_FLAG_APPLY_ISOLATION_REDIRECTION	equ 1
;Flags to preserve Win32 SearchPathW() semantics in the ntdll implementation:
RTL_DOS_SEARCH_PATH_FLAG_DISALLOW_DOT_RELATIVE_PATH_SEARCH	equ 2
RTL_DOS_SEARCH_PATH_FLAG_APPLY_DEFAULT_EXTENSION_WHEN_NOT_RELATIVE_PATH_EVEN_IF_FILE_HAS_EXTENSION	equ 4

RtlDosSearchPath_Ustr proto Flags:ULONG, Path:PCUNICODE_STRING, FileName:PCUNICODE_STRING, DefaultExtension:PCUNICODE_STRING,
 StaticString:PUNICODE_STRING, DynamicString:PUNICODE_STRING, FullFileNameOut:PCUNICODE_STRING, FilePartPrefixCch:SIZE_T, BytesRequired:SIZE_T
comment '
RtlDosSearchPath_Ustr(
IN ULONG Flags,
IN PCUNICODE_STRING Path,
IN PCUNICODE_STRING FileName,
IN PCUNICODE_STRING DefaultExtension OPTIONAL,
OUT PUNICODE_STRING StaticString OPTIONAL,
OUT PUNICODE_STRING DynamicString OPTIONAL,
OUT PCUNICODE_STRING *FullFileNameOut OPTIONAL,
OUT SIZE_T *FilePartPrefixCch OPTIONAL,
OUT SIZE_T *BytesRequired OPTIONAL):NTSTATUS'

RtlDoesFileExists_U proto FileName:PCWSTR
comment '
RtlDoesFileExists_U(
IN PCWSTR FileName):BOOLEAN'

;input flags
RTL_DOS_APPLY_FILE_REDIRECTION_USTR_FLAG_RESPECT_DOT_LOCAL	equ 1
;output flags
RTL_DOS_APPLY_FILE_REDIRECTION_USTR_OUTFLAG_DOT_LOCAL_REDIRECT	equ 1
RTL_DOS_APPLY_FILE_REDIRECTION_USTR_OUTFLAG_ACTCTX_REDIRECT	equ 2

RtlDosApplyFileIsolationRedirection_Ustr proto Flags:ULONG, FileName:PCUNICODE_STRING, DefaultExtension:PCUNICODE_STRING,PreAllocatedString:PCUNICODE_STRING,
 DynamicallyAllocatedString:PUNICODE_STRING, FullPath:PUNICODE_STRING, OutFlags:PULONG, FilePartPrefixCch:SIZE_T, BytesRequired:SIZE_T
comment '
RtlDosApplyFileIsolationRedirection_Ustr(
IN ULONG Flags,
IN PCUNICODE_STRING FileName,
IN PCUNICODE_STRING DefaultExtension OPTIONAL,
IN PUNICODE_STRING PreAllocatedString OPTIONAL,
OUT PUNICODE_STRING DynamicallyAllocatedString OPTIONAL,
OUT PUNICODE_STRING *FullPath OPTIONAL,
OUT ULONG *OutFlags,
OUT SIZE_T *FilePartPrefixCch OPTIONAL,
OUT SIZE_T *BytesRequired OPTIONAL):NTSTATUS'

RtlComputePrivatizedDllName_U proto DllName:PCUNICODE_STRING, NewDllNameUnderImageDir:PUNICODE_STRING, NewDllNameUnderLocalDir:PUNICODE_STRING
comment '
RtlComputePrivatizedDllName_U(
IN PCUNICODE_STRING DllName,
IN OUT PUNICODE_STRING NewDllNameUnderImageDir,
IN OUT PUNICODE_STRING NewDllNameUnderLocalDir):NTSTATUS'
;******************************************************************** Miscilaneous *************************************************************
RtlAddVectoredExceptionHandler proto First:ULONG, Handler:PVOID
comment '
RtlAddVectoredExceptionHandler(
IN ULONG First,
IN PVOID Handler):VOID'

RtlRemoveVectoredExceptionHandler proto Handler:PVOID
comment '
RtlRemoveVectoredExceptionHandler(
IN PVOID Handler):ULONG'

RtlSetUnhandledExceptionFilter proto UnhandledExceptionFilter:PVOID
comment '
RtlSetUnhandledExceptionFilter(
IN PRTLP_UNHANDLED_EXCEPTION_FILTER UnhandledExceptionFilter):VOID'

ZwRaiseException proto ExceptionRecord:PEXCEPTION_RECORD, Context:PCONTEXT, SearchFrames:BOOLEAN
comment '
ZwRaiseException(
IN PEXCEPTION_RECORD ExceptionRecord,
IN PCONTEXT Context,
IN BOOLEAN SearchFrames):NTSTATUS
' 

ZwSetLowWaitHighThread proto

ZwSetHighWaitLowThread proto

ZwLoadDriver proto DriverServiceName:PUNICODE_STRING
comment '
ZwLoadDriver(
IN PUNICODE_STRING DriverServiceName):NTSTATUS'

ZwUnloadDriver proto DriverServiceName:PUNICODE_STRING
comment '
ZwUnloadDriver(
IN PUNICODE_STRING DriverServiceName):NTSTATUS'

ZwFlushWriteBuffer proto

ZwSetDefaultHardErrorPort proto PortHandle:HANDLE
comment '
ZwSetDefaultHardErrorPort(
IN HANDLE PortHandle):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_PRIVILEGE_NOT_HELD.
Необходима привилегия SeTcbPrivilege'

ZwDisplayString proto String:PUNICODE_STRING
comment '
ZwDisplayString(
IN PUNICODE_STRING String):NTSTATUS
Returns STATUS_SUCCESS or an error status, such as STATUS_PRIVILEGE_NOT_HELD.
Необходима привилегия SeTcbPrivilege'

ZwAddAtom proto String:PWSTR, StringLength:ULONG, Atom:PUSHORT
comment '
ZwAddAtom(
IN PWSTR String,
IN ULONG StringLength,
OUT PUSHORT Atom):NTSTATUS'

ZwFindAtom proto String:PWSTR, StringLength:ULONG, Atom:PUSHORT
comment '
ZwFindAtom(
IN PWSTR String,
IN ULONG StringLength,
OUT PUSHORT Atom):NTSTATUS'

ZwDeleteAtom proto Atom:PUSHORT
comment '
ZwDeleteAtom(
IN USHORT Atom):NTSTATUS'

ZwQueryInformationAtom proto Atom:USHORT, AtomInformationClass:ULONG, AtomInformation:PVOID, AtomInformationLength:ULONG, ReturnLength:PULONG
comment '
ZwQueryInformationAtom(
IN USHORT Atom,
IN ATOM_INFORMATION_CLASS AtomInformationClass,
OUT PVOID AtomInformation,
IN ULONG AtomInformationLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS'

;typedef enum _ATOM_INFORMATION_CLASS {
AtomBasicInformation	equ 0
AtomListInformation		equ 1

ATOM_BASIC_INFORMATION struct
ReferenceCount	USHORT ?
Pinned		USHORT ?
NameLength	USHORT ?
;Name	WCHAR 1 DUP (?)
ATOM_BASIC_INFORMATION ends
PATOM_BASIC_INFORMATION typedef ptr ATOM_BASIC_INFORMATION

ATOM_LIST_INFORMATION struct
NumberOfAtoms	ULONG ?
Atoms		ATOM 1 DUP (?)
ATOM_LIST_INFORMATION ends
PATOM_LIST_INFORMATION typedef ptr ATOM_LIST_INFORMATION

ZwSetLdtEntries proto Selector0:ULONG, Entry0Low:ULONG, Entry0Hi:ULONG, Selector1:ULONG, Entry1Low:ULONG, Entry0Hi:ULONG
comment '
ZwSetLdtEntries(
IN ULONG Selector1,
IN LDT_ENTRY LdtEntry1,
IN ULONG Selector2,
IN LDT_ENTRY LdtEntry2):NTSTATUS'

ZwVdmControl proto ControlCode:ULONG, ControlData:PVOID
comment '
ZwVdmControl(
IN ULONG ControlCode,
IN PVOID ControlData):NTSTATUS'

ZwSystemDebugControl proto ControlCode:ULONG, InputBuffer:PVOID, InputBufferLength:ULONG, OutputBuffer:PVOID, OutputBufferLength:ULONG, ReturnLength:PULONG
comment '
ZwSystemDebugControl(
IN DEBUG_CONTROL_CODE ControlCode,
IN PVOID InputBuffer OPTIONAL,
IN ULONG InputBufferLength,
OUT PVOID OutputBuffer OPTIONAL,
IN ULONG OutputBufferLength,
OUT PULONG ReturnLength OPTIONAL):NTSTATUS'

RtlGetFrame proto
comment '
RtlGetFrame():PTEB_ACTIVE_FRAME'

RtlPushFrame proto Frame:PTEB_ACTIVE_FRAME
comment '
RtlPushFrame(
IN PTEB_ACTIVE_FRAME Frame):VOID'

RtlPopFrame proto Frame:PTEB_ACTIVE_FRAME
comment '
RtlPopFrame(
IN PTEB_ACTIVE_FRAME Frame):VOID'

comment '
typedef struct _RTL_HANDLE_TABLE_ENTRY {
    union {
        ULONG Flags;                                // Allocated entries have low bit set
        struct _RTL_HANDLE_TABLE_ENTRY *NextFree;   // Free entries use this word for free list
    };
} RTL_HANDLE_TABLE_ENTRY, *PRTL_HANDLE_TABLE_ENTRY;'

RTL_HANDLE_ALLOCATED	equ 1

RTL_HANDLE_TABLE struct
MaximumNumberOfHandles	ULONG ?
SizeOfHandleTableEntry	ULONG ?
Reserved				ULONG 2 DUP (?)
FreeHandles			PVOID ?	;PRTL_HANDLE_TABLE_ENTRY
CommittedHandles		PVOID ?	;PRTL_HANDLE_TABLE_ENTRY
UnCommittedHandles		PVOID ?	;PRTL_HANDLE_TABLE_ENTRY ;
MaxReservedHandles		PVOID ?	;PRTL_HANDLE_TABLE_ENTRY ;
RTL_HANDLE_TABLE ends
PRTL_HANDLE_TABLE typedef ptr RTL_HANDLE_TABLE

RtlInitializeHandleTable proto MaximumNumberOfHandles:ULONG, SizeOfHandleTableEntry:ULONG, HandleTable:PRTL_HANDLE_TABLE
comment '
RtlInitializeHandleTable(
IN ULONG MaximumNumberOfHandles,
IN ULONG SizeOfHandleTableEntry,
OUT PRTL_HANDLE_TABLE HandleTable):VOID'

RtlDestroyHandleTable proto HandleTable:PRTL_HANDLE_TABLE
comment '
RtlDestroyHandleTable(
IN OUT PRTL_HANDLE_TABLE HandleTable):NTSTATUS'

RtlAllocateHandle proto HandleTable:PRTL_HANDLE_TABLE, HandleIndex:PULONG
comment '
RtlAllocateHandle(
IN PRTL_HANDLE_TABLE HandleTable,
OUT PULONG HandleIndex OPTIONAL):PRTL_HANDLE_TABLE_ENTRY'

RtlFreeHandle proto HandleTable:PRTL_HANDLE_TABLE, Handle:PVOID
comment '
RtlFreeHandle(
IN PRTL_HANDLE_TABLE HandleTable,
IN PRTL_HANDLE_TABLE_ENTRY Handle):BOOLEAN'

RtlIsValidHandle proto HandleTable:PRTL_HANDLE_TABLE, Handle:PVOID
comment '
RtlIsValidHandle(
IN PRTL_HANDLE_TABLE HandleTable,
IN PRTL_HANDLE_TABLE_ENTRY Handle):BOOLEAN'

RtlIsValidIndexHandle proto HandleTable:PRTL_HANDLE_TABLE, Handle:PVOID
comment '
RtlIsValidIndexHandle(
IN PRTL_HANDLE_TABLE HandleTable,
IN ULONG HandleIndex,
OUT PRTL_HANDLE_TABLE_ENTRY *Handle):BOOLEAN'

RtlSetThreadPoolStartFunc proto StartFunc:PVOID, ExitFunc:PVOID
comment '
RtlSetThreadPoolStartFunc(
PRTLP_START_THREAD StartFunc,
PRTLP_EXIT_THREAD ExitFunc):NTSTATUS'

RTL_QUERY_PROCESS_MODULES		equ 1h
RTL_QUERY_PROCESS_BACKTRACES		equ 2h
RTL_QUERY_PROCESS_HEAP_SUMMARY	equ 4h
RTL_QUERY_PROCESS_HEAP_TAGS		equ 8h
RTL_QUERY_PROCESS_HEAP_ENTRIES	equ 10h
RTL_QUERY_PROCESS_LOCKS			equ 20h
RTL_QUERY_PROCESS_MODULES32		equ 40h
RTL_QUERY_PROCESS_NONINVASIVE		equ 80000000h

RtlQueryProcessBackTraceInformation proto Buffer:PRTL_DEBUG_INFORMATION
comment '
RtlQueryProcessBackTraceInformation(
IN OUT PRTL_DEBUG_INFORMATION Buffer):NTSTATUS'

RtlQueryProcessHeapInformation proto Buffer:PRTL_DEBUG_INFORMATION
comment '
RtlQueryProcessHeapInformation(
IN OUT PRTL_DEBUG_INFORMATION Buffer):NTSTATUS'

RtlQueryProcessLockInformation proto Buffer:PRTL_DEBUG_INFORMATION
comment '
RtlQueryProcessLockInformation(
IN OUT PRTL_DEBUG_INFORMATION Buffer):NTSTATUS'
;*************************************************************************************************************************
RtlAdjustPrivilege proto Privilege:ULONG, NewValue:BOOLEAN, ForThread:BOOLEAN, OldValue:PBOOLEAN
comment '
RtlAdjustPrivilege(
IN ULONG Privilege,
IN BOOLEAN NewValue,
IN BOOLEAN ForThread,
OUT PBOOLEAN OldValue):NTSTATUS
' 

RtlSetLastWin32ErrorAndNtStatusFromNtStatus proto Status:NTSTATUS
comment '
RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
IN NTSTATUS Status):NTSTATUS
' 

RtlNtStatusToDosErrorNoTeb proto Status:NTSTATUS
comment '
RtlNtStatusToDosErrorNoTeb(
IN NTSTATUS Status):ULONG
' 

RtlNtStatusToDosError proto Status:NTSTATUS
comment '
RtlNtStatusToDosError(
IN NTSTATUS Status):ULONG
' 
;******************************************************** Files *****************************************************************
ZwCreateFile proto FileHandle:PHANDLE, DesiredAccess:ULONG, ObjectAttributes:POBJECT_ATTRIBUTES, IoStatusBlock:PIO_STATUS_BLOCK, AllocationSize:PLARGE_INTEGER,
 FileAttributes:ULONG, ShareAccess:ULONG, CreateDisposition:ULONG, CreateOptions:ULONG, EaBuffer:PVOID, EaLength:ULONG
comment '
ZwCreateFile(
OUT PHANDLE FileHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PLARGE_INTEGER AllocationSize OPTIONAL,
IN ULONG FileAttributes,
IN ULONG ShareAccess,
IN ULONG CreateDisposition,
IN ULONG CreateOptions,
IN PVOID EaBuffer OPTIONAL,
IN ULONG EaLength):NTSTATUS'

ZwOpenFile proto FileHandle:PHANDLE, DesiredAccess:ULONG, ObjectAttributes:POBJECT_ATTRIBUTES, IoStatusBlock:PIO_STATUS_BLOCK, ShareAccess:ULONG, OpenOptions:ULONG
comment '
ZwOpenFile(
OUT PHANDLE FileHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN ULONG ShareAccess,
IN ULONG OpenOptions):NTSTATUS'

ZwDeleteFile proto ObjectAttributes:POBJECT_ATTRIBUTES
comment '
ZwDeleteFile(
IN POBJECT_ATTRIBUTES ObjectAttributes):NTSTATUS'

ZwFlushBuffersFile proto FileHandle:HANDLE, IoStatusBlock:PIO_STATUS_BLOCK
comment '
ZwFlushBuffersFile(
IN HANDLE FileHandle,
OUT PIO_STATUS_BLOCK IoStatusBlock):NTSTATUS'

ZwCancelIoFile proto FileHandle:HANDLE, IoStatusBlock:PIO_STATUS_BLOCK
comment '
ZwCancelIoFile(
IN HANDLE FileHandle,
OUT PIO_STATUS_BLOCK IoStatusBlock):NTSTATUS'

ZwReadFile proto FileHandle:HANDLE, Event:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK,
 Buffer:PVOID, _Length:ULONG, ByteOffset:PLARGE_INTEGER, Key:PULONG
comment '
ZwReadFile(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
OUT PVOID Buffer,
IN ULONG Length,
IN PLARGE_INTEGER ByteOffset OPTIONAL,
IN PULONG Key OPTIONAL):NTSTATUS'

ZwWriteFile proto FileHandle:HANDLE, Event:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK,
 Buffer:PVOID, _Length:ULONG, ByteOffset:PLARGE_INTEGER, Key:PULONG
comment '
ZwWriteFile(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PVOID Buffer,
IN ULONG Length,
IN PLARGE_INTEGER ByteOffset OPTIONAL,
IN PULONG Key OPTIONAL):NTSTATUS'

ZwReadFileScatter proto FileHandle:HANDLE, Event:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK,
 Buffer:PVOID, _Length:ULONG, ByteOffset:PLARGE_INTEGER, Key:PULONG
comment '
ZwReadFileScatter(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PFILE_SEGMENT_ELEMENT Buffer,
IN ULONG Length,
IN PLARGE_INTEGER ByteOffset OPTIONAL,
IN PULONG Key OPTIONAL):NTSTATUS'

ZwWriteFileGather proto FileHandle:HANDLE, Event:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK,
 Buffer:PVOID, _Length:ULONG, ByteOffset:PLARGE_INTEGER, Key:PULONG
comment '
ZwWriteFileGather(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PFILE_SEGMENT_ELEMENT Buffer,
IN ULONG Length,
IN PLARGE_INTEGER ByteOffset OPTIONAL,
IN PULONG Key OPTIONAL):NTSTATUS'

ZwLockFile proto FileHandle:HANDLE, Event:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK,
 LockOffset:PLARGE_INTEGER, LockLength:PLARGE_INTEGER, Key:ULONG, FailImmediately:BOOLEAN, ExclusiveLock:BOOLEAN
comment '
ZwLockFile(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PULARGE_INTEGER LockOffset,
IN PULARGE_INTEGER LockLength,
IN ULONG Key,
IN BOOLEAN FailImmediately,
IN BOOLEAN ExclusiveLock):NTSTATUS'

ZwUnlockFile proto FileHandle:HANDLE, IoStatusBlock:PIO_STATUS_BLOCK, LockOffset:PLARGE_INTEGER, LockLength:PLARGE_INTEGER, Key:ULONG 
comment '
ZwUnlockFile(
IN HANDLE FileHandle,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PULARGE_INTEGER LockOffset,
IN PULARGE_INTEGER LockLength,
IN ULONG Key):NTSTATUS'

ZwDeviceIoControlFile proto FileHandle:HANDLE, Event:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK,
 IoControlCode:ULONG, InputBuffer:PVOID, InputBufferLength:ULONG, OutputBuffer:PVOID, OutputBufferLength:ULONG
comment '
ZwDeviceIoControlFile(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN ULONG IoControlCode,
IN PVOID InputBuffer OPTIONAL,
IN ULONG InputBufferLength,
OUT PVOID OutputBuffer OPTIONAL,
IN ULONG OutputBufferLength):NTSTATUS'

ZwFsControlFile proto FileHandle:HANDLE, Event:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK, FsControlCode:ULONG,
 InputBuffer:PVOID, InputBufferLength:ULONG, OutputBuffer:PVOID, OutputBufferLength:ULONG 
comment '
ZwFsControlFile(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN ULONG FsControlCode,
IN PVOID InputBuffer OPTIONAL,
IN ULONG InputBufferLength,
OUT PVOID OutputBuffer OPTIONAL,
IN ULONG OutputBufferLength):NTSTATUS'

FILE_NOTIFY_INFORMATION struct
NextEntryOffset	ULONG ?
Action			ULONG ?	;FILE_ACTION_
NameLength		ULONG ?
Name				ULONG 1 DUP (?)
FILE_NOTIFY_INFORMATION ends
PFILE_NOTIFY_INFORMATION typedef ptr FILE_NOTIFY_INFORMATION

ZwNotifyChangeDirectoryFile proto FileHandle:HANDLE, Event:HANDLE, ApcRoutine:PIO_APC_ROUTINE, ApcContext:PVOID, IoStatusBlock:PIO_STATUS_BLOCK,
 Buffer:PFILE_NOTIFY_INFORMATION, BufferLength:ULONG, NotifyFilter:ULONG, WatchSubtree:BOOLEAN 
comment '
ZwNotifyChangeDirectoryFile(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
OUT PFILE_NOTIFY_INFORMATION Buffer,
IN ULONG BufferLength,
IN ULONG NotifyFilter,	;FILE_NOTIFY_CHANGE_
IN BOOLEAN WatchSubtree):NTSTATUS'

;FILES
ZwQueryEaFile                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwQueryFullAttributesFile                          proto stdcall :DWORD, :DWORD
ZwSetEaFile                                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwQueryQuotaInformationFile                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwQueryAttributesFile                              proto stdcall :DWORD, :DWORD
ZwQueryInformationFile                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwSetInformationFile                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwSetVolumeInformationFile                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwSetQuotaInformationFile                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwQueryVolumeInformationFile                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

;FILE_INFORMATION_CLASS {			Query Set File/Directory
FileDirectoryInformation		equ	1;Y N D
FileFullDirectoryInformation	equ	2; Y N D
FileBothDirectoryInformation	equ	3; Y N D
FileBasicInformation		equ	4; Y Y F
FileStandardInformation		equ	5; Y N F
FileInternalInformation		equ	6; Y N F
FileEaInformation			equ	7; Y N F
FileAccessInformation		equ	8; Y N F
FileNameInformation			equ	9; Y N F
FileRenameInformation		equ	10; N Y F
FileLinkInformation			equ	11; N Y F
FileNamesInformation		equ	12; Y N D
FileDispositionInformation	equ	13; N Y F
FilePositionInformation		equ	14; Y Y F
FileModeInformation			equ	16; Y Y F
FileAlignmentInformation		equ	17; Y N F
FileAllInformation			equ	18; Y N F
FileAllocationInformation	equ	19; N Y F
FileEndOfFileInformation		equ	20; N Y F
FileAlternateNameInformation	equ	21; Y N F
FileStreamInformation		equ	22; Y N F
FilePipeInformation			equ	23; Y Y F
FilePipeLocalInformation		equ	24; Y N F
FilePipeRemoteInformation	equ	25; Y Y F
FileMailslotQueryInformation	equ	26; Y N F
FileMailslotSetInformation	equ	27; N Y F
FileCompressionInformation	equ	28; Y N F
FileObjectIdInformation		equ	29; Y Y F
FileCompletionInformation	equ	30; N Y F
FileMoveClusterInformation	equ	31; N Y F
FileQuotaInformation		equ	32; Y Y F
FileReparsePointInformation	equ	33; Y N F
FileNetworkOpenInformation	equ	34; Y N F
FileAttributeTagInformation	equ	35; Y N F
FileTrackingInformation		equ	36; N Y F

FILE_DIRECTORY_INFORMATION struct	;Information Class 1
NextEntryOffset	ULONG ?
Unknown			ULONG ?
CreationTime		LARGE_INTEGER <>
LastAccessTime		LARGE_INTEGER <>
LastWriteTime		LARGE_INTEGER <>
ChangeTime		LARGE_INTEGER <>
EndOfFile			LARGE_INTEGER <>
AllocationSize		LARGE_INTEGER <>
FileAttributes		ULONG ?
FileNameLength		ULONG ? 
FileName			WCHAR 1 DUP (?)
FILE_DIRECTORY_INFORMATION ends
PFILE_DIRECTORY_INFORMATION typedef ptr FILE_DIRECTORY_INFORMATION

;*************************************************************************************************************************

NtAcceptConnectPort                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAccessCheck                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAccessCheckAndAuditAlarm                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAccessCheckByType                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAccessCheckByTypeAndAuditAlarm                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAccessCheckByTypeResultList                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAccessCheckByTypeResultListAndAuditAlarm         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAccessCheckByTypeResultListAndAuditAlarmByHandle proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAddAtom                                          proto stdcall :DWORD, :DWORD, :DWORD
NtAdjustGroupsToken                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAdjustPrivilegesToken                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAlertResumeThread                                proto stdcall :DWORD, :DWORD
NtAlertThread                                      proto stdcall :DWORD
NtAllocateLocallyUniqueId                          proto stdcall :DWORD
NtAllocateUserPhysicalPages                        proto stdcall :DWORD, :DWORD, :DWORD
NtAllocateUuids                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtAllocateVirtualMemory                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtAreMappedFilesTheSame                            proto stdcall :DWORD, :DWORD
NtAssignProcessToJobObject                         proto stdcall :DWORD, :DWORD
NtCallbackReturn                                   proto stdcall :DWORD, :DWORD, :DWORD
NtCancelDeviceWakeupRequest                        proto stdcall :DWORD
NtCancelIoFile                                     proto stdcall :DWORD, :DWORD
NtCancelTimer                                      proto stdcall :DWORD, :DWORD
NtClearEvent                                       proto stdcall :DWORD
NtClose                                            proto stdcall :DWORD
NtCloseObjectAuditAlarm                            proto stdcall :DWORD, :DWORD, :DWORD
NtCompleteConnectPort                              proto stdcall :DWORD
NtConnectPort                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtContinue                                         proto stdcall :DWORD, :DWORD
NtCreateChannel                                    proto stdcall :DWORD, :DWORD
NtCreateDirectoryObject                            proto stdcall :DWORD, :DWORD, :DWORD
NtCreateEvent                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateEventPair                                  proto stdcall :DWORD, :DWORD, :DWORD
NtCreateFile                                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateIoCompletion                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtCreateJobObject                                  proto stdcall :DWORD, :DWORD, :DWORD
NtCreateKey                                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateMailslotFile                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateMutant                                     proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtCreateNamedPipeFile                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreatePagingFile                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtCreatePort                                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateProcess                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateProfile                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateSection                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateSemaphore                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateSymbolicLinkObject                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtCreateThread                                     proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateTimer                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtCreateToken                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCreateWaitablePort                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtCurrentTeb                                       proto stdcall
NtDelayExecution                                   proto stdcall :DWORD, :DWORD
NtDeleteAtom                                       proto stdcall :DWORD
NtDeleteFile                                       proto stdcall :DWORD
NtDeleteKey                                        proto stdcall :DWORD
NtDeleteObjectAuditAlarm                           proto stdcall :DWORD, :DWORD, :DWORD
NtDeleteValueKey                                   proto stdcall :DWORD, :DWORD
NtDeviceIoControlFile                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtDisplayString                                    proto stdcall :DWORD
NtDuplicateObject                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtDuplicateToken                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtEnumerateKey                                     proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtEnumerateValueKey                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtExtendSection                                    proto stdcall :DWORD, :DWORD
NtFilterToken                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtFindAtom                                         proto stdcall :DWORD, :DWORD, :DWORD
NtFlushBuffersFile                                 proto stdcall :DWORD, :DWORD
NtFlushInstructionCache                            proto stdcall :DWORD, :DWORD, :DWORD
NtFlushKey                                         proto stdcall :DWORD
NtFlushVirtualMemory                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtFlushWriteBuffer                                 proto stdcall
NtFreeUserPhysicalPages                            proto stdcall :DWORD, :DWORD, :DWORD
NtFreeVirtualMemory                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtFsControlFile                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtGetContextThread                                 proto stdcall :DWORD, :DWORD
NtGetDevicePowerState                              proto stdcall :DWORD, :DWORD
NtGetPlugPlayEvent                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtGetTickCount                                     proto stdcall
NtGetWriteWatch                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtImpersonateAnonymousToken                        proto stdcall :DWORD
NtImpersonateClientOfPort                          proto stdcall :DWORD, :DWORD
NtImpersonateThread                                proto stdcall :DWORD, :DWORD, :DWORD
NtInitializeRegistry                               proto stdcall :DWORD
NtInitiatePowerAction                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtIsSystemResumeAutomatic                          proto stdcall
NtListenChannel                                    proto stdcall :DWORD, :DWORD
NtListenPort                                       proto stdcall :DWORD, :DWORD
NtLoadDriver                                       proto stdcall :DWORD
NtLoadKey2                                         proto stdcall :DWORD, :DWORD, :DWORD
NtLoadKey                                          proto stdcall :DWORD, :DWORD
NtLockFile                                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtLockVirtualMemory                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtMakeTemporaryObject                              proto stdcall :DWORD
NtMapUserPhysicalPages                             proto stdcall :DWORD, :DWORD, :DWORD
NtMapUserPhysicalPagesScatter                      proto stdcall :DWORD, :DWORD, :DWORD
NtMapViewOfSection                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtNotifyChangeDirectoryFile                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtNotifyChangeKey                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtNotifyChangeMultipleKeys                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtOpenChannel                                      proto stdcall :DWORD, :DWORD
NtOpenDirectoryObject                              proto stdcall :DWORD, :DWORD, :DWORD
NtOpenEvent                                        proto stdcall :DWORD, :DWORD, :DWORD
NtOpenEventPair                                    proto stdcall :DWORD, :DWORD, :DWORD
NtOpenFile                                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtOpenIoCompletion                                 proto stdcall :DWORD, :DWORD, :DWORD
NtOpenJobObject                                    proto stdcall :DWORD, :DWORD, :DWORD
NtOpenKey                                          proto stdcall :DWORD, :DWORD, :DWORD
NtOpenMutant                                       proto stdcall :DWORD, :DWORD, :DWORD
NtOpenObjectAuditAlarm                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtOpenProcess                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtOpenProcessToken                                 proto stdcall :DWORD, :DWORD, :DWORD
NtOpenSection                                      proto stdcall :DWORD, :DWORD, :DWORD
NtOpenSemaphore                                    proto stdcall :DWORD, :DWORD, :DWORD
NtOpenSymbolicLinkObject                           proto stdcall :DWORD, :DWORD, :DWORD
NtOpenThread                                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtOpenThreadToken                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtOpenTimer                                        proto stdcall :DWORD, :DWORD, :DWORD
NtPlugPlayControl                                  proto stdcall :DWORD, :DWORD, :DWORD
NtPowerInformation                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtPrivilegeCheck                                   proto stdcall :DWORD, :DWORD, :DWORD
NtPrivilegeObjectAuditAlarm                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtPrivilegedServiceAuditAlarm                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtProtectVirtualMemory                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtPulseEvent                                       proto stdcall :DWORD, :DWORD
NtQueryAttributesFile                              proto stdcall :DWORD, :DWORD
NtQueryDefaultLocale                               proto stdcall :DWORD, :DWORD
NtQueryDefaultUILanguage                           proto stdcall :DWORD
NtQueryDirectoryFile                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryDirectoryObject                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryEaFile                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryEvent                                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryFullAttributesFile                          proto stdcall :DWORD, :DWORD
NtQueryInformationAtom                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryInformationFile                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryInformationJobObject                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryInformationPort                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryInformationProcess                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryInformationThread                           proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryInformationToken                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryInstallUILanguage                           proto stdcall :DWORD
NtQueryIntervalProfile                             proto stdcall :DWORD, :DWORD
NtQueryIoCompletion                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryKey                                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryMultipleValueKey                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryMutant                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryObject                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryOpenSubKeys                                 proto stdcall :DWORD, :DWORD
NtQueryPerformanceCounter                          proto stdcall :DWORD, :DWORD
NtQueryQuotaInformationFile                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQuerySection                                     proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQuerySecurityObject                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQuerySemaphore                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQuerySymbolicLinkObject                          proto stdcall :DWORD, :DWORD, :DWORD
NtQuerySystemEnvironmentValue                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtQuerySystemInformation                           proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtQuerySystemTime                                  proto stdcall :DWORD
NtQueryTimer                                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryTimerResolution                             proto stdcall :DWORD, :DWORD, :DWORD
NtQueryValueKey                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryVirtualMemory                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueryVolumeInformationFile                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtQueueApcThread                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtRaiseException                                   proto stdcall :DWORD, :DWORD, :DWORD
NtRaiseHardError                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtReadFile                                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtReadFileScatter                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtReadRequestData                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtReadVirtualMemory                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtRegisterThreadTerminatePort                      proto stdcall :DWORD
NtReleaseMutant                                    proto stdcall :DWORD, :DWORD
NtReleaseSemaphore                                 proto stdcall :DWORD, :DWORD, :DWORD
NtRemoveIoCompletion                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtReplaceKey                                       proto stdcall :DWORD, :DWORD, :DWORD
NtReplyPort                                        proto stdcall :DWORD, :DWORD
NtReplyWaitReceivePort                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtReplyWaitReceivePortEx                           proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtReplyWaitReplyPort                               proto stdcall :DWORD, :DWORD
NtReplyWaitSendChannel                             proto stdcall :DWORD, :DWORD, :DWORD
NtRequestDeviceWakeup                              proto stdcall :DWORD
NtRequestPort                                      proto stdcall :DWORD, :DWORD
NtRequestWaitReplyPort                             proto stdcall :DWORD, :DWORD, :DWORD
NtRequestWakeupLatency                             proto stdcall :DWORD
NtResetEvent                                       proto stdcall :DWORD, :DWORD
NtResetWriteWatch                                  proto stdcall :DWORD, :DWORD, :DWORD
NtRestoreKey                                       proto stdcall :DWORD, :DWORD, :DWORD
NtResumeThread                                     proto stdcall :DWORD, :DWORD
NtSaveKey                                          proto stdcall :DWORD, :DWORD
NtSaveMergedKeys                                   proto stdcall :DWORD, :DWORD, :DWORD
NtSecureConnectPort                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtSendWaitReplyChannel                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetContextChannel                                proto stdcall :DWORD
NtSetContextThread                                 proto stdcall :DWORD, :DWORD
NtSetDefaultHardErrorPort                          proto stdcall :DWORD
NtSetDefaultLocale                                 proto stdcall :DWORD, :DWORD
NtSetDefaultUILanguage                             proto stdcall :DWORD
NtSetEaFile                                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetEvent                                         proto stdcall :DWORD, :DWORD
NtSetHighEventPair                                 proto stdcall :DWORD
NtSetHighWaitLowEventPair                          proto stdcall :DWORD
NtSetInformationFile                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtSetInformationJobObject                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetInformationKey                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetInformationObject                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetInformationProcess                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetInformationThread                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetInformationToken                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetIntervalProfile                               proto stdcall :DWORD, :DWORD
NtSetIoCompletion                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtSetLdtEntries                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtSetLowEventPair                                  proto stdcall :DWORD
NtSetLowWaitHighEventPair                          proto stdcall :DWORD
NtSetQuotaInformationFile                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtSetSecurityObject                                proto stdcall :DWORD, :DWORD, :DWORD
NtSetSystemEnvironmentValue                        proto stdcall :DWORD, :DWORD
NtSetSystemInformation                             proto stdcall :DWORD, :DWORD, :DWORD
NtSetSystemPowerState                              proto stdcall :DWORD, :DWORD, :DWORD
NtSetSystemTime                                    proto stdcall :DWORD, :DWORD
NtSetThreadExecutionState                          proto stdcall :DWORD, :DWORD
NtSetTimer                                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtSetTimerResolution                               proto stdcall :DWORD, :DWORD, :DWORD
NtSetUuidSeed                                      proto stdcall :DWORD
NtSetValueKey                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtSetVolumeInformationFile                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtShutdownSystem                                   proto stdcall :DWORD
NtSignalAndWaitForSingleObject                     proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtStartProfile                                     proto stdcall :DWORD
NtStopProfile                                      proto stdcall :DWORD
NtSuspendThread                                    proto stdcall :DWORD, :DWORD
NtSystemDebugControl                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtTerminateJobObject                               proto stdcall :DWORD, :DWORD
NtTerminateProcess                                 proto stdcall :DWORD, :DWORD
NtTerminateThread                                  proto stdcall :DWORD, :DWORD
NtTestAlert                                        proto stdcall
NtUnloadDriver                                     proto stdcall :DWORD
NtUnloadKey                                        proto stdcall :DWORD
NtUnlockFile                                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtUnlockVirtualMemory                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
NtUnmapViewOfSection                               proto stdcall :DWORD, :DWORD
NtVdmControl                                       proto stdcall :DWORD, :DWORD
NtWaitForMultipleObjects                           proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtWaitForSingleObject                              proto stdcall :DWORD, :DWORD, :DWORD
NtWaitHighEventPair                                proto stdcall :DWORD
NtWaitLowEventPair                                 proto stdcall :DWORD
NtWriteFile                                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtWriteFileGather                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtWriteRequestData                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtWriteVirtualMemory                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
NtYieldExecution                                   proto stdcall

PfxFindPrefix                                      proto stdcall :DWORD, :DWORD
PfxInitialize                                      proto stdcall :DWORD
PfxInsertPrefix                                    proto stdcall :DWORD, :DWORD, :DWORD
PfxRemovePrefix                                    proto stdcall :DWORD, :DWORD
RtlAbortRXact                                      proto stdcall :DWORD
RtlAddAccessAllowedAce                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAccessAllowedAceEx                           proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAccessAllowedObjectAce                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAccessDeniedAce                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAccessDeniedAceEx                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAccessDeniedObjectAce                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAce                                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddActionToRXact                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAtomToAtomTable                              proto stdcall :DWORD, :DWORD, :DWORD
RtlAddAttributeActionToRXact                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAuditAccessAce                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAuditAccessAceEx                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddAuditAccessObjectAce                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddCompoundAce                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAddRange                                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlAllocateAndInitializeSid                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlApplyRXact                                      proto stdcall :DWORD
RtlApplyRXactNoFlush                               proto stdcall :DWORD
RtlAreAllAccessesGranted                           proto stdcall :DWORD, :DWORD
RtlAreAnyAccessesGranted                           proto stdcall :DWORD, :DWORD
RtlAreBitsClear                                    proto stdcall :DWORD, :DWORD, :DWORD
RtlAreBitsSet                                      proto stdcall :DWORD, :DWORD, :DWORD
RtlClearAllBits                                    proto stdcall :DWORD
RtlClearBits                                       proto stdcall :DWORD, :DWORD, :DWORD
RtlConvertToAutoInheritSecurityObject              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlConvertUiListToApiList                          proto stdcall :DWORD, :DWORD, :DWORD
RtlConvertUlongToLargeInteger                      proto stdcall :DWORD
RtlCopyLuid                                        proto stdcall :DWORD, :DWORD
RtlCopyLuidAndAttributesArray                      proto stdcall :DWORD, :DWORD, :DWORD
RtlCopyRangeList                                   proto stdcall :DWORD, :DWORD
RtlCopySecurityDescriptor                          proto stdcall :DWORD, :DWORD
RtlCopySidAndAttributesArray                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlCreateAcl                                       proto stdcall :DWORD, :DWORD, :DWORD
RtlCreateAndSetSD                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlCreateAtomTable                                 proto stdcall :DWORD, :DWORD
RtlCreateEnvironment                               proto stdcall :DWORD, :DWORD
RtlCreateUserSecurityObject                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlCustomCPToUnicodeN                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlCutoverTimeToSystemTime                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlDefaultNpAcl                                    proto stdcall :DWORD
RtlDelete                                          proto stdcall :DWORD
RtlDeleteAce                                       proto stdcall :DWORD, :DWORD
RtlDeleteAtomFromAtomTable                         proto stdcall :DWORD, :DWORD
RtlDeleteElementGenericTable                       proto stdcall :DWORD, :DWORD
RtlDeleteNoSplay                                   proto stdcall :DWORD, :DWORD
RtlDeleteOwnersRanges                              proto stdcall :DWORD, :DWORD
RtlDeleteRange                                     proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlDeleteSecurityObject                            proto stdcall :DWORD
RtlDestroyAtomTable                                proto stdcall :DWORD
RtlDestroyEnvironment                              proto stdcall :DWORD
RtlDnsHostNameToComputerName                       proto stdcall :DWORD, :DWORD, :DWORD
RtlDumpResource                                    proto stdcall :DWORD
RtlEmptyAtomTable                                  proto stdcall :DWORD, :DWORD
RtlEnlargedIntegerMultiply                         proto stdcall :DWORD, :DWORD
RtlEnlargedUnsignedDivide                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlEnlargedUnsignedMultiply                        proto stdcall :DWORD, :DWORD
RtlEnumerateGenericTable                           proto stdcall :DWORD, :DWORD
RtlEnumerateGenericTableWithoutSplaying            proto stdcall :DWORD, :DWORD
RtlEqualComputerName                               proto stdcall :DWORD, :DWORD
RtlEqualDomainName                                 proto stdcall :DWORD, :DWORD
RtlEqualLuid                                       proto stdcall :DWORD, :DWORD
RtlEqualPrefixSid                                  proto stdcall :DWORD, :DWORD
RtlExpandEnvironmentStrings_U                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlExtendedIntegerMultiply                         proto stdcall :DWORD, :DWORD, :DWORD
RtlExtendedLargeIntegerDivide                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlExtendedMagicDivide                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlFindClearBits                                   proto stdcall :DWORD, :DWORD, :DWORD
RtlFindClearBitsAndSet                             proto stdcall :DWORD, :DWORD, :DWORD
RtlFindLastBackwardRunClear                        proto stdcall :DWORD, :DWORD, :DWORD
RtlFindLeastSignificantBit                         proto stdcall :DWORD, :DWORD
RtlFindLongestRunClear                             proto stdcall :DWORD, :DWORD
RtlFindMessage                                     proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlFindMostSignificantBit                          proto stdcall :DWORD, :DWORD
RtlFindNextForwardRunClear                         proto stdcall :DWORD, :DWORD, :DWORD
RtlFindRange                                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlFindSetBits                                     proto stdcall :DWORD, :DWORD, :DWORD
RtlFindSetBitsAndClear                             proto stdcall :DWORD, :DWORD, :DWORD
RtlFormatCurrentUserKeyPath                        proto stdcall :DWORD
RtlFormatMessage                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlFreeRangeList                                   proto stdcall :DWORD
RtlFreeSid                                         proto stdcall :DWORD
RtlGetAce                                          proto stdcall :DWORD, :DWORD, :DWORD
RtlGetElementGenericTable                          proto stdcall :DWORD, :DWORD
RtlGetFirstRange                                   proto stdcall :DWORD, :DWORD, :DWORD
RtlGetNextRange                                    proto stdcall :DWORD, :DWORD, :DWORD
RtlGetNtProductType                                proto stdcall :DWORD
RtlGetSecurityDescriptorRMControl                  proto stdcall :DWORD, :DWORD
RtlIdentifierAuthoritySid                          proto stdcall :DWORD
RtlImpersonateSelf                                 proto stdcall :DWORD
RtlInitializeAtomPackage                           proto stdcall :DWORD
RtlInitializeBitMap                                proto stdcall :DWORD, :DWORD, :DWORD
RtlInitializeGenericTable                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlInitializeRXact                                 proto stdcall :DWORD, :DWORD, :DWORD
RtlInitializeRangeList                             proto stdcall :DWORD
RtlInsertElementGenericTable                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlInvertRangeList                                 proto stdcall :DWORD, :DWORD
RtlIsGenericTableEmpty                             proto stdcall :DWORD
RtlIsRangeAvailable                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlIsTextUnicode                                   proto stdcall :DWORD, :DWORD, :DWORD
RtlLargeIntegerAdd                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlLargeIntegerArithmeticShift                     proto stdcall :DWORD, :DWORD, :DWORD
RtlLargeIntegerDivide                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlLargeIntegerNegate                              proto stdcall :DWORD, :DWORD
RtlLargeIntegerShiftLeft                           proto stdcall :DWORD, :DWORD, :DWORD
RtlLargeIntegerShiftRight                          proto stdcall :DWORD, :DWORD, :DWORD
RtlLargeIntegerSubtract                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlLengthSecurityDescriptor                        proto stdcall :DWORD
RtlLocalTimeToSystemTime                           proto stdcall :DWORD, :DWORD
RtlLookupAtomInAtomTable                           proto stdcall :DWORD, :DWORD, :DWORD
RtlLookupElementGenericTable                       proto stdcall :DWORD, :DWORD
RtlMakeSelfRelativeSD                              proto stdcall :DWORD, :DWORD, :DWORD
RtlMapGenericMask                                  proto stdcall :DWORD, :DWORD
RtlMergeRangeLists                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlNewInstanceSecurityObject                       proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlNewSecurityGrantedAccess                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlNewSecurityObjectEx                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlNumberGenericTableElements                      proto stdcall :DWORD
RtlNumberOfClearBits                               proto stdcall :DWORD
RtlNumberOfSetBits                                 proto stdcall :DWORD
RtlPinAtomInAtomTable                              proto stdcall :DWORD, :DWORD
RtlQueryAtomInAtomTable                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlQueryEnvironmentVariable_U                      proto stdcall :DWORD, :DWORD, :DWORD
RtlQueryInformationAcl                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlQuerySecurityObject                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlQueryTimeZoneInformation                        proto stdcall :DWORD
RtlRealPredecessor                                 proto stdcall :DWORD
RtlRealSuccessor                                   proto stdcall :DWORD
RtlResetRtlTranslations                            proto stdcall :DWORD
RtlSelfRelativeToAbsoluteSD2                       proto stdcall :DWORD, :DWORD
RtlSetAllBits                                      proto stdcall :DWORD
RtlSetAttributesSecurityDescriptor                 proto stdcall :DWORD, :DWORD, :DWORD
RtlSetBits                                         proto stdcall :DWORD, :DWORD, :DWORD
RtlSetControlSecurityDescriptor                    proto stdcall :DWORD, :DWORD, :DWORD
RtlSetCurrentEnvironment                           proto stdcall :DWORD, :DWORD
RtlSetEnvironmentVariable                          proto stdcall :DWORD, :DWORD, :DWORD
RtlSetSecurityDescriptorRMControl                  proto stdcall :DWORD, :DWORD
RtlSetSecurityObjectEx                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlSetTimeZoneInformation                          proto stdcall :DWORD
RtlSetUnicodeCallouts                              proto stdcall :DWORD
RtlSplay                                           proto stdcall :DWORD
RtlStartRXact                                      proto stdcall :DWORD
RtlSubtreePredecessor                              proto stdcall :DWORD
RtlSubtreeSuccessor                                proto stdcall :DWORD
RtlSystemTimeToLocalTime                           proto stdcall :DWORD, :DWORD
RtlTimeToElapsedTimeFields                         proto stdcall :DWORD, :DWORD
RtlTraceDatabaseAdd                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlTraceDatabaseCreate                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlTraceDatabaseDestroy                            proto stdcall :DWORD
RtlTraceDatabaseEnumerate                          proto stdcall :DWORD, :DWORD, :DWORD
RtlTraceDatabaseFind                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlTraceDatabaseLock                               proto stdcall :DWORD
RtlTraceDatabaseUnlock                             proto stdcall :DWORD
RtlTraceDatabaseValidate                           proto stdcall :DWORD
RtlUniform                                         proto stdcall :DWORD
RtlUnwind                                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlValidRelativeSecurityDescriptor                 proto stdcall :DWORD, :DWORD, :DWORD
RtlValidSecurityDescriptor                         proto stdcall :DWORD
RtlpNtCreateKey                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlpNtEnumerateSubKey                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlpNtMakeTemporaryKey                             proto stdcall :DWORD
RtlpNtOpenKey                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlpNtQueryValueKey                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlpNtSetValueKey                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
RtlpUnWaitCriticalSection                          proto stdcall :DWORD

ZwAccessCheck                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAccessCheckAndAuditAlarm                         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAccessCheckByType                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAccessCheckByTypeAndAuditAlarm                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAccessCheckByTypeResultList                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAccessCheckByTypeResultListAndAuditAlarm         proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAccessCheckByTypeResultListAndAuditAlarmByHandle proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAdjustGroupsToken                                proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAdjustPrivilegesToken                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwAllocateLocallyUniqueId                          proto stdcall :DWORD
ZwAllocateUuids                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwAssignProcessToJobObject                         proto stdcall :DWORD, :DWORD
ZwCallbackReturn                                   proto stdcall :DWORD, :DWORD, :DWORD
ZwCancelDeviceWakeupRequest                        proto stdcall :DWORD
ZwCloseObjectAuditAlarm                            proto stdcall :DWORD, :DWORD, :DWORD
ZwCreateChannel                                    proto stdcall :DWORD, :DWORD
ZwCreateJobObject                                  proto stdcall :DWORD, :DWORD, :DWORD
ZwCreateMailslotFile                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwCreateNamedPipeFile                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwCreatePagingFile                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwCreateProfile                                    proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwCreateToken                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwDeleteObjectAuditAlarm                           proto stdcall :DWORD, :DWORD, :DWORD

ZwDuplicateToken                                   proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwFilterToken                                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwGetDevicePowerState                              proto stdcall :DWORD, :DWORD
ZwGetPlugPlayEvent                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwInitiatePowerAction                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwIsSystemResumeAutomatic                          proto stdcall
ZwListenChannel                                    proto stdcall :DWORD, :DWORD

ZwOpenChannel                                      proto stdcall :DWORD, :DWORD
ZwOpenJobObject                                    proto stdcall :DWORD, :DWORD, :DWORD
ZwOpenObjectAuditAlarm                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwOpenThreadToken                                  proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwPlugPlayControl                                  proto stdcall :DWORD, :DWORD, :DWORD
ZwPowerInformation                                 proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwPrivilegeCheck                                   proto stdcall :DWORD, :DWORD, :DWORD
ZwPrivilegeObjectAuditAlarm                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwPrivilegedServiceAuditAlarm                      proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwQueryDefaultLocale                               proto stdcall :DWORD, :DWORD
ZwQueryDefaultUILanguage                           proto stdcall :DWORD
ZwQueryDirectoryFile                               proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

ZwQueryInformationJobObject                        proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwQueryInformationToken                            proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ZwQueryInstallUILanguage                           proto stdcall :DWORD
ZwQueryIntervalProfile                             proto stdcall :DWORD, :DWORD
ZwQueryPerformanceCounter                          proto stdcall :DWORD, :DWORD
ZwQuerySystemTime                                  proto stdcall :DWORD

ZwReplyWaitSendChannel                             proto stdcall :DWORD, :DWORD, :DWORD
ZwRequestDeviceWakeup                              proto stdcall :DWORD
ZwRequestWakeupLatency                             proto stdcall :DWORD
ZwSendWaitReplyChannel                             proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwSetContextChannel                                proto stdcall :DWORD
ZwSetDefaultLocale                                 proto stdcall :DWORD, :DWORD
ZwSetDefaultUILanguage                             proto stdcall :DWORD
ZwSetInformationJobObject                          proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwSetInformationToken                              proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
ZwSetIntervalProfile                               proto stdcall :DWORD, :DWORD

ZwSetSystemPowerState                              proto stdcall :DWORD, :DWORD, :DWORD
ZwSetSystemTime                                    proto stdcall :DWORD, :DWORD
ZwSetTimerResolution                               proto stdcall :DWORD, :DWORD, :DWORD
ZwSetUuidSeed                                      proto stdcall :DWORD
ZwStartProfile                                     proto stdcall :DWORD
ZwStopProfile                                      proto stdcall :DWORD
ZwTerminateJobObject                               proto stdcall :DWORD, :DWORD


_rt_probe_read4                                    proto stdcall :DWORD
_seh_longjmp_unwind                                proto stdcall :DWORD

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
;:                                             CDECL                                              ::
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

;__eCommonExceptions PROTO C :VARARG
;__eEmulatorInit PROTO C :VARARG

; FPU Emulator
comment ^
__eF2XM1 PROTO C :VARARG
__eFABS PROTO C :VARARG
__eFADD32 PROTO C :VARARG
__eFADD64 PROTO C :VARARG
__eFADDPreg PROTO C :VARARG
__eFADDreg PROTO C :VARARG
__eFADDtop PROTO C :VARARG
__eFCHS PROTO C :VARARG
__eFCOM PROTO C :VARARG
__eFCOM32 PROTO C :VARARG
__eFCOM64 PROTO C :VARARG
__eFCOMP PROTO C :VARARG
__eFCOMP32 PROTO C :VARARG
__eFCOMP64 PROTO C :VARARG
__eFCOMPP PROTO C :VARARG
__eFCOS PROTO C :VARARG
__eFDECSTP PROTO C :VARARG
__eFDIV32 PROTO C :VARARG
__eFDIV64 PROTO C :VARARG
__eFDIVPreg PROTO C :VARARG
__eFDIVR32 PROTO C :VARARG
__eFDIVR64 PROTO C :VARARG
__eFDIVreg PROTO C :VARARG
__eFDIVRPreg PROTO C :VARARG
__eFDIVRreg PROTO C :VARARG
__eFDIVRtop PROTO C :VARARG
__eFDIVtop PROTO C :VARARG
__eFFREE PROTO C :VARARG
__eFIADD16 PROTO C :VARARG
__eFIADD32 PROTO C :VARARG
__eFICOM16 PROTO C :VARARG
__eFICOM32 PROTO C :VARARG
__eFICOMP16 PROTO C :VARARG
__eFICOMP32 PROTO C :VARARG
__eFIDIV16 PROTO C :VARARG
__eFIDIV32 PROTO C :VARARG
__eFIDIVR16 PROTO C :VARARG
__eFIDIVR32 PROTO C :VARARG
__eFILD16 PROTO C :VARARG
__eFILD32 PROTO C :VARARG
__eFILD64 PROTO C :VARARG
__eFIMUL16 PROTO C :VARARG
__eFIMUL32 PROTO C :VARARG
__eFINCSTP PROTO C :VARARG
__eFINIT PROTO C :VARARG
__eFIST16 PROTO C :VARARG
__eFIST32 PROTO C :VARARG
__eFISTP16 PROTO C :VARARG
__eFISTP32 PROTO C :VARARG
__eFISTP64 PROTO C :VARARG
__eFISUB16 PROTO C :VARARG
__eFISUB32 PROTO C :VARARG
__eFISUBR16 PROTO C :VARARG
__eFISUBR32 PROTO C :VARARG
__eFLD1 PROTO C :VARARG
__eFLD32 PROTO C :VARARG
__eFLD64 PROTO C :VARARG
__eFLD80 PROTO C :VARARG
__eFLDCW PROTO C :VARARG
__eFLDENV PROTO C :VARARG
__eFLDL2E PROTO C :VARARG
__eFLDLN2 PROTO C :VARARG
__eFLDPI PROTO C :VARARG
__eFLDZ PROTO C :VARARG
__eFMUL32 PROTO C :VARARG
__eFMUL64 PROTO C :VARARG
__eFMULPreg PROTO C :VARARG
__eFMULreg PROTO C :VARARG
__eFMULtop PROTO C :VARARG
__eFPATAN PROTO C :VARARG
__eFPREM PROTO C :VARARG
__eFPREM1 PROTO C :VARARG
__eFPTAN PROTO C :VARARG
__eFRNDINT PROTO C :VARARG
__eFRSTOR PROTO C :VARARG
__eFSAVE PROTO C :VARARG
__eFSCALE PROTO C :VARARG
__eFSIN PROTO C :VARARG
__eFSQRT PROTO C :VARARG
__eFST PROTO C :VARARG
__eFST32 PROTO C :VARARG
__eFST64 PROTO C :VARARG
__eFSTCW PROTO C :VARARG
__eFSTENV PROTO C :VARARG
__eFSTP PROTO C :VARARG
__eFSTP32 PROTO C :VARARG
__eFSTP64 PROTO C :VARARG
__eFSTP80 PROTO C :VARARG
__eFSTSW PROTO C :VARARG
__eFSUB32 PROTO C :VARARG
__eFSUB64 PROTO C :VARARG
__eFSUBPreg PROTO C :VARARG
__eFSUBR32 PROTO C :VARARG
__eFSUBR64 PROTO C :VARARG
__eFSUBreg PROTO C :VARARG
__eFSUBRPreg PROTO C :VARARG
__eFSUBRreg PROTO C :VARARG
__eFSUBRtop PROTO C :VARARG
__eFSUBtop PROTO C :VARARG
__eFTST PROTO C :VARARG
__eFUCOM PROTO C :VARARG
__eFUCOMP PROTO C :VARARG
__eFUCOMPP PROTO C :VARARG
__eFXAM PROTO C :VARARG
__eFXCH PROTO C :VARARG
__eFXTRACT PROTO C :VARARG
__eFYL2X PROTO C :VARARG
__eFYL2XP1 PROTO C :VARARG
^
__eGetStatusWord PROTO C
__isascii PROTO C :DWORD
__iscsym PROTO C :DWORD
__iscsymf PROTO C :DWORD
__toascii PROTO C :DWORD
;_abnormal_termination PROTO C

; Some funcs below are decorated as __cdecl
; but pop arguments from the stack.

_alldiv PROTO C :DWORD, :DWORD, :DWORD, :DWORD
_allmul PROTO C :DWORD, :DWORD, :DWORD, :DWORD
;_alloca_probe PROTO C :VARARG
;_allrem PROTO C :DWORD, :DWORD, :DWORD, :DWORD	; ???!!!
_allshl PROTO C	; ???!!!
_allshr PROTO C	; ???!!!
_atoi64 PROTO C :DWORD
_aulldiv PROTO C :DWORD, :DWORD, :DWORD, :DWORD
_aullrem PROTO C :DWORD, :DWORD, :DWORD, :DWORD
_aullshr PROTO C	; ???!!!
;_chkstk PROTO C :VARARG	; !!!
;_CIpow PROTO C :VARARG
;_except_handler2 PROTO C
;_except_handler3 PROTO C
;_except_list PROTO C
;_fltused PROTO C :VARARG
;_ftol PROTO C :VARARG
;_global_unwind2 PROTO C
_i64toa PROTO C :DWORD, :DWORD, :DWORD, :DWORD
_i64tow PROTO C :DWORD, :DWORD, :DWORD, :DWORD
_itoa PROTO C :DWORD, :DWORD, :DWORD
_itow PROTO C :DWORD, :DWORD, :DWORD
;_local_unwind2 PROTO C
;_longjmpex PROTO C :VARARG
_ltoa PROTO C :DWORD, :DWORD, :DWORD
_ltow PROTO C :DWORD, :DWORD, :DWORD
_memccpy PROTO C :DWORD, :DWORD, :DWORD, :DWORD
_memicmp PROTO C :DWORD, :DWORD, :DWORD
;_setjmp PROTO C :VARARG
;_setjmp3 PROTO C :VARARG
;_setjmpexused PROTO C :VARARG
_snprintf PROTO C :DWORD, :DWORD, :DWORD, :VARARG
_snwprintf PROTO C :DWORD, :DWORD, :DWORD, :VARARG
_splitpath PROTO C :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
_strcmpi PROTO C :DWORD, :DWORD
_stricmp PROTO C :DWORD, :DWORD
_strlwr PROTO C :DWORD
_strnicmp PROTO C :DWORD, :DWORD, :DWORD
_strupr PROTO C :DWORD
_tolower PROTO C :DWORD
_toupper PROTO C :DWORD
_ui64toa PROTO C :DWORD, :DWORD, :DWORD, :DWORD
_ultoa PROTO C :DWORD, :DWORD, :DWORD
_ultow PROTO C :DWORD, :DWORD, :DWORD
_vsnprintf PROTO C :DWORD, :DWORD, :DWORD, :DWORD
_wcsicmp PROTO C :DWORD, :DWORD
_wcslwr PROTO C :DWORD
_wcsnicmp PROTO C :DWORD, :DWORD, :DWORD
_wcsupr PROTO C :DWORD
_wtoi PROTO C :DWORD
_wtoi64 PROTO C :DWORD
_wtol PROTO C :DWORD
abs PROTO C :DWORD
atan PROTO C :DWORD, :DWORD	; double
atoi PROTO C :DWORD
;atol PROTO C :DWORD
ceil PROTO C :DWORD, :DWORD	; double
cos PROTO C :DWORD, :DWORD	; double
DbgPrint PROTO C :DWORD, :VARARG
DbgPrintReturnControlC PROTO C
;fabs PROTO C :VARARG
floor PROTO C :DWORD, :DWORD	; double
isalnum PROTO C :DWORD
isalpha PROTO C :DWORD
iscntrl PROTO C :DWORD
isdigit PROTO C :DWORD
isgraph PROTO C :DWORD
islower PROTO C :DWORD
isprint PROTO C :DWORD
ispunct PROTO C :DWORD
isspace PROTO C :DWORD
isupper PROTO C :DWORD
iswalpha PROTO C :DWORD
iswctype PROTO C :DWORD, :DWORD
iswdigit PROTO C :DWORD
iswlower PROTO C :DWORD
iswspace PROTO C :DWORD
iswxdigit PROTO C :DWORD
isxdigit PROTO C :DWORD
labs PROTO C :DWORD
log PROTO C :DWORD, :DWORD	; ???
longjmp PROTO C :DWORD, :DWORD
mbstowcs PROTO C :DWORD, :DWORD, :DWORD
memchr PROTO C :DWORD, :DWORD, :DWORD
memcmp PROTO C :DWORD, :DWORD, :DWORD
memcpy PROTO C :DWORD, :DWORD, :DWORD
memmove PROTO C :DWORD, :DWORD, :DWORD
memset PROTO C :DWORD, :DWORD, :DWORD
; exported variables
NlsAnsiCodePage PROTO C
NlsMbCodePageTag PROTO C
NlsMbOemCodePageTag PROTO C
;NPXEMULATORTABLE PROTO C :VARARG
pow PROTO C :DWORD, :DWORD, :DWORD, :DWORD	; ???
qsort PROTO C :DWORD, :DWORD, :DWORD, :DWORD
;raisex PROTO C :VARARG
RestoreEm87Context PROTO C :DWORD	; ???
SaveEm87Context PROTO C :DWORD	; ???
sin PROTO C :DWORD, :DWORD
sprintf PROTO C :DWORD, :DWORD, :VARARG
sqrt PROTO C :DWORD, :DWORD
sscanf PROTO C :DWORD, :DWORD, :VARARG
strcat PROTO C :DWORD, :DWORD
strchr PROTO C :DWORD, :DWORD
strcmp PROTO C :DWORD, :DWORD
strcpy PROTO C :DWORD, :DWORD
strcspn PROTO C :DWORD, :DWORD
strlen PROTO C :DWORD
strncat PROTO C :DWORD, :DWORD, :DWORD	
strncmp PROTO C :DWORD, :DWORD, :DWORD	
strncpy PROTO C :DWORD, :DWORD, :DWORD	
strpbrk PROTO C :DWORD, :DWORD
strrchr PROTO C :DWORD, :DWORD
strspn PROTO C :DWORD, :DWORD
strstr PROTO C :DWORD, :DWORD
strtol PROTO C :DWORD, :DWORD, :DWORD
strtoul PROTO C :DWORD, :DWORD, :DWORD
swprintf PROTO C :DWORD, :DWORD, :VARARG
tan PROTO C :DWORD, :DWORD
tolower PROTO C :DWORD
toupper PROTO C :DWORD
towlower PROTO C :DWORD
towupper PROTO C :DWORD
vsprintf PROTO C :DWORD, :DWORD, :DWORD
wcscat PROTO C :DWORD, :DWORD
wcschr PROTO C :DWORD, :DWORD
wcscmp PROTO C :DWORD, :DWORD
wcscpy PROTO C :DWORD, :DWORD
wcscspn PROTO C :DWORD, :DWORD
wcslen PROTO C :DWORD
wcsncat PROTO C :DWORD, :DWORD, :DWORD
wcsncmp PROTO C :DWORD, :DWORD, :DWORD
wcsncpy PROTO C :DWORD, :DWORD, :DWORD
wcspbrk PROTO C :DWORD, :DWORD
wcsrchr PROTO C :DWORD, :DWORD
wcsspn PROTO C :DWORD, :DWORD
wcsstr PROTO C :DWORD, :DWORD
wcstol PROTO C :DWORD, :DWORD, :DWORD
wcstombs PROTO C :DWORD, :DWORD, :DWORD
wcstoul PROTO C :DWORD, :DWORD, :DWORD

externdef syscall @RtlUlongByteSwap@4:proc
RtlUlongByteSwap textequ <@RtlUlongByteSwap@4>

externdef syscall @RtlUlonglongByteSwap@4:proc
RtlUlonglongByteSwap textequ <@RtlUlonglongByteSwap@4>

externdef syscall @RtlUshortByteSwap@4:proc
RtlUshortByteSwap textequ <@RtlUshortByteSwap@4>

PIN_WAIT		equ (1)
PIN_EXCLUSIVE	equ (2)
PIN_NO_READ	equ (4)
PIN_IF_BCB	equ (8)

MAP_WAIT		equ (1)
MAP_NO_READ	equ (16)