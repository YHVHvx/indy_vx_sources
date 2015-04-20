	.686
	.model flat, stdcall
	option casemap :none
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib

; User.h
;
; USERCONNECT - \
;               |
;               + SHAREDINFO - \
;               |              |
;                              + (ulSharedDelta)
;                              |
;                              + PSERVERINFO
;                              |
;                              + PDISPLAYINFO
;                              |
;                              + PHANDLEENTRY
;                              |

; TEB.CLIENTINFO - \
;                  |
;                  + (ulClientDelta)
;                  |
;                  + PDESKTOPINFO
;                  |
;                  + PCLIENTTHREADINFO
;                  |               

KERNEL_ULONG_PTR	typedef DWORD
KERNEL_PVOID		typedef DWORD

; Private types.
PPROCESSINFO		typedef PVOID
PWND				typedef PVOID
PVWPL			typedef PVOID
PFNCLIENT			typedef PVOID
PFNCLIENTWORKER	typedef PVOID
WNDPROC_PWNDEX		typedef PVOID
WNDPROC_PWND		typedef PVOID
PMONITOR			typedef PVOID
PHOOK			typedef PVOID
PDCE				typedef PVOID
PSPB				typedef PVOID
KHKL				typedef HANDLE
HBITMAP			typedef HANDLE

CWINHOOKS	equ (WH_MAX - WH_MIN + 1)

; +
;
DESKTOPINFO struct
pvDesktopBase		KERNEL_PVOID ?	; For handle validation
pvDesktopLimit		KERNEL_PVOID ?	; 
spwnd			PWND ?		; Desktop window
fsHooks			DWORD ?		; Deskop global hooks
aphkStart			PHOOK CWINHOOKS DUP (?)	; List of hooks
spwndShell		PWND ?	; Shell window
ppiShellProcess	PPROCESSINFO ?	; Shell Process
spwndBkGnd		PWND ?	; Shell background window
spwndTaskman		PWND ?	; Task-Manager window
spwndProgman		PWND ?	; Program-Manager window
pvwplShellHook		PVWPL ?	; see (De)RegisterShellHookWindow
cntMBox			ULONG ?
DESKTOPINFO ends
PDESKTOPINFO typedef ptr DESKTOPINFO

; +
; CI
; TEB.Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH]

CALLBACKWND struct
hwnd		HWND ?
pwnd		PWND ?
CALLBACKWND ends
PCALLBACKWND typedef ptr CALLBACKWND

CLIENTTHREADINFO struct
CTIF_flags		UINT ?
fsChangeBits		WORD ?	; Bits changes since last compared
fsWakeBits		WORD ?	; Bits currently available
fsWakeBitsJournal	WORD ?	; Bits saved while journalling
fsWakeMask		WORD ?	; Bits looking for when asleep
timeLastRead		LONG ?	; Time of last input read
CLIENTTHREADINFO ends
PCLIENTTHREADINFO typedef ptr CLIENTTHREADINFO

WIN32_CLIENT_INFO_LENGTH	equ 7CH	; sizeof(CLIENTINFO)

CVKKEYCACHE	equ 32
CBKEYCACHE	equ (CVKKEYCACHE shr 2)

CVKASYNCKEYCACHE	equ 16
CBASYNCKEYCACHE	equ (CVKASYNCKEYCACHE shr 2)

CLIENTINFO struct
CI_flags			KERNEL_ULONG_PTR ?	; Needs to be first because CSR sets this
cSpins			KERNEL_ULONG_PTR ?	; GDI resets this
dwExpWinVer		DWORD ?
dwCompatFlags		DWORD ?
dwCompatFlags2		DWORD ?
dwTIFlags			DWORD ?	; TIF_*
pDeskInfo			PDESKTOPINFO ?
ulClientDelta		KERNEL_ULONG_PTR ?
phkCurrent		PHOOK ?
fsHooks			DWORD ?
cWnd				CALLBACKWND <>
dwHookCurrent		DWORD ?
cInDDEMLCallback	DWORD ?
pClientThreadInfo	PCLIENTTHREADINFO ?
dwHookData		KERNEL_ULONG_PTR ?
dwKeyCache		DWORD ?
afKeyState		BYTE CBKEYCACHE DUP (?)
dwAsyncKeyCache	DWORD ?
afAsyncKeyState	BYTE CBASYNCKEYCACHE DUP (?) 
afAsyncKeyStateRecentDown	BYTE CBASYNCKEYCACHE DUP (?)
hKL				KHKL ?
CodePage			WORD ?
achDbcsCF			BYTE 2 DUP (?)
;msgDbcsCB		KERNEL_MSG ?
; #if LATER
; eventCached		EVENTMSG ?	; Cached Event for Journal Hook
CLIENTINFO ends
PCLIENTINFO typedef ptr CLIENTINFO

; +
; HE
;
HANDLEF_DESTROY		equ 1
HANDLEF_INDESTROY		equ 2
HANDLEF_INWAITFORDEATH	equ 4
HANDLEF_FINALDESTROY	equ 8
HANDLEF_MARKED_OK		equ 10H
HANDLEF_GRANTED		equ 20H
HANDLEF_VALID			equ 3FH

; Object types

TYPE_FREE			equ 0
TYPE_WINDOW		equ 1
TYPE_MENU			equ 2
TYPE_CURSOR		equ 3
TYPE_SETWINDOWPOS	equ 4
TYPE_HOOK			equ 5
TYPE_CLIPDATA		equ 6	; clipboard data
TYPE_CALLPROC		equ 7
TYPE_ACCELTABLE	equ 8
TYPE_DDEACCESS		equ 9
TYPE_DDECONV		equ 10
TYPE_DDEXACT		equ 11	; DDE transaction tracking info.
TYPE_MONITOR		equ 12
TYPE_KBDLAYOUT		equ 13	; Keyboard Layout handle (HKL) object.
TYPE_KBDFILE		equ 14	; Keyboard Layout file object.
TYPE_WINEVENTHOOK	equ 15	; WinEvent hook (EVENTHOOK)
TYPE_TIMER		equ 16
TYPE_INPUTCONTEXT	equ 17	; Input Context info structure
TYPE_CTYPES		equ 18	; Count of TYPEs; Must be LAST + 1
TYPE_GENERIC		equ 255	; used for generic handle validation

HMINDEXBITS	equ 0FFFFH	; Change HMINDEXBITS for bits that make up table index in handle
HMUNIQSHIFT	equ 16		; Change HMUNIQSHIFT for count of bits to shift uniqueness left.
HMUNIQBITS	equ 0FFFFH	; Change HMUNIQBITS for bits that make up uniqueness.

HEAD struct
h		HANDLE ?
cLockObj	DWORD ?
HEAD ends
PHEAD typedef ptr HEAD

HANDLEENTRY struct
phead	PHEAD ?	; pointer to the real object
pOwner	PVOID ?	; pointer to owning entity (pti or ppi)
bType	BYTE ?	; type of object
bFlags	BYTE ?	; flags - like destroy flag
wUniq	WORD ?	; uniqueness count
HANDLEENTRY ends
PHANDLEENTRY typedef ptr HANDLEENTRY
PHE typedef ptr PHANDLEENTRY

; +
; DISPLAYINFO
; NT:[gpDispInfo]

DISPLAYINFO struct
; device stuff
hDev				HANDLE ?
pmdev			PVOID ?
hDevInfo			HANDLE ?
; useful dcs
hdcScreen			HDC ?	; Device-Context for screen
hdcBits			HDC ?	; Holds system-bitmap resource
; Graystring resources
hdcGray			HDC ?	; GrayString DC.
hbmGray			HBITMAP ?	; GrayString Bitmap Surface.
cxGray			ULONG ?	; width of gray bitmap
cyGray			ULONG ?	; height of gray bitmap
; random stuff
pdceFirst			PDCE ?	; list of dcs
pspbFirst			PSPB ?	; list of spbs
; Monitors on this device
cMonitors			ULONG ?	; number of monitors attached to desktop
pMonitorPrimary	PMONITOR ?	; the primary monitor (display)
pMonitorFirst		PMONITOR ?	; monitor in use list
; device characteristics
rcScreen			RECT <>	; Rectangle of entire desktop surface
hrgnScreen		HRGN ?	; region describing virtual screen
dmLogPixels		WORD ?	; pixels per inch
BitCountMax		WORD ?	; Maximum bitcount across all monitors
DISPLAYINFO ends
PDISPLAYINFO typedef ptr DISPLAYINFO

FNID_START		equ 29AH
FNID_END			equ 2B4H
FNID_WNDPROCEND	equ 29EH

FNID_ARRAY_SIZE	equ 32

ICLS_MAX			equ 22	; Number of system classes

MBSTRING struct
szName	WCHAR 15 DUP (?)
uID		UINT ?
uStr		UINT ?
MBSTRING ends
PMBSTRING typedef ptr MBSTRING

; Total number of strings used as button strings in MessageBoxes
MAX_MB_STRINGS		equ 11

NCHARS			equ 256

; +
; SI
; [gpsi]
;
SERVERINFO struct
wRIPFlags			WORD ?	; RIPF_ flags
wSRVIFlags		WORD ?	; SRVIF_ flags
wRIPPID			WORD ?	; PID of process to apply RIP flags to (zero means all)
wRIPError			WORD ?	; Error to break on (zero means all errors are treated equal)
cHandleEntries		KERNEL_ULONG_PTR ?	; count of handle entries in array
; Array of server-side function pointers.
; Client passes servers function ID so they can be easily validated;
; this array maps function ID into server-side function address.
; The order of these are enforced by the FNID_ constants, and must match
; the client-side mpFnidClientPfn[] order as well.
mpFnidPfn			WNDPROC_PWNDEX FNID_ARRAY_SIZE DUP (<>)	; function mapping table
aStoCidPfn		WNDPROC_PWND (FNID_WNDPROCEND - FNID_START) + 1 DUP (<>)

; mapping of fnid to min bytes need by public windproc user
mpFnid_serverCBWndProc	WORD (FNID_END - FNID_START) + 1 DUP (<>)

; Client side functions pointer structure.
apfnClientA		PFNCLIENT ?	; Version dependent!
apfnClientW		PFNCLIENT ?
apfnClientWorker	PFNCLIENTWORKER ?

cbHandleTable		DWORD ?

; Class atoms to allow fast checks on the client.
atomSysClass		ATOM ICLS_MAX DUP (<>)	; Atoms for control classes

dwDefaultHeapBase	DWORD ?	; so WOW can do handle validation
dwDefaultHeapSize	DWORD ?

uiShellMsg		UINT ?	; message for shell hooks
wMaxBtnSize		UINT ?	; Size of the longest button string in any MessageBox
MBStrings			MBSTRING MAX_MB_STRINGS DUP (<>)

;values to allow HasCaptionIcon to be in user32
atomIconSmProp		ATOM <>
atomIconProp		ATOM <>

atomContextHelpIdProp	ATOM <>

acOemToAnsi		CHAR NCHARS DUP (?)
acAnsiToOem		CHAR NCHARS DUP (?)

; ..PERUSERSERVERINFO

; #if DEBUGTAGS
;    DWORD adwDBGTAGFlags[DBGTAG_Max + 1];
SERVERINFO ends
PSERVERINFO typedef ptr SERVERINFO

WNDMSG struct
maxMsgs	UINT ?
abMsgs	PVOID ?
WNDMSG ends
PWNDMSG typedef ptr WNDMSG

; +
; SHAREDINFO
; [WIN32:gSharedInfo]
;
SHAREDINFO struct
psi				PSERVERINFO ?
aheList			PHANDLEENTRY ?	; Handle table pointer.
pDispInfo			PDISPLAYINFO ?
ulSharedDelta		KERNEL_ULONG_PTR ?	; for REBASESHAREDPTR, NT:ghSectionShared, InitMapSharedSection()
awmControl		WNDMSG (FNID_END - FNID_START + 1) DUP (<>)
DefWindowMsgs		WNDMSG <>
DefWindowSpecMsgs	WNDMSG <>
SHAREDINFO ends
PSHAREDINFO typedef ptr SHAREDINFO

; +
;
USERCONNECT struct
ulVersion			ULONG ?	; USERCURRENTVERSION
ulCurrentVersion	ULONG ?	; OPTIONAL
dwDispatchCount	DWORD ?	; Число валидных теневых сервисов.
siClient			SHAREDINFO <>
USERCONNECT ends
PUSERCONNECT typedef ptr USERCONNECT

USER_MAJOR_VERSION	equ 5
USER_MINOR_VERSION	equ 0
USERCURRENTVERSION	equ ((USER_MAJOR_VERSION shl 16) or USER_MINOR_VERSION)

CSRSRV_SERVERDLL_INDEX	equ 0
BASESRV_SERVERDLL_INDEX	equ 1
CONSRV_SERVERDLL_INDEX	equ 2
USERSRV_SERVERDLL_INDEX	equ 3

.code
	ASSUME FS:NOTHING
; +
; Верификация описателя.
; Eax - ссылка на обьект в пользовательской проекции.
; Ecx - ссылка на обьект в ядерной проекции.
; Edx - ссылка на описатель обьекта.
;
ValidateHandle proc SharedInformation:PSHAREDINFO, ObjectType:ULONG, Handle:HANDLE
	mov ecx,SharedInformation
	mov edx,Handle
	mov eax,SHAREDINFO.psi[ecx]
	and edx,HMINDEXBITS
	cmp SERVERINFO.cHandleEntries[eax],edx	; limit.
	mov ecx,SHAREDINFO.aheList[ecx]
	jb Error
	lea edx,[edx + edx*2]	; sizeof(HANDLEENTRY) = 12
	mov eax,Handle
	lea edx,[ecx + edx*4]	;  p + n*12 = p + (n*3)*4
	shr eax,HMUNIQSHIFT
	mov ecx,ObjectType
	assume edx:PHANDLEENTRY
	cmp [edx].wUniq,ax
	jne Error
	cmp [edx].bType,cl
	jne Error
	mov ecx,fs:[CLIENTINFO.pDeskInfo[TEB.Win32ClientInfo]]
	mov eax,[edx].phead
	cmp DESKTOPINFO.pvDesktopBase[ecx],eax	; range.
	jnb Error
	cmp DESKTOPINFO.pvDesktopLimit[ecx],eax
	mov ecx,eax
	jb Error
	sub eax,fs:[CLIENTINFO.ulClientDelta[TEB.Win32ClientInfo]]
	jbe Error
Exit:
	ret
Error:
	xor eax,eax
	xor ecx,ecx
	xor edx,edx
	jmp Exit
ValidateHandle endp

; +
; Запрос к csrss для получения SHAREDINFO.
;
UserConnectToServer proc uses ebx esi edi pCsrClientConnectToServer:PVOID, ConnectionInformation:PUSERCONNECT
Local SessionDirectory[10]:WCHAR
Local ConnectionInformationLength:ULONG
Local CalledFromServer:BOOLEAN
	xor eax,eax
	mov ecx,ConnectionInformation
	mov ebx,STATUS_INVALID_PARAMETER
	mov ConnectionInformationLength,124H
; WINSS_OBJECT_DIRECTORY_NAME = "\Windows"
	mov dword ptr [SessionDirectory],('W' shl 16) or '\'
	mov USERCONNECT.ulVersion[ecx],USERCURRENTVERSION
	mov dword ptr [SessionDirectory + 2*2],('n' shl 16) or 'i'
	mov dword ptr [SessionDirectory + 4*2],('o' shl 16) or 'd'
	mov dword ptr [SessionDirectory + 6*2],('s' shl 16) or 'w'
	mov dword ptr [SessionDirectory + 8*2],eax
	mov CalledFromServer,eax
	lea esi,CalledFromServer
	lea edi,ConnectionInformationLength
	lea eax,SessionDirectory
	push esi
	push edi
	push ConnectionInformation
	push USERSRV_SERVERDLL_INDEX
	push eax
	Call pCsrClientConnectToServer
	cmp eax,ebx	; STATUS_UNSUCCESSFUL если версия не верна.
	mov ConnectionInformationLength,120H	; (FNID_END..)
	jne Exit
	lea eax,SessionDirectory
	push esi
	push edi
	push ConnectionInformation
	push USERSRV_SERVERDLL_INDEX
	push eax
	Call pCsrClientConnectToServer
	cmp eax,ebx
	mov ConnectionInformationLength,sizeof(USERCONNECT) + 4*8
	jne Exit
@@:
	lea eax,SessionDirectory
	push esi
	push edi
	push ConnectionInformation
	push USERSRV_SERVERDLL_INDEX
	push eax
	Call pCsrClientConnectToServer
	sub ConnectionInformationLength,4
	cmp eax,ebx
	jne Exit
	cmp ConnectionInformationLength,sizeof(USERCONNECT)
	jnb @b
Exit:
	ret
UserConnectToServer endp

_imp__IsMenu proto :dword

comment '
BOOL IsMenu(
   HMENU hMenu)
{
   if (HMValidateHandle(hMenu, TYPE_MENU))
      return TRUE;

   return FALSE;
}

$ IsMenu	8BFF			mov edi,edi
$+2		55			push ebp
$+3		8BEC			mov ebp,esp
$+5		8B4D 08		mov ecx,dword ptr ss:[ebp+8]
$+8		B2 02		mov dl,2
$+A		E8 A971FEFF	call HMValidateHandle
	'
%HM_VALIDATE_HANDLE macro
; Ecx:HANDLE
; dl:TYPE
	mov eax,dword ptr [_imp__IsMenu]	; @HMValidateHandle()
	add eax,dword ptr [eax + 10 + 1]
	add eax,15
	call eax
endm

TbClientDelta	equ 6E8H	; CLIENTINFO.ulClientDelta[TEB.Win32ClientInfo]

%GET_CURRENT_GRAPH_ENTRY macro
	Call GetGraphReference
endm

%GET_GRAPH_ENTRY macro PGET_CURRENT_GRAPH_ENTRY
	Call PGET_CURRENT_GRAPH_ENTRY
endm

%GET_GRAPH_REFERENCE macro
GetGraphReference::
	pop eax
	ret
endm

	%GET_GRAPH_REFERENCE

	assume fs:nothing
SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	jmp ecx
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 2*4]
	pop ebp
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	%GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov ecx,dword ptr [esp + 3*4]	; Ctx.
	mov edx,dword ptr [esp]	; ~ nt!ExecuteHandler2().
	mov ebx,CONTEXT.regEbx[ecx]
	mov esi,CONTEXT.regEsi[ecx]
	mov edi,CONTEXT.regEdi[ecx]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov ecx,EXCEPTION_RECORD.ExceptionAddress[eax]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

%APIERR macro
	.if !Eax
	int 3
	.endif
endm

%NTERR macro
	.if Eax
	int 3
	.endif
endm

$Text	CHAR "...",0
$Caption	CHAR "love",0	; l: 0x6C - INS.

; +
; WND
;
TwWindowRect	equ 58H
TwClientRect	equ 5CH
TwWndProc		equ 60H
TwClass		equ 64H
TwName		equ 88H	; tagWND.strName

xxxMessageBox proc
	invoke MessageBox, NULL, addr $Text, addr $Caption, MB_OK
	ret
xxxMessageBox endp

$Dbg	CHAR "%ws", 13, 10, 0
$NX	CHAR "NX: On", 13, 10, 0
$NXF	CHAR "NX: Off", 13, 10, 0

_imp__CsrClientConnectToServer proto :dword, :dword, :dword, :dword, :dword
	
Entry proc
Local ThreadId:HANDLE
Local ConnectionInformation[512]:BYTE
	invoke CreateThread, NULL, 0, addr xxxMessageBox, 0, 0, addr ThreadId
	%APIERR
	invoke Sleep, 2000
	invoke UserConnectToServer, dword ptr [_imp__CsrClientConnectToServer], addr ConnectionInformation
	%NTERR
	invoke FindWindow, NULL, addr $Caption
	%APIERR
	mov ecx,eax
	mov dl,TYPE_WINDOW
	%HM_VALIDATE_HANDLE
;	invoke ValidateHandle, addr USERCONNECT.siClient[ConnectionInformation], TYPE_WINDOW, Eax
	%APIERR
	mov eax,dword ptr [eax + TwName]
	sub eax,dword ptr fs:[TbClientDelta]	; PWSTR
;	add eax,dword ptr [eax + TwName]
;	sub eax,ecx
	mov ebx,eax
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	Call ebx
	xor eax,eax
	jmp Xcpt
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Xcpt:
	.if Eax == STATUS_PRIVILEGED_INSTRUCTION
	   invoke DbgPrint, addr $NXF
	.else
	   invoke DbgPrint, addr $NX	; #STATUS_ACCESS_VIOLATION
	.endif
	ret
Entry endp
end Entry