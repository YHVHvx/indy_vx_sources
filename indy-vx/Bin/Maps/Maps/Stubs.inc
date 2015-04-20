SERVICES_LIST struct
iNtAllocateVirtualMemory		ULONG ?
iNtClose					ULONG ?
iNtFreeVirtualMemory		ULONG ?
iNtOpenDirectoryObject		ULONG ?
iNtOpenSymbolicLinkObject	ULONG ?
iNtQuerySymbolicLinkObject	ULONG ?
iNtQuerySystemInformation	ULONG ?
iNtQueryVirtualMemory		ULONG ?
Eol						ULONG ?
SERVICES_LIST ends
PSERVICES_LIST typedef ptr SERVICES_LIST

$NtQueryVirtualMemory macro p1, p2, p3, p4, p5, p6
	FOR Arg, <p6,p5,p4,p3,p2,p1>
	IFNB <Arg>
	push Arg
	ENDIF
	ENDM
	mov eax,SERVICES_LIST.iNtQueryVirtualMemory[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 6*4]
endm

$NtAllocateVirtualMemory macro p1, p2, p3, p4, p5, p6
	FOR Arg, <p6,p5,p4,p3,p2,p1>
	IFNB <Arg>
	push Arg
	ENDIF
	ENDM
	mov eax,SERVICES_LIST.iNtAllocateVirtualMemory[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 6*4]
endm

$NtClose macro p1
	IFNB <p1>
	push p1
	ENDIF
	mov eax,SERVICES_LIST.iNtClose[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 4]
endm

$NtFreeVirtualMemory macro p1, p2, p3, p4
	FOR Arg, <p4,p3,p2,p1>
	IFNB <Arg>
	push Arg
	ENDIF
	ENDM
	mov eax,SERVICES_LIST.iNtFreeVirtualMemory[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 4*4]
endm

$NtOpenDirectoryObject macro p1, p2, p3
	FOR Arg, <p3,p2,p1>
	IFNB <Arg>
	push Arg
	ENDIF
	ENDM
	mov eax,SERVICES_LIST.iNtOpenDirectoryObject[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 3*4]
endm

$NtOpenSymbolicLinkObject macro p1, p2, p3
	FOR Arg, <p3,p2,p1>
	IFNB <Arg>
	push Arg
	ENDIF
	ENDM
	mov eax,SERVICES_LIST.iNtOpenSymbolicLinkObject[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 3*4]
endm

$NtQuerySymbolicLinkObject macro p1, p2, p3
	FOR Arg, <p3,p2,p1>
	IFNB <Arg>
	push Arg
	ENDIF
	ENDM
	mov eax,SERVICES_LIST.iNtQuerySymbolicLinkObject[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 3*4]
endm

$NtQuerySystemInformation macro p1, p2, p3, p4
	FOR Arg, <p4,p3,p2,p1>
	IFNB <Arg>
	push Arg
	ENDIF
	ENDM
	mov eax,SERVICES_LIST.iNtQuerySystemInformation[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 4*4]
endm

$NtQueryVirtualMemory macro p1, p2, p3, p4, p5, p6
	FOR Arg, <p6,p5,p4,p3,p2,p1>
	IFNB <Arg>
	push Arg
	ENDIF
	ENDM
	mov eax,SERVICES_LIST.iNtQueryVirtualMemory[ebx]
	mov edx,esp
	Int 2EH
	lea esp,[esp + 6*4]
endm