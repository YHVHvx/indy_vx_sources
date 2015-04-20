; Макро для работы с TLS.
;
; Загрузка пост-хэндлера при S-маршрутизации.
;
%TLS_SET_SROUTE_STUB macro Reg32, pTls
	ifdef pTls
	   mov dword ptr TLS.RouteIp[pTls],Reg32
	else
	   mov ecx,Tls
	   mov dword ptr TLS.RouteIp[ecx],Reg32
	endif
endm

%TLS_GET_SROUTE_STUB macro Reg32, pTls
	ifdef pTls
	   mov Reg32,dword ptr TLS.RouteIp[pTls]
	else
	   mov Reg32,Tls
	   mov Reg32,dword ptr TLS.RouteIp[Reg32]
	endif
endm

%TLS_SET_SKIP_STUB macro Reg32, pTls
	ifdef pTls
	   mov dword ptr TLS.SkipIp[pTls],Reg32
	else
	   mov ecx,Tls
	   mov dword ptr TLS.SkipIp[ecx],Reg32
	endif
endm

%TLS_GET_SKIP_STUB macro Reg32, pTls
	ifdef pTls
	   mov Reg32,dword ptr TLS.SkipIp[pTls]
	else
	   mov Reg32,Tls
	   mov Reg32,dword ptr TLS.SkipIp[Reg32]
	endif
endm

%TLS_SET_2NDF_STUB macro Reg32, pTls
	ifdef pTls
	   mov dword ptr TLS.Ip2ndf[pTls],Reg32
	else
	   mov ecx,Tls
	   mov dword ptr TLS.Ip2ndf[ecx],Reg32
	endif
endm

%TLS_GET_2NDF_STUB macro Reg32, pTls
	ifdef pTls
	   mov Reg32,dword ptr TLS.Ip2ndf[pTls]
	else
	   mov Reg32,Tls
	   mov Reg32,dword ptr TLS.Ip2ndf[Reg32]
	endif
endm

%TLS_SET_POST_STUB macro Reg32, pTls
	ifdef pTls
	   mov dword ptr TLS.PostIp[pTls],Reg32
	else
	   mov ecx,Tls
	   mov dword ptr TLS.PostIp[ecx],Reg32
	endif
endm

%TLS_START_TRACE macro pTls
	ifdef pTls
	   bts dword ptr TLS.Flags[pTls],0
	else
	   mov ecx,Tls
	   bts dword ptr TLS.Flags[ecx],0
	endif
endm

%TLS_STOP_TRACE macro pTls
	ifdef pTls
	   btr dword ptr TLS.Flags[pTls],0
	else
	   mov ecx,Tls
	   btr dword ptr TLS.Flags[ecx],0
	endif
endm

%TLS_IS_TRACE macro pTls
	ifdef pTls
	   bt dword ptr TLS.Flags[pTls],0
	else
	   mov ecx,Tls
	   bt dword ptr TLS.Flags[ecx],0
	endif
endm

%TLS_START_STRACE macro pTls
	ifdef pTls
	   bts dword ptr TLS.Flags[pTls],1
	else
	   mov ecx,Tls
	   bts dword ptr TLS.Flags[ecx],1
	endif
endm

%TLS_STOP_STRACE macro pTls
	ifdef pTls
	   btr dword ptr TLS.Flags[pTls],1
	else
	   mov ecx,Tls
	   btr dword ptr TLS.Flags[ecx],1
	endif
endm

%TLS_IS_STRACE macro pTls
	ifdef pTls
	   bt dword ptr TLS.Flags[pTls],1
	else
	   mov ecx,Tls
	   bt dword ptr TLS.Flags[ecx],1
	endif
endm

%TLS_STOP_TRACE_END_STRACE macro pTls
	ifdef pTls
	   and dword ptr TLS.Flags[pTls],NOT(TRACE_ACTIVE_FLAG or STRACE_PROCESSING_FLAG)
	else
	   mov ecx,Tls
	   and dword ptr TLS.Flags[ecx],NOT(TRACE_ACTIVE_FLAG or STRACE_PROCESSING_FLAG)
	endif
endm

%TLS_AFD_OPEN macro pTls
	ifdef pTls
	   bts dword ptr TLS.Flags[pTls],2
	else
	   mov ecx,Tls
	   bts dword ptr TLS.Flags[ecx],2
	endif
endm

%TLS_IS_AFD_OPEN macro pTls
	ifdef pTls
	   bt dword ptr TLS.Flags[pTls],2
	else
	   mov ecx,Tls
	   bt dword ptr TLS.Flags[ecx],2
	endif
endm