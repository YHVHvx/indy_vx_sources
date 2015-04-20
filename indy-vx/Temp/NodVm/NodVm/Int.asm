100174C5 <Int_0x2A>           |> \8B8424 60030000                 mov eax,dword ptr ss:[esp+360]              ;  ; KiGetTickCount; Case 2A of switch 10017159
100174CC                      |.  5F                              pop edi
100174CD                      |.  5E                              pop esi
100174CE                      |.  5D                              pop ebp
100174CF                      |.  A3 205B1510                     mov dword ptr ds:[<rEip>],eax
100174D4                      |.  C705 005B1510 BEE98100          mov dword ptr ds:[<rEax>],81E9BE
100174DE                      |.  C705 085B1510 E9810000          mov dword ptr ds:[<rEdx>],81E9
100174E8                      |.  33C0                            xor eax,eax
100174EA                      |.  5B                              pop ebx
100174EB                      |.  81C4 44030000                   add esp,344
100174F1                      |.  C3                              ret
100174F2 <Int_0x2B>           |>  8B8424 60030000                 mov eax,dword ptr ss:[esp+360]              ;  ; KiCallbackReturn; Case 2B of switch 10017159
100174F9                      |.  5F                              pop edi
100174FA                      |.  5E                              pop esi
100174FB                      |.  892D 045B1510                   mov dword ptr ds:[<rEcx>],ebp
10017501                      |.  5D                              pop ebp
10017502                      |.  A3 205B1510                     mov dword ptr ds:[<rEip>],eax
10017507                      |.  C705 005B1510 580200C0          mov dword ptr ds:[<rEax>],C0000258          ;  ; STATUS_NO_CALLBACK_ACTIVE
10017511                      |.  33C0                            xor eax,eax
10017513                      |.  5B                              pop ebx
10017514                      |.  81C4 44030000                   add esp,344
1001751A                      |.  C3                              ret
1001751B <Int_0x2C>           |>  8B8424 60030000                 mov eax,dword ptr ss:[esp+360]              ;  ; KiRaiseAssertion; Case 2C of switch 10017159
10017522                      |.  5F                              pop edi
10017523                      |.  5E                              pop esi
10017524                      |.  5D                              pop ebp
10017525                      |.  A3 205B1510                     mov dword ptr ds:[<rEip>],eax
1001752A                      |.  C705 005B1510 4E0100C0          mov dword ptr ds:[<rEax>],C000014E          ;  ;  STATUS_NO_EVENT_PAIR
10017534                      |.  C705 045B1510 01010100          mov dword ptr ds:[<rEcx>],10101
1001753E                      |.  C705 085B1510 FFFFFFFF          mov dword ptr ds:[<rEdx>],-1
10017548                      |.  33C0                            xor eax,eax
1001754A                      |.  5B                              pop ebx
1001754B                      |.  81C4 44030000                   add esp,344
10017551                      |.  C3                              ret
10017552 <Int_0x2D>           |>  A1 005B1510                     mov eax,dword ptr ds:[<rEax>]               ;  ; KiDebugService; Case 2D of switch 10017159
10017557                      |.  3BC6                            cmp eax,esi
10017559                      |.  74 13                           je short em004_32.1001756E
1001755B                      |.  83F8 03                         cmp eax,3
1001755E                      |.  74 0E                           je short em004_32.1001756E
10017560                      |.  83F8 04                         cmp eax,4
10017563                      |.  74 09                           je short em004_32.1001756E
10017565                      |.  83F8 05                         cmp eax,5
10017568                      |.  0F85 29010000                   jnz em004_32.10017697
1001756E                      |>  01B424 60030000                 add dword ptr ss:[esp+360],esi
10017575                      |.  8B8424 60030000                 mov eax,dword ptr ss:[esp+360]
1001757C                      |.  5F                              pop edi
1001757D                      |.  5E                              pop esi
1001757E                      |.  5D                              pop ebp
1001757F                      |.  A3 205B1510                     mov dword ptr ds:[<rEip>],eax
10017584                      |.  33C0                            xor eax,eax
10017586                      |.  5B                              pop ebx
10017587                      |.  81C4 44030000                   add esp,344
1001758D                      |.  C3                              ret
1001758E <Int_0x2E>           |>  A1 145B1510                     mov eax,dword ptr ds:[<rEbp>]               ;  ; KiSystemService; Case 2E of switch 10017159
10017593                      |.  894424 68                       mov dword ptr ss:[esp+68],eax
10017597                      |.  25 0000FCFF                     and eax,FFFC0000
1001759C                      |.  3D 000050CD                     cmp eax,CD500000
100175A1                      |.  0F84 AA000000                   je em004_32.10017651
100175A7                      |.  A1 005B1510                     mov eax,dword ptr ds:[<rEax>]
100175AC                      |.  25 FF0F0000                     and eax,0FFF
100175B1                      |.  3D 30010000                     cmp eax,130                                 ;  Switch (cases 0..12F)
100175B6                      |.  73 6E                           jnb short em004_32.10017626                 ;  ; Id > 0x130
100175B8                      |.  83C0 F7                         add eax,-9
100175BB                      |.  3D FC000000                     cmp eax,0FC
100175C0                      |.  77 39                           ja short em004_32.100175FB
100175C2                      |.  0FB680 287A0110                 movzx eax,byte ptr ds:[eax+10017A28]
100175C9                      |.  FF2485 207A0110                 jmp dword ptr ds:[eax*4+<ServiceTable>]
100175D0                      |>  8B8C24 60030000                 mov ecx,dword ptr ss:[esp+360]              ;  Cases 9,15,3D,46,48,6D,8C,8D,AC,D3,D4,EF,105 of switch 100175B1
100175D7                      |.  5F                              pop edi
100175D8                      |.  5E                              pop esi
100175D9                      |.  8BC1                            mov eax,ecx
100175DB                      |.  5D                              pop ebp
100175DC                      |.  A3 205B1510                     mov dword ptr ds:[<rEip>],eax
100175E1                      |.  C705 005B1510 020000C0          mov dword ptr ds:[<rEax>],C0000002
100175EB                      |.  890D 085B1510                   mov dword ptr ds:[<rEdx>],ecx
100175F1                      |.  33C0                            xor eax,eax
100175F3                      |.  5B                              pop ebx
100175F4                      |.  81C4 44030000                   add esp,344
100175FA                      |.  C3                              ret
100175FB                      |>  8B8C24 60030000                 mov ecx,dword ptr ss:[esp+360]              ;  ; Id > 0xFC; Cases 0,1,2,3,4,5,6,7,8,A,B,C,D,E,F,10,11,12,13,14,16,17,18,19,1A,1B,1C,1D,1E,1F,20,21,22,23,24,25,26,27,28,29,2A,2B,2C,2D,2E,2F,30,31,32,33,34,35,36,37,38,39,3A,3B,3C,3E,3F,40,41... of switch 100175B1
10017602                      |.  5F                              pop edi
10017603                      |.  5E                              pop esi
10017604                      |.  8BC1                            mov eax,ecx
10017606                      |.  5D                              pop ebp
10017607                      |.  A3 205B1510                     mov dword ptr ds:[<rEip>],eax
1001760C                      |.  C705 005B1510 050000C0          mov dword ptr ds:[<rEax>],C0000005
10017616                      |.  890D 085B1510                   mov dword ptr ds:[<rEdx>],ecx
1001761C                      |.  33C0                            xor eax,eax
1001761E                      |.  5B                              pop ebx
1001761F                      |.  81C4 44030000                   add esp,344
10017625                      |.  C3                              ret
10017626                      |>  8B8C24 60030000                 mov ecx,dword ptr ss:[esp+360]              ;  Default case of switch 100175B1
1001762D                      |.  5F                              pop edi
1001762E                      |.  5E                              pop esi
1001762F                      |.  8BC1                            mov eax,ecx
10017631                      |.  5D                              pop ebp
10017632                      |.  A3 205B1510                     mov dword ptr ds:[<rEip>],eax
10017637                      |.  C705 005B1510 1C0000C0          mov dword ptr ds:[<rEax>],C000001C          ;  ; STATUS_INVALID_SYSTEM_SERVICE
10017641                      |.  890D 085B1510                   mov dword ptr ds:[<rEdx>],ecx
10017647                      |.  33C0                            xor eax,eax
10017649                      |.  5B                              pop ebx
1001764A                      |.  81C4 44030000                   add esp,344
10017650                      |.  C3                              ret
10017651                      |>  8B15 105B1510                   mov edx,dword ptr ds:[<rEsp>]
10017657                      |.  6A 04                           push 4
10017659                      |.  52                              push edx
1001765A                      |.  8D4424 6C                       lea eax,dword ptr ss:[esp+6C]
1001765E                      |.  50                              push eax
1001765F                      |.  E8 BCA80000                     call em004_32.10021F20
10017664                      |.  8B4C24 70                       mov ecx,dword ptr ss:[esp+70]
10017668                      |.  8305 105B1510 04                add dword ptr ds:[<rEsp>],4
1001766F                      |.  8D5424 74                       lea edx,dword ptr ss:[esp+74]
10017673                      |.  52                              push edx
10017674                      |.  890D 145B1510                   mov dword ptr ds:[<rEbp>],ecx
1001767A                      |.  E8 71C7FFFF                     call em004_32.10013DF0
1001767F                      |.  83C4 10                         add esp,10
10017682                      |.  5F                              pop edi
10017683                      |.  5E                              pop esi
10017684                      |.  5D                              pop ebp
10017685                      |.  5B                              pop ebx
10017686                      |.  81C4 44030000                   add esp,344
1001768C                      |.  C3                              ret
1001768D                      |>  C705 005B1510 1C0000C0          mov dword ptr ds:[<rEax>],C000001C          ;  ; STATUS_INVALID_SYSTEM_SERVICE; Case 41 of switch 10017159
10017697                      |>  8B8424 60030000                 mov eax,dword ptr ss:[esp+360]              ;  Case 68 of switch 10017159
1001769E                      |.  5F                              pop edi
1001769F                      |.  5E                              pop esi
100176A0                      |.  5D                              pop ebp
100176A1                      |.  A3 205B1510                     mov dword ptr ds:[<rEip>],eax
100176A6                      |.  33C0                            xor eax,eax
100176A8                      |.  5B                              pop ebx
100176A9                      |.  81C4 44030000                   add esp,344
100176AF                      |.  C3                              ret