@echo off
\masm32\bin\ml /c /coff ldr123.asm
\masm32\bin\Link /SUBSYSTEM:WINDOWS /DLL /DEF:ldr123.def ldr123.obj
dir ldr123.*
pause
