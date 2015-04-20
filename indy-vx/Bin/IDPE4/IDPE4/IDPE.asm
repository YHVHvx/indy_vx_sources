	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.code
MIENTRY:
	test eax,eax
	jz IdpAddReference
	dec eax
	jz IdpAddVEH
	dec eax
	jz IdpRemoveVEH
	dec eax
	jz IdpGetReference
	dec eax
	jz LdrImageQueryEntryFromHash
	dec eax
	jz LdrEncodeEntriesListEx
	mov eax,STATUS_INVALID_PARAMETER
	ret
	
	include Hdr.inc
	include Img.asm
	include Env.asm
	include Tls.asm
	include Idp.asm
	include Trap.asm

end MIENTRY