
rule Trojan_Win32_MalPwshShadowCopyDel_AA{
	meta:
		description = "Trojan:Win32/MalPwshShadowCopyDel.AA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 63 00 } //1 powershell.exe -c
		$a_00_1 = {67 00 65 00 74 00 2d 00 63 00 69 00 6d 00 69 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 20 00 77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //1 get-ciminstance win32_shadowcopy
		$a_00_2 = {72 00 65 00 6d 00 6f 00 76 00 65 00 2d 00 63 00 69 00 6d 00 69 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //1 remove-ciminstance
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}