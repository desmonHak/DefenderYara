
rule Trojan_Win32_MalWmicShadowCopyDel_AB{
	meta:
		description = "Trojan:Win32/MalWmicShadowCopyDel.AB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 6d 00 69 00 63 00 } //1 wmic
		$a_00_1 = {73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //1 shadowcopy
		$a_00_2 = {64 00 65 00 6c 00 65 00 74 00 65 00 } //1 delete
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}