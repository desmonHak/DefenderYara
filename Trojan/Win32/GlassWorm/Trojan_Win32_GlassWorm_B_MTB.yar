
rule Trojan_Win32_GlassWorm_B_MTB{
	meta:
		description = "Trojan:Win32/GlassWorm.B!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {65 00 76 00 61 00 6c 00 28 00 61 00 74 00 6f 00 62 00 28 00 } //1 eval(atob(
		$a_00_1 = {6e 6f 64 65 2e 65 78 65 } //1 node.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}