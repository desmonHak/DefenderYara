
rule Trojan_Win32_FileFix_GGY_MTB{
	meta:
		description = "Trojan:Win32/FileFix.GGY!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-10] 2d 00 63 00 [0-20] 70 00 69 00 6e 00 67 00 [0-3c] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-10] 20 00 23 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}