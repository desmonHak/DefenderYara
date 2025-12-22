
rule Trojan_Win32_ClickFix_HIJ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HIJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {7c 00 20 00 63 00 6d 00 64 00 20 00 26 00 26 00 20 00 65 00 78 00 69 00 74 00 } //1 | cmd && exit
		$a_02_1 = {63 00 75 00 72 00 6c 00 20 00 2d 00 73 00 20 00 68 00 74 00 74 00 70 00 [0-02] 3a 00 2f 00 2f 00 [0-ff] 3a 00 } //1
		$a_00_2 = {2f 00 6d 00 69 00 6e 00 20 00 63 00 6d 00 64 00 20 00 2f 00 6b 00 } //1 /min cmd /k
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}