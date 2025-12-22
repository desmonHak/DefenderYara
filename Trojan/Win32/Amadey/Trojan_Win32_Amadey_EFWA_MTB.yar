
rule Trojan_Win32_Amadey_EFWA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.EFWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 05 03 45 e8 33 c8 8b 55 f8 2b d1 89 55 f8 } //2
		$a_01_1 = {03 45 f8 8b 4d e4 03 4d f8 8a 11 88 10 83 7d f8 0a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}