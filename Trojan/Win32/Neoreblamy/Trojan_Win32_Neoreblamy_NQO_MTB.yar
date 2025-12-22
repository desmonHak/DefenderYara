
rule Trojan_Win32_Neoreblamy_NQO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 cc 40 89 45 cc 83 7d cc 03 7d 10 8b 45 cc } //1
		$a_03_1 = {6a 18 58 6b c0 00 8d 84 05 ?? ?? ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}