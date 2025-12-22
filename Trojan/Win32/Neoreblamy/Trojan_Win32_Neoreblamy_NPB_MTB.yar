
rule Trojan_Win32_Neoreblamy_NPB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 40 } //1
		$a_01_1 = {8b 45 90 40 89 45 90 83 7d 90 01 7d 0d 8b 45 90 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}