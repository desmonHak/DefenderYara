
rule Trojan_Win32_Neoreblamy_NKO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 40 89 45 dc 83 7d dc 01 7d 0d 8b 45 dc } //1
		$a_03_1 = {75 0f 83 7d e8 00 75 09 83 a5 ?? ?? ff ff 00 eb 0a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}