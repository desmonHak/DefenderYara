
rule Trojan_Win32_Neoreblamy_NIW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 40 89 45 dc 83 7d dc 03 7d 16 ff 75 dc } //1
		$a_03_1 = {8b 00 40 8b 8d ?? ?? ff ff 89 01 6a 02 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}