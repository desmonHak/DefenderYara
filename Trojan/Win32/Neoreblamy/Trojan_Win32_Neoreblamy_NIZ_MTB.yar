
rule Trojan_Win32_Neoreblamy_NIZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e8 40 89 45 e8 83 7d e8 } //1
		$a_03_1 = {6a 02 58 d1 e0 33 c9 66 89 8c 05 ?? ?? ff ff 83 4d fc 01 ff 75 10 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}