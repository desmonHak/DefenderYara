
rule Trojan_Win32_Neoreblamy_NQE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 24 58 6b c0 05 8d 84 05 ?? ?? ff ff 6a 04 } //1
		$a_01_1 = {8b 45 fc 40 89 45 fc 83 7d fc 01 7d 0d 8b 45 fc } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}