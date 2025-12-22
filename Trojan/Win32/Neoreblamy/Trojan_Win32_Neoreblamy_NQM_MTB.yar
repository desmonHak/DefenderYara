
rule Trojan_Win32_Neoreblamy_NQM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 c0 40 89 45 c0 83 7d c0 01 7d 0d 8b 45 c0 } //1
		$a_03_1 = {40 6b c0 1c 8d 84 05 ?? ?? ff ff 8b 4d f4 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}