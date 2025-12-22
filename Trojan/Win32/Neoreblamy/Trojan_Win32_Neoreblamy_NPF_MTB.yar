
rule Trojan_Win32_Neoreblamy_NPF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 48 } //1
		$a_01_1 = {8b 45 d4 40 89 45 d4 83 7d d4 03 7d 10 8b 45 d4 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}