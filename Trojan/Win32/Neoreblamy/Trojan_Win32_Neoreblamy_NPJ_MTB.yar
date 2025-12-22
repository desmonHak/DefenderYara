
rule Trojan_Win32_Neoreblamy_NPJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 1c 58 6b c0 03 8d 84 05 ?? ?? ff ff 6a 04 } //1
		$a_01_1 = {8b 45 f0 40 89 45 f0 83 7d f0 04 7d 10 8b 45 f0 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}