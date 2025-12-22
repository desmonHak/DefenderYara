
rule Trojan_Win32_Neoreblamy_NQJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 9c 40 89 45 9c 83 7d 9c 03 7d 10 8b 45 9c } //1
		$a_03_1 = {6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 03 45 e0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}