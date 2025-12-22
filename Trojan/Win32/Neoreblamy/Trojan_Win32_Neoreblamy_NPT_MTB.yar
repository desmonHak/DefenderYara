
rule Trojan_Win32_Neoreblamy_NPT_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 40 89 45 e0 83 7d e0 04 7d 10 8b 45 e0 } //1
		$a_03_1 = {58 6b c0 03 8d 84 05 ?? ?? ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}