
rule Trojan_Win32_Neoreblamy_NQS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 3e 83 65 f8 00 eb 07 8b 45 f8 40 89 45 f8 } //1
		$a_03_1 = {6a 1c 58 d1 e0 8d 84 05 ?? ?? ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}