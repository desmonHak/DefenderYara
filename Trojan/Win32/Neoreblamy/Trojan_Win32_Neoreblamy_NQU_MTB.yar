
rule Trojan_Win32_Neoreblamy_NQU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 65 b0 00 eb 07 8b 45 b0 40 89 45 b0 } //1
		$a_03_1 = {58 c1 e0 03 8d 84 05 ?? ?? ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}