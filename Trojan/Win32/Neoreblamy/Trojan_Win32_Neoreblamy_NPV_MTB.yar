
rule Trojan_Win32_Neoreblamy_NPV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7c a9 8b 75 e8 8b 45 08 46 89 75 e8 81 fe } //1
		$a_03_1 = {8b fb 8b c6 8d 8d ?? ?? ff ff 33 c7 99 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}