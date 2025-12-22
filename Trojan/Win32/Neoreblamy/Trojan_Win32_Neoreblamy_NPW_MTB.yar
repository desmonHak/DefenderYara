
rule Trojan_Win32_Neoreblamy_NPW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 49 89 8d 74 fe ff ff 85 c0 75 08 } //1
		$a_01_1 = {8b 45 bc 48 ff 4d b8 89 45 bc 75 a9 8b 75 e0 46 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}