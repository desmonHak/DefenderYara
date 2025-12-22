
rule Trojan_Win32_Neoreblamy_NPU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 40 89 45 e8 83 7d e8 03 7d 10 8b 45 e8 } //1
		$a_03_1 = {6a 28 58 c1 e0 00 8d 84 05 ?? ?? ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}