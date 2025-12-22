
rule Trojan_Win32_Neoreblamy_NIY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 40 89 45 f0 83 7d f0 03 7d 10 8b 45 f0 } //1
		$a_03_1 = {6a 04 58 6b c0 00 83 bc 05 ?? ?? ff ff 03 7c 0c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}