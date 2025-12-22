
rule Trojan_Win32_Neoreblamy_NKX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7c 0e 83 c8 ff 75 09 83 a5 ?? ?? ff ff 00 eb 0a } //1
		$a_01_1 = {8b 45 8c 40 89 45 8c 83 7d 8c 01 7d 0d 8b 45 8c } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}