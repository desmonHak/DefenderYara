
rule Trojan_Win32_Neoreblamy_NKD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 f4 40 89 45 f4 83 7d f4 01 7d 10 8b 45 f4 } //1
		$a_03_1 = {6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 48 6a 04 59 d1 e1 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}