
rule Trojan_Win32_Neoreblamy_NKR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 40 89 45 f8 83 7d f8 03 7d 10 8b 45 f8 } //1
		$a_01_1 = {6a 04 58 6b c0 00 8b 44 05 cc 48 6a 04 59 6b c9 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}