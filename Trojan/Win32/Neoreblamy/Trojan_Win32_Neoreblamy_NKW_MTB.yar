
rule Trojan_Win32_Neoreblamy_NKW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 6b c0 00 8b 4d 84 89 8c 05 ?? ff ff ff 8b } //1
		$a_01_1 = {eb 07 8b 45 d4 40 89 45 d4 83 7d d4 04 7d 10 8b 45 d4 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}