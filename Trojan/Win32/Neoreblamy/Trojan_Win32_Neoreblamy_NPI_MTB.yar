
rule Trojan_Win32_Neoreblamy_NPI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 84 40 89 45 84 83 7d 84 03 7d 10 8b 45 84 } //1
		$a_03_1 = {6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 40 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}