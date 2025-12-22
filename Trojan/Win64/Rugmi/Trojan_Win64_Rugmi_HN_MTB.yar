
rule Trojan_Win64_Rugmi_HN_MTB{
	meta:
		description = "Trojan:Win64/Rugmi.HN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 40 48 8b 40 10 48 63 40 3c 48 8b 4c 24 40 48 03 41 10 48 89 44 24 28 48 8b 44 24 28 0f b7 40 18 25 00 02 00 00 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}