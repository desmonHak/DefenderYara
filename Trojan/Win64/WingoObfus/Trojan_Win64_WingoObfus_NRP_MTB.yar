
rule Trojan_Win64_WingoObfus_NRP_MTB{
	meta:
		description = "Trojan:Win64/WingoObfus.NRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 3d 8e d5 f7 00 04 75 29 81 3a 69 63 6d 70 75 21 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}