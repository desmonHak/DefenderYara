
rule Trojan_Win64_Vidar_ASVD_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ASVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f b7 40 24 48 8b 85 10 07 00 00 48 8b 50 18 48 8b 0d 48 a1 12 00 48 83 ec 40 45 31 ff 4c 89 7c 24 38 4c 89 7c 24 20 c7 44 24 30 00 00 00 00 c7 44 24 28 03 00 00 00 45 31 c9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}