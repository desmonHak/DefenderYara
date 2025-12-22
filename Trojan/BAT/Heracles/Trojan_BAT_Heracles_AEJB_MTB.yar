
rule Trojan_BAT_Heracles_AEJB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AEJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 04 11 06 91 61 d2 81 ?? 00 00 01 11 06 17 58 13 06 11 06 11 04 8e 69 32 d8 } //5
		$a_03_1 = {06 13 07 11 07 8e 69 1a 5d 13 08 11 07 8e 69 1a 5b 13 09 11 07 8e 69 8d ?? 00 00 01 13 0a 08 8e 69 1a 5b } //2
		$a_01_2 = {11 1a 16 31 0c 11 12 1e 62 13 12 11 13 1e 58 13 13 11 0a 11 0f 11 1a 58 11 19 11 12 5f 11 13 1f 1f 5f 64 d2 9c 11 1a 17 58 13 1a } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}