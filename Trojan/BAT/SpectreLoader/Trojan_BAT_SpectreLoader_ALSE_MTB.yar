
rule Trojan_BAT_SpectreLoader_ALSE_MTB{
	meta:
		description = "Trojan:BAT/SpectreLoader.ALSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 14 11 05 11 11 11 14 16 11 14 8e 69 28 ?? 00 00 0a 11 0e 11 07 11 13 6a 58 11 14 11 14 8e 69 16 6a 28 ?? 00 00 06 26 11 0f 17 58 68 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}