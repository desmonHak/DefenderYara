
rule Trojan_BAT_Crysan_ANS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ANS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 5b 17 da 17 d6 8d ?? 00 00 01 0c 07 16 8c ?? 00 00 01 08 17 28 ?? 00 00 0a 18 da 8c ?? 00 00 01 17 8c ?? 00 00 01 12 03 12 01 28 ?? 00 00 0a 13 04 11 04 2c 4a 08 07 28 ?? 00 00 0a 72 ?? f8 03 70 02 18 8c ?? 00 00 01 07 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}