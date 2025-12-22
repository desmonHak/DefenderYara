
rule Trojan_BAT_Crysan_ANSC_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ANSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b7 13 0e 11 0d 11 0e 61 11 05 61 13 0f 07 11 0f 28 ?? 02 00 0a 28 ?? 02 00 0a 28 ?? 00 00 0a 0b 11 0c 17 d6 13 0c 11 0c 11 0b 31 b1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}