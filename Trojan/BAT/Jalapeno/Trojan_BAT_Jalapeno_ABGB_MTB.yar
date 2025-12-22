
rule Trojan_BAT_Jalapeno_ABGB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ABGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 08 8e b7 17 da 11 05 da 02 11 05 91 06 61 8c ?? 00 00 01 07 17 8d ?? 00 00 01 13 08 11 08 16 11 04 8c ?? 00 00 01 a2 11 08 14 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 9c 11 05 17 d6 13 05 11 05 11 07 31 b9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}