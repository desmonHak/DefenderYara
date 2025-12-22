
rule Trojan_BAT_Rozena_PGRO_MTB{
	meta:
		description = "Trojan:BAT/Rozena.PGRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 17 ?? 11 06 ?? 11 06 91 18 59 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 ?? 8e 69 32 e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}