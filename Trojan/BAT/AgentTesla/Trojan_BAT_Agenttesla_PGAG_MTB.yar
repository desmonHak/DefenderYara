
rule Trojan_BAT_Agenttesla_PGAG_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.PGAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8c 07 00 00 1b 03 04 05 6f ?? ?? 00 0a 06 17 58 0a 0e 05 25 5a 0e 05 58 18 5d 2c 0e 11 04 20 76 01 00 00 91 0c 38 67 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}