
rule Trojan_BAT_Agenttesla_PGAR_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.PGAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0b 11 0d 6f ?? 00 00 0a 13 0e 04 03 6f ?? 00 00 0a 59 13 0f 11 0f 13 10 11 10 19 fe 02 13 16 11 16 2c 03 19 13 10 11 10 16 fe 04 13 17 11 17 2c 03 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}