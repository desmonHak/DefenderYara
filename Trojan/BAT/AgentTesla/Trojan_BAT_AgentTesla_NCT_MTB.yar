
rule Trojan_BAT_AgentTesla_NCT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 03 08 6f ?? 00 00 0a 59 13 06 08 17 8d ?? 00 00 01 25 16 12 05 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 06 17 59 25 13 06 16 fe 02 16 fe 01 13 0e 11 0e 2c 05 38 39 01 00 00 08 17 8d ?? 00 00 01 25 16 12 05 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 06 17 59 25 13 06 16 fe 02 16 fe 01 13 0f 11 0f 2c 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}