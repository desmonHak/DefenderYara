
rule Trojan_BAT_Agenttesla_PALA_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.PALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 1b 03 04 6f ?? 00 00 0a 0b [0-0f] 13 06 38 ?? ff ff ff 06 17 58 0a 20 ?? ?? 00 00 0d [0-05] 13 04 20 ?? ?? 00 00 09 18 5b 11 04 59 32 [0-0f] 00 00 59 13 06 38 ?? ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}