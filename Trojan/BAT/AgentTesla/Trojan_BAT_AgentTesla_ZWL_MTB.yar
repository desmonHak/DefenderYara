
rule Trojan_BAT_AgentTesla_ZWL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ZWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 10 11 11 6f ?? 00 00 0a 13 20 12 20 28 ?? 00 00 0a 03 06 6f ?? 00 00 0a 59 13 1a 28 ?? 00 00 0a 13 1b 18 13 1c 17 13 1d 16 13 1e 11 07 11 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}