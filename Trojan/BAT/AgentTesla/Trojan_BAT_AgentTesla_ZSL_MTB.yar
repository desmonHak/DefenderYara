
rule Trojan_BAT_AgentTesla_ZSL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ZSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0a 11 0b 6f ?? 00 00 0a 13 1c 12 1c 28 ?? 00 00 0a 20 ff 00 00 00 13 11 04 6f ?? 00 00 0a 09 58 17 5f 2c 04 1f 10 2b 02 1f 10 13 12 05 11 04 61 18 5f 2c 03 1e 2b 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}