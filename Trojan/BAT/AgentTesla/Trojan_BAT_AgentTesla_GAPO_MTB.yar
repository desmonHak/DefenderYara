
rule Trojan_BAT_AgentTesla_GAPO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 07 06 1f ?? 58 4a 91 54 06 4a 61 06 1f ?? 58 4a 61 54 08 06 1f ?? 58 4a 06 1f ?? 58 4a d2 9c 06 1f ?? 58 4a 06 1a 58 4a 17 59 33 } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}