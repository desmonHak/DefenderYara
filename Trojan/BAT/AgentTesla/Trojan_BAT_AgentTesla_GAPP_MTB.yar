
rule Trojan_BAT_AgentTesla_GAPP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 0a 95 61 9e 38 ?? ?? 00 00 11 07 11 05 25 17 58 13 05 11 0b 1f 10 64 d2 } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}