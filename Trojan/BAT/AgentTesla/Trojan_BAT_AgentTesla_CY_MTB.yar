
rule Trojan_BAT_AgentTesla_CY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e fe 02 00 04 20 6a 59 81 05 20 06 00 00 00 63 20 05 00 00 00 62 20 a0 ac c0 02 61 7d df 02 00 04 20 2c 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}