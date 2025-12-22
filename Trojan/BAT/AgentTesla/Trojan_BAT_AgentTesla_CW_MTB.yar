
rule Trojan_BAT_AgentTesla_CW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 7d 7a 00 00 04 02 7b 79 00 00 04 7b 10 00 00 04 02 7b 7a 00 00 04 16 02 7b 7a 00 00 04 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}