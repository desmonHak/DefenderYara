
rule Trojan_BAT_AgentTesla_PG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 f9 f1 d1 23 59 1a 63 2a 20 b3 78 49 e0 66 65 20 4f e8 d8 fa 59 66 20 69 90 70 e5 58 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}