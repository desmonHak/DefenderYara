
rule Trojan_BAT_AgentTesla_ZDO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ZDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 14 72 43 00 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 9c 08 09 19 d8 02 14 72 2d 00 00 70 18 8d ?? 00 00 01 13 09 11 09 16 11 05 8c ?? 00 00 01 a2 11 09 17 11 04 8c ?? 00 00 01 a2 11 09 13 08 11 08 14 14 18 } //6
		$a_03_1 = {02 03 61 04 61 8c ?? 00 00 01 2a } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}