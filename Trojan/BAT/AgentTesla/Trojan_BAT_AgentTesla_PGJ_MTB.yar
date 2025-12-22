
rule Trojan_BAT_AgentTesla_PGJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0f 16 5f 13 13 11 13 19 5d 13 14 17 11 13 58 19 5d 13 15 18 11 13 58 19 5d 13 16 19 8d 34 00 00 01 13 17 11 17 16 12 10 28 ?? ?? ?? ?? 9c 11 17 17 12 10 28 ?? ?? ?? ?? 9c 11 17 18 12 10 28 ?? ?? ?? ?? 9c 11 12 16 fe 02 13 1a 11 1a 2c 12 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}