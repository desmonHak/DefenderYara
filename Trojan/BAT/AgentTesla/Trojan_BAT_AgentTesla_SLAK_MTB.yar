
rule Trojan_BAT_AgentTesla_SLAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SLAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 9f 03 00 06 11 08 8d 1d 00 00 01 13 0a 7e ?? 02 00 04 02 1a 58 11 0a 16 11 08 28 1d 01 00 0a 28 e3 00 00 0a 11 0a 16 11 0a 8e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}