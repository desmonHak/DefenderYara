
rule Trojan_BAT_AgentTesla_NCX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 03 16 03 8e 69 6f 18 00 00 0a 11 05 6f 19 00 00 0a 11 04 6f 1a 00 00 0a 13 06 11 06 8e 69 28 a9 00 00 06 0c 11 06 16 08 16 11 06 8e 69 28 1b 00 00 0a 08 13 07 dd 2b 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}