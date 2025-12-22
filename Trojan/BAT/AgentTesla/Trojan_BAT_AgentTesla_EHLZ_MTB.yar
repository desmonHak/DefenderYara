
rule Trojan_BAT_AgentTesla_EHLZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EHLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 11 07 1b 63 61 61 13 07 16 13 2c ?? ?? ?? ?? ?? 00 11 07 11 2c 1f 53 5a 61 13 2d 00 02 11 2b 11 2c ?? ?? ?? ?? ?? 13 2e 04 03 ?? ?? ?? ?? ?? 59 13 2f 11 2f 13 30 11 30 19 fe 02 13 36 11 36 2c 03 19 13 30 11 30 16 fe 04 13 37 11 37 2c 03 16 13 30 11 07 16 5f 13 31 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}