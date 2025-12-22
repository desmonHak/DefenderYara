
rule Trojan_BAT_Lokibot_ALA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0f 11 0e 74 ?? 00 00 1b 8e 69 17 58 11 0f 74 ?? 00 00 1b 8e 69 58 17 58 06 75 ?? 00 00 1b 8e 69 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}