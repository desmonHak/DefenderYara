
rule Trojan_BAT_Lokibot_SL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 11 11 11 16 09 11 06 9a a2 11 11 28 02 00 00 06 74 02 00 00 1b 13 07 12 00 06 8e 69 11 07 8e 69 58 28 01 00 00 2b 11 07 16 06 06 8e 69 11 07 8e 69 59 11 07 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}