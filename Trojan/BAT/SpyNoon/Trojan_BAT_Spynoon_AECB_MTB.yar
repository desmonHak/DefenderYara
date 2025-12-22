
rule Trojan_BAT_Spynoon_AECB_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AECB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 06 6f ?? 00 00 0a 13 0f 04 03 6f ?? 00 00 0a 59 0c 03 12 0f 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 59 25 0c 16 fe 02 16 fe 01 13 0d 11 0d 2c 02 2b 41 03 12 0f 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 59 25 0c 16 fe 02 16 fe 01 13 0e 11 0e 2c 02 2b 21 03 12 0f 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 58 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}