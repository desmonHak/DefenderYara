
rule Trojan_BAT_Stealerium_SI_MTB{
	meta:
		description = "Trojan:BAT/Stealerium.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {02 11 0b 11 0c 6f 2d 00 00 0a 13 23 12 23 28 2e 00 00 0a 13 1d 19 8d 3a 00 00 01 25 16 1f 10 9e 25 17 1e 9e 13 1e 03 07 6f 2c 00 00 0a 59 13 1f 16 13 24 2b 27 } //1
		$a_00_1 = {11 08 17 11 1b 17 5f 58 17 11 1b 17 58 17 5f 58 73 23 00 00 0a 6f 24 00 00 0a 00 11 1b 17 58 13 1b 11 1b 11 09 fe 04 13 1c 11 1c 2d d3 } //1
		$a_81_2 = {4e 69 6d 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 NimGame.Properties.Resources.resources
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}