
rule Trojan_BAT_PureLogs_SE_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {02 7b 26 00 00 04 06 07 03 6f 4d 00 00 0a 0c 08 2c 0f 07 08 58 0b 03 08 59 fe 0b 01 00 03 16 30 df } //2
		$a_81_1 = {61 63 72 2d 47 45 54 57 45 4c 4c 2d 78 71 74 68 75 66 79 65 2e 62 30 73 5f } //2 acr-GETWELL-xqthufye.b0s_
	condition:
		((#a_00_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}