
rule Trojan_BAT_PureLogs_SD_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 09 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f 0a 00 00 0a 38 00 00 00 00 11 06 6f 0b 00 00 0a 13 07 38 00 00 00 00 dd 72 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}