
rule TrojanDownloader_BAT_Heracles_SK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 1a 00 00 06 7e 04 00 00 04 7e 05 00 00 04 28 0d 00 00 06 28 10 00 00 06 72 01 00 00 70 72 51 00 00 70 28 13 00 00 06 38 00 00 00 00 dd 10 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}