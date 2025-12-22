
rule TrojanDownloader_BAT_Zilla_AR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Zilla.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0b 16 14 16 13 1a 12 1a 16 16 13 1b 12 1b 16 6f } //12
		$a_01_1 = {16 fe 01 13 36 11 36 2c 19 11 34 11 0c 28 1c 01 00 06 } //8
	condition:
		((#a_01_0  & 1)*12+(#a_01_1  & 1)*8) >=20
 
}