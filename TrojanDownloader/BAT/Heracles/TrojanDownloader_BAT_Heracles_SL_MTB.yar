
rule TrojanDownloader_BAT_Heracles_SL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 07 2b 0c 18 2c f9 de 0d 28 0b 00 00 06 2b f2 0a 2b f1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}