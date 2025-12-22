
rule TrojanDownloader_BAT_Heracles_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 10 11 10 72 8b 01 00 70 6f ?? 00 00 0a 26 de 0c 11 10 2c 07 11 10 6f ?? 00 00 0a dc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}