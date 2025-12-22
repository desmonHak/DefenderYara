
rule TrojanDownloader_Win64_Androm_ARAX_MTB{
	meta:
		description = "TrojanDownloader:Win64/Androm.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 8d 05 ?? 8b 00 00 48 89 c1 e8 7c 11 00 00 48 8d 05 ?? 8b 00 00 48 89 c1 e8 a5 6e 00 00 8b 85 6c 86 01 00 48 63 c8 48 8d 55 a0 48 8b 85 ?? 86 01 00 49 89 c8 48 89 c1 e8 6e 6e 00 00 48 8d 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}