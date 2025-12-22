
rule TrojanDownloader_BAT_PureLogs_PTM_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureLogs.PTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 02 00 00 0a 0b 07 72 ad 00 00 70 6f 03 00 00 0a 0a dd 0d 00 00 00 07 39 06 00 00 00 07 } //4
		$a_03_1 = {00 0a 13 04 08 09 11 04 6f ?? 00 00 0a 13 05 03 73 09 00 00 0a 13 06 11 06 11 05 16 73 0a 00 00 0a 13 07 73 0b 00 00 0a 13 08 11 07 11 08 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 0a 1f 64 0b dd 0f 00 00 00 11 08 39 07 00 00 00 11 08 6f ?? 00 00 0a dc } //3
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*3) >=7
 
}