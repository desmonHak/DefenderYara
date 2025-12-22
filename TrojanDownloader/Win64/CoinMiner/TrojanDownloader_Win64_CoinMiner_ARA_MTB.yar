
rule TrojanDownloader_Win64_CoinMiner_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/CoinMiner.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 09 83 e1 0f 4a 0f be 84 31 a8 a7 01 00 42 8a 8c 31 b8 a7 01 00 4c 2b c8 41 8b 41 fc d3 e8 03 f8 8b c7 49 03 c2 48 03 c6 48 3b d8 72 2b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}