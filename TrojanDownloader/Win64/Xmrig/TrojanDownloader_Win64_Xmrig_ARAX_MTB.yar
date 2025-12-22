
rule TrojanDownloader_Win64_Xmrig_ARAX_MTB{
	meta:
		description = "TrojanDownloader:Win64/Xmrig.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 44 24 50 48 03 c2 0f b6 0c 07 30 4c 15 90 48 ff c2 30 08 48 3b d3 72 e6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}