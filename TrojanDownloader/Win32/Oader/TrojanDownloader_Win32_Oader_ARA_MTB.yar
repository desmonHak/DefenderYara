
rule TrojanDownloader_Win32_Oader_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Oader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 c3 7e 14 89 c2 83 e2 1f 8a 14 11 32 14 06 41 88 14 00 48 ff c0 eb e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}