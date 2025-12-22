
rule TrojanDownloader_Win32_Rugmi_PAGW_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.PAGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 14 18 8d 7c 24 18 34 cc 83 c9 ff 88 44 14 18 33 c0 42 f2 ae f7 d1 49 3b d1 72 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}