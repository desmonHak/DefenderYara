
rule TrojanDownloader_Win64_SalatStealer_CD_MTB{
	meta:
		description = "TrojanDownloader:Win64/SalatStealer.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8d 8c 24 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 bc 24 ?? ?? ?? ?? 5a 72 } //2
		$a_03_1 = {48 2b c6 48 35 ?? ?? ?? ?? 0f b6 44 04 ?? 41 88 03 49 ff c3 4c 3b db 75 } //2
		$a_01_2 = {43 65 6c 65 73 74 69 61 6c 44 6f 77 6e 6c 6f 61 64 65 72 } //1 CelestialDownloader
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}