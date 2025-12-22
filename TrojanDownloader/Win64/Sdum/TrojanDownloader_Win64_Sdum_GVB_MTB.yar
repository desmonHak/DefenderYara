
rule TrojanDownloader_Win64_Sdum_GVB_MTB{
	meta:
		description = "TrojanDownloader:Win64/Sdum.GVB!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 powershell.exe -Command
		$a_01_1 = {41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 } //1 Add-MpPreference -ExclusionPath
		$a_01_2 = {3a 00 2f 00 2f 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 74 00 65 00 63 00 68 00 2e 00 70 00 72 00 6f 00 } //5 ://softwaretech.pro
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=7
 
}