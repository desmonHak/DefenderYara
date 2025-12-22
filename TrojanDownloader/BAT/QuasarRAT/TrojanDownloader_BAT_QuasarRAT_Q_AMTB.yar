
rule TrojanDownloader_BAT_QuasarRAT_Q_AMTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.Q!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 [0-01] 3a 2f 2f 34 35 2e 34 33 2e 31 34 33 2e 32 31 32 2f } //7
		$a_03_1 = {68 74 74 70 [0-01] 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 33 77 36 70 33 39 65 6d } //7
		$a_01_2 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 24 } //2 Add-MpPreference -ExclusionPath $
		$a_03_3 = {5b 53 79 73 74 65 6d 2e 49 4f 2e 50 61 74 68 5d 3a 3a 43 6f 6d 62 69 6e 65 28 24 65 6e 76 3a 41 50 50 44 41 54 41 2c 20 27 [0-1a] 27 2c 20 27 [0-14] 2e 65 78 65 27 29 } //1
		$a_01_4 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 } //1 Invoke-WebRequest
		$a_01_5 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 24 6f 75 74 70 75 74 46 69 6c 65 } //1 Start-Process -FilePath $outputFile
	condition:
		((#a_03_0  & 1)*7+(#a_03_1  & 1)*7+(#a_01_2  & 1)*2+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}