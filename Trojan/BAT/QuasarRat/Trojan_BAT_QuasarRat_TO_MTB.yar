
rule Trojan_BAT_QuasarRat_TO_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.TO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 33 33 2e 31 36 34 2e 31 32 33 2f [0-19] 2e 65 78 65 } //7
		$a_03_1 = {24 65 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 3d 20 22 24 65 6e 76 3a 41 50 50 44 41 54 41 5c [0-1e] 22 } //1
		$a_01_2 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 24 65 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 Add-MpPreference -ExclusionPath $exclusionPath
		$a_01_3 = {24 6f 75 74 70 75 74 46 69 6c 65 20 3d 20 5b 53 79 73 74 65 6d 2e 49 4f 2e 50 61 74 68 5d 3a 3a 43 6f 6d 62 69 6e 65 28 24 65 6e 76 3a 41 50 50 44 41 54 41 } //1 $outputFile = [System.IO.Path]::Combine($env:APPDATA
		$a_01_4 = {53 74 61 72 74 2d 53 6c 65 65 70 20 2d 4d 69 6c 6c 69 73 65 63 6f 6e 64 73 20 31 30 30 } //1 Start-Sleep -Milliseconds 100
		$a_01_5 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 24 75 73 69 6e 67 3a 75 72 6c 20 2d 4f 75 74 46 69 6c 65 20 24 75 73 69 6e 67 3a 6f 75 74 70 75 74 46 69 6c 65 } //1 Invoke-WebRequest -Uri $using:url -OutFile $using:outputFile
	condition:
		((#a_03_0  & 1)*7+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}