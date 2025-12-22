
rule Trojan_Win64_Killfiles_PAGZ_MTB{
	meta:
		description = "Trojan:Win64/Killfiles.PAGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //2 DisableAntiSpyware
		$a_01_1 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin.exe delete shadows /all /quiet
		$a_01_2 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 6e 61 62 6c 65 43 6f 6e 74 72 6f 6c 6c 65 64 46 6f 6c 64 65 72 41 63 63 65 73 73 20 44 69 73 61 62 6c 65 64 } //1 Set-MpPreference -EnableControlledFolderAccess Disabled
		$a_01_3 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6f 66 66 } //1 bcdedit /set {current} recoveryenabled off
		$a_01_4 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 61 64 76 61 6e 63 65 64 6f 70 74 69 6f 6e 73 20 6f 66 66 } //1 bcdedit /set {current} advancedoptions off
		$a_01_5 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 40 28 24 65 6e 76 3a 55 73 65 72 50 72 6f 66 69 6c 65 2c 20 24 65 6e 76 3a 50 72 6f 67 72 61 6d 44 61 74 61 2c 20 24 65 6e 76 3a 50 72 6f 67 72 61 6d 46 69 6c 65 73 2c 20 24 65 6e 76 3a 50 72 6f 67 72 61 6d 46 69 6c 65 73 20 28 78 38 36 29 29 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e 20 27 2e 65 78 65 27 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 } //2 Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramData, $env:ProgramFiles, $env:ProgramFiles (x86)) -ExclusionExtension '.exe' -ExclusionProcess
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=9
 
}