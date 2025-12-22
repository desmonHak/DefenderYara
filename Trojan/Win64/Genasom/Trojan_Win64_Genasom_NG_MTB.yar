
rule Trojan_Win64_Genasom_NG_MTB{
	meta:
		description = "Trojan:Win64/Genasom.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_03_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 22 77 75 73 61 20 2f 75 6e 69 6e 73 74 61 6c 6c 20 2f 6b 62 3a [0-2f] 20 2f 71 75 69 65 74 20 2f 6e 6f 72 65 73 74 61 72 74 } //2
		$a_01_1 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin.exe delete shadows /all /quiet
		$a_01_2 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 40 28 24 65 6e 76 3a 55 73 65 72 50 72 6f 66 69 6c 65 2c 20 24 65 6e 76 3a 50 72 6f 67 72 61 6d 44 61 74 61 } //1 Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramData
		$a_01_3 = {2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 20 27 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 } //1 -ExclusionProcess 'C:\Windows\System32\cmd.exe
		$a_01_4 = {2d 46 6f 72 63 65 } //1 -Force
		$a_01_5 = {55 53 45 52 50 52 4f 46 49 4c 45 } //1 USERPROFILE
		$a_01_6 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6f 66 66 } //1 bcdedit /set {current} recoveryenabled off
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}