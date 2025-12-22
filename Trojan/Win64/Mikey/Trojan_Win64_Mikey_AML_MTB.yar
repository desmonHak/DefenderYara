
rule Trojan_Win64_Mikey_AML_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 00 2f 00 2f 00 31 00 39 00 36 00 2e 00 32 00 35 00 31 00 2e 00 31 00 30 00 37 00 2e 00 39 00 34 00 3a 00 35 00 35 00 35 00 33 00 2f 00 [0-2f] 5f 00 62 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //3
		$a_02_1 = {68 74 74 70 3a 2f 2f 31 39 36 2e 32 35 31 2e 31 30 37 2e 39 34 3a 35 35 35 33 2f [0-2f] 5f 62 75 69 6c 64 2e 65 78 65 } //3
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 } //powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command  1
		$a_80_3 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //Add-MpPreference -ExclusionPath  1
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}