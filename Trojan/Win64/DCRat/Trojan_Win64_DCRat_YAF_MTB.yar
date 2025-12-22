
rule Trojan_Win64_DCRat_YAF_MTB{
	meta:
		description = "Trojan:Win64/DCRat.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 74 6d 70 66 69 6c 65 73 2e 6f 72 67 2f } //2 https://tmpfiles.org/
		$a_01_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 Add-MpPreference -ExclusionPath
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1 powershell -Command "Invoke-WebRequest -Uri
		$a_03_3 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 43 3a 5c [0-30] 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}