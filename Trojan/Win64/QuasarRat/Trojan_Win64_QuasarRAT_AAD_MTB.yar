
rule Trojan_Win64_QuasarRAT_AAD_MTB{
	meta:
		description = "Trojan:Win64/QuasarRAT.AAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //powershell -NoProfile -WindowStyle Hidden  1
		$a_01_1 = {31 30 33 2e 31 33 31 2e 32 30 30 2e 32 30 38 } //1 103.131.200.208
		$a_80_2 = {75 70 64 61 74 65 2f 57 69 6e 64 6f 77 73 53 79 73 74 65 6d 2e 65 78 65 } //update/WindowsSystem.exe  1
		$a_80_3 = {50 6f 77 65 72 53 68 65 6c 6c 5c 70 73 68 6f 73 74 73 76 63 2e 65 78 65 } //PowerShell\pshostsvc.exe  1
		$a_80_4 = {50 53 48 6f 73 74 53 76 63 } //PSHostSvc  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}