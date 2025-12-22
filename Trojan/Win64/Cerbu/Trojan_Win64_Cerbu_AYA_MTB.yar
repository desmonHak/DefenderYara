
rule Trojan_Win64_Cerbu_AYA_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 61 73 74 65 70 6c 6f 61 64 2e 63 6f 6d } //5 pastepload.com
		$a_01_1 = {4c 6f 61 64 65 72 2e 70 64 62 } //2 Loader.pdb
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 69 63 61 63 6c 73 20 22 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 72 65 61 67 65 6e 74 63 2e 65 78 65 22 20 2f 64 65 6e 79 20 45 76 65 72 79 6f 6e 65 3a 52 58 } //1 cmd.exe /C icacls "%SystemRoot%\System32\reagentc.exe" /deny Everyone:RX
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 20 27 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 27 } //1 powershell -Command "Add-MpPreference -ExclusionProcess 'powershell.exe'
		$a_00_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=10
 
}