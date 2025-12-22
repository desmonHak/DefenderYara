
rule Trojan_Win64_Khalesi_MK_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 40 01 00 00 49 50 43 41 c7 84 24 44 01 00 00 53 53 44 54 c7 84 24 50 01 00 00 46 41 43 50 c7 84 24 48 01 00 00 54 44 53 44 } //15
		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 33 20 3e 6e 75 6c 20 26 20 64 65 6c 20 2f 46 20 2f 51 } //10 cmd.exe /C ping 127.0.0.1 -n 3 >nul & del /F /Q
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 2f 56 33 2f 74 65 61 6d 72 65 64 6d 69 6e 65 72 2e 65 78 65 } //5 download/V3/teamredminer.exe
		$a_01_3 = {70 72 6f 63 65 78 70 2e 65 78 65 } //3 procexp.exe
		$a_01_4 = {4a 6f 65 42 6f 78 } //2 JoeBox
	condition:
		((#a_01_0  & 1)*15+(#a_81_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=35
 
}