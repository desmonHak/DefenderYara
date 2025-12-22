
rule Trojan_Win64_Tasker_ARR_MTB{
	meta:
		description = "Trojan:Win64/Tasker.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 57 69 6e 64 6f 77 73 53 79 73 74 65 6d 53 65 72 76 69 63 65 22 20 2f 74 72 20 22 5c 22 25 73 5c 22 22 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 66 } //6 schtasks /create /tn "WindowsSystemService" /tr "\"%s\"" /sc onlogon /rl highest /f
		$a_01_1 = {63 6d 64 20 2f 63 20 74 69 6d 65 6f 75 74 20 33 20 3e 20 6e 75 6c } //4 cmd /c timeout 3 > nul
		$a_01_2 = {25 73 5c 6d 6f 6e 69 74 6f 72 5f 6c 6f 67 2e 74 78 74 } //8 %s\monitor_log.txt
		$a_01_3 = {8b 0b 4c 89 f2 49 89 e8 83 c7 01 49 01 ee 41 0f af cf 41 0f af cc } //2
	condition:
		((#a_81_0  & 1)*6+(#a_01_1  & 1)*4+(#a_01_2  & 1)*8+(#a_01_3  & 1)*2) >=20
 
}