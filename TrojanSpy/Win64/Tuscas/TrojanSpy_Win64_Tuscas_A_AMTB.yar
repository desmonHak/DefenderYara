
rule TrojanSpy_Win64_Tuscas_A_AMTB{
	meta:
		description = "TrojanSpy:Win64/Tuscas.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 43 52 45 45 4e 53 48 4f 54 } //1 SCREENSHOT
		$a_01_1 = {63 00 6d 00 64 00 20 00 2f 00 43 00 20 00 22 00 74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 53 00 56 00 43 00 20 00 3e 00 3e 00 20 00 25 00 73 00 } //1 cmd /C "tasklist.exe /SVC >> %s
		$a_81_2 = {53 59 53 49 4e 46 4f } //1 SYSINFO
		$a_81_3 = {63 6d 64 20 2f 43 20 22 73 79 73 74 65 6d 69 6e 66 6f 2e 65 78 65 20 3e 20 25 73 } //1 cmd /C "systeminfo.exe > %s
		$a_81_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}