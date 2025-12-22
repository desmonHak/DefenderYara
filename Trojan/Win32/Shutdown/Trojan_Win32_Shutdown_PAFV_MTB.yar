
rule Trojan_Win32_Shutdown_PAFV_MTB{
	meta:
		description = "Trojan:Win32/Shutdown.PAFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 c8 c1 f8 1f c1 fa 02 29 c2 8d 04 92 8d 04 82 29 c1 8b 45 e0 29 cb 03 5d e4 89 04 24 89 5c 24 04 89 5d e4 } //2
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //2 taskkill /f /im explorer.exe
		$a_03_2 = {73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 66 20 2f 74 20 [0-02] 20 2f 63 20 22 } //2
		$a_01_3 = {41 50 50 44 41 54 41 } //1 APPDATA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}