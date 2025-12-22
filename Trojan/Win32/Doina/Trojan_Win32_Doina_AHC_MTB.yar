
rule Trojan_Win32_Doina_AHC_MTB{
	meta:
		description = "Trojan:Win32/Doina.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 b4 24 28 02 00 00 89 9c 24 24 02 00 00 66 89 94 24 14 02 00 00 c6 84 24 40 02 00 00 ?? 83 bc 24 40 01 00 00 } //30
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 6f 6e 68 6f 7a 2e 65 78 65 20 2f 46 } //20 taskkill /IM conhoz.exe /F
		$a_81_2 = {47 6c 6f 62 61 6c 5c 54 65 73 74 44 6f 77 6e 32 30 31 39 4d 75 74 65 78 } //10 Global\TestDown2019Mutex
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_81_2  & 1)*10) >=60
 
}