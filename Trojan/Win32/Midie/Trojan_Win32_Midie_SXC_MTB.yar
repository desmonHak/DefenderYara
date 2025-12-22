
rule Trojan_Win32_Midie_SXC_MTB{
	meta:
		description = "Trojan:Win32/Midie.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 85 78 ff ff ff 2e 64 6c 6c 0f 28 05 ?? ?? ?? ?? c6 85 7c ff ff ff 00 0f 11 45 a0 c7 45 b0 69 74 79 50 c7 45 b4 6c 61 79 65 c7 45 b8 72 2e 64 6c 66 c7 45 bc 6c 00 } //15
		$a_03_1 = {83 c4 0c c7 85 c8 fe ff ff 00 04 00 00 8d 85 c4 fe ff ff c7 85 d0 fe ff ff ?? ?? ?? ?? c7 85 d4 fe ff ff ?? ?? ?? ?? c7 85 e0 fe ff ff ?? ?? ?? ?? 50 ff 15 } //10
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 68 68 2e 65 78 65 } //1 taskkill /f /im hh.exe
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=26
 
}