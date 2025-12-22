
rule Trojan_Win32_Fragtor_AHC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 6a 20 66 89 45 ce 58 6a 69 66 89 45 d0 58 6a 6c 66 89 45 d4 58 6a 65 66 89 45 d6 58 6a 73 66 89 45 d8 } //30
		$a_03_1 = {0f b6 c1 8a 4c 3b ?? 0f 43 d0 c0 e2 ?? ?? ?? ?? 57 1a c0 83 c3 ?? 24 ?? 04 ?? 2a c8 02 ca 88 0e 46 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}