
rule Trojan_Win32_Injuke_AHC_MTB{
	meta:
		description = "Trojan:Win32/Injuke.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 13 01 f6 43 09 ce 81 c7 ?? ?? ?? ?? 01 f1 89 f1 09 f1 39 c7 7e } //20
		$a_03_1 = {8b 3c 24 83 c4 ?? 81 c3 ?? ?? ?? ?? 57 09 d8 43 01 d8 5a 48 81 c0 ?? ?? ?? ?? 4b 41 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}