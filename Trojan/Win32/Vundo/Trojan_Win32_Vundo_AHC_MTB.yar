
rule Trojan_Win32_Vundo_AHC_MTB{
	meta:
		description = "Trojan:Win32/Vundo.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 10 80 f2 ?? 66 0f b6 d2 0f b7 d2 88 10 41 8b c1 80 39 ?? 75 } //30
		$a_03_1 = {32 14 2f 8b 4c 24 14 8d 34 85 ?? ?? ?? ?? 33 f0 03 f6 22 d9 33 f0 32 d3 32 d0 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}