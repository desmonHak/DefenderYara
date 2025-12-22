
rule Trojan_Win64_Vidar_AHC_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {f2 0f 59 c1 f2 0f 10 94 c4 ?? ?? 00 00 f2 0f 10 ?? ?? ?? ?? ?? f2 0f 59 d3 f2 0f 58 d0 f2 0f 11 94 c4 ?? ?? 00 00 48 ff c0 } //30
		$a_03_1 = {f2 0f 10 84 c4 ?? ?? 00 00 48 89 c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 f7 e9 48 01 ca 48 d1 fa 48 8d 14 52 48 89 c8 48 29 d0 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}