
rule Trojan_Win64_Lazy_KAC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 cb f6 c2 01 b8 ?? ?? ?? ?? 41 0f 45 c4 f6 c1 01 41 0f 44 c4 f6 c3 01 b9 ?? ?? ?? ?? 0f 44 c1 3d } //20
		$a_01_1 = {80 f3 01 89 c8 20 d8 30 cb 08 c3 89 d8 34 01 20 d8 34 01 89 d9 30 c1 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}