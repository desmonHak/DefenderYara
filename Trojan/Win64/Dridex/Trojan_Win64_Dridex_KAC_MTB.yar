
rule Trojan_Win64_Dridex_KAC_MTB{
	meta:
		description = "Trojan:Win64/Dridex.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 08 89 4c 24 04 48 89 c1 48 d3 e8 48 89 44 24 38 8b 54 24 04 83 e2 ?? c7 44 24 28 ?? 00 00 00 83 fa 00 } //20
		$a_03_1 = {8b 44 24 20 8b 4c 24 44 81 c1 ?? ?? ?? ?? 21 c8 c7 44 24 28 ?? 00 00 00 83 f8 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}