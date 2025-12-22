
rule Trojan_Win64_Oyster_ZC_MTB{
	meta:
		description = "Trojan:Win64/Oyster.ZC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 89 44 5c 42 0f b6 01 84 c0 74 15 66 89 44 5c 44 48 83 c1 03 48 83 c3 03 48 83 fb 3f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}