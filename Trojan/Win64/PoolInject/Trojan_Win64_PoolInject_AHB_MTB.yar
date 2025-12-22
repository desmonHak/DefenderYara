
rule Trojan_Win64_PoolInject_AHB_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 44 24 09 0f b6 44 24 09 c1 f8 ?? 0f b6 4c 24 09 c1 e1 ?? 0b c1 0f b6 4c 24 09 33 c8 8b c1 88 44 24 09 } //20
		$a_03_1 = {48 8b 84 24 b0 00 00 00 48 25 ?? ?? ?? ?? 0f b7 c0 89 44 24 70 48 8b 84 24 b0 00 00 00 48 c1 e8 ?? 48 25 ?? ?? ?? ?? 0f b7 c0 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}