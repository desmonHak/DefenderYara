
rule Trojan_Win64_PoolInject_MK_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 83 c0 0c 48 89 44 24 78 48 8b 44 24 78 0f b6 00 89 44 24 74 8b 44 24 74 89 c1 } //10
		$a_01_1 = {8b 44 24 74 41 89 c0 48 8b 54 24 78 48 83 c2 01 48 8b 4c 24 68 } //10
		$a_01_2 = {c7 44 24 64 00 00 00 00 48 8b 54 24 78 48 83 c2 01 8b 44 24 74 48 01 c2 48 8d 4c 24 64 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}