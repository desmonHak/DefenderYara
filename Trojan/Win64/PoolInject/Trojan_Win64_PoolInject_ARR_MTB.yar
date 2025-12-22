
rule Trojan_Win64_PoolInject_ARR_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 84 24 c8 00 00 00 45 8b 44 ?? 04 48 63 84 24 c8 00 00 00 44 23 44 24 38 45 03 c0 41 8b 54 ?? 04 48 63 84 24 } //15
		$a_03_1 = {83 c8 01 44 8b c7 42 89 04 09 4d 03 c1 48 8b 05 ?? ?? ?? ?? 48 8d 4c 24 ?? 48 89 44 24 ?? 33 d2 33 c0 41 c6 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}