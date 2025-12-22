
rule Trojan_Win64_PoolInject_C_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 08 44 31 c2 88 14 08 48 8b 84 24 ?? ?? ?? ?? 8b 00 8b 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}