
rule Trojan_Win64_PoolInject_KK_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8d 0d ?? ?? ?? ?? ?? ?? ?? 00 00 48 8b 00 48 83 c0 20 48 89 44 24 60 48 8b 44 24 60 8b 00 ff c0 48 8b 4c 24 60 89 01 33 c0 85 c0 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}