
rule Trojan_Win64_PoolInject_MKA_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 8c 24 68 03 00 00 88 c2 8b 84 24 64 03 00 00 0f be d2 01 d0 89 84 24 70 03 00 00 48 8b 05 } //15
		$a_03_1 = {0f be c9 0f af c1 89 c1 44 89 c0 8d 04 88 8a 0d ?? ?? ?? ?? 0f be c9 f7 f1 8a 0d ?? ?? ?? ?? 0f be c9 29 c8 83 f8 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}