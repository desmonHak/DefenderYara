
rule Trojan_Win32_PoolInject_SXD_MTB{
	meta:
		description = "Trojan:Win32/PoolInject.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 30 48 c7 40 10 00 ?? ?? ?? 48 8b 44 24 30 c7 40 18 ?? ?? ?? ?? 4c 8d 0d ?? ?? ?? ?? 48 8b 44 24 30 44 8b 40 08 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 8b 4c 24 30 } //3
		$a_03_1 = {8b 44 24 2c 3b 84 24 88 00 00 00 7d ?? 48 8b 44 24 48 48 63 4c 24 2c 0f b6 04 08 03 44 24 30 89 44 24 30 8b 44 24 2c 83 c0 ?? 89 44 24 2c eb d0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}