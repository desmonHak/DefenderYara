
rule Trojan_Win64_PoolInject_SXB_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b c5 49 f7 e3 48 d1 ea 0f b6 c2 02 c0 02 d0 } //3
		$a_03_1 = {73 23 48 8b 04 24 48 63 4c 24 4c 8b 54 8c 5c 48 63 4c 24 4c 89 54 88 04 8b 44 24 4c 83 c0 ?? 89 44 24 4c eb d2 } //2
		$a_80_2 = {2f 63 20 74 69 6d 65 6f 75 74 20 32 20 26 20 64 65 6c 20 2f 66 20 2f 71 20 22 25 73 } ///c timeout 2 & del /f /q "%s  1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_80_2  & 1)*1) >=6
 
}