
rule Trojan_Win64_Androm_SX_MTB{
	meta:
		description = "Trojan:Win64/Androm.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 04 41 89 44 24 ?? 8b 04 24 99 b9 6d 00 00 00 f7 f9 8b c2 05 ?? ?? ?? ?? 8b 4c 24 ?? 33 c8 8b c1 48 63 0c 24 } //6
		$a_03_1 = {8b 44 24 34 ff c0 89 44 24 34 83 7c 24 34 ?? 7d 23 8b 44 24 24 c1 e0 ?? 8b 4c 24 24 c1 e9 ?? 0b c1 89 44 24 24 8b 44 24 24 35 ?? ?? ?? ?? 89 44 24 24 eb cc } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}
rule Trojan_Win64_Androm_SX_MTB_2{
	meta:
		description = "Trojan:Win64/Androm.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_03_0 = {f3 43 0f 6f 04 28 48 63 c1 83 c2 ?? 83 c1 ?? 48 8d 7f ?? 66 0f ef c6 f3 43 0f 7f 04 28 f3 42 0f 6f 04 28 4c 63 c2 66 0f ef c6 f3 42 0f 7f 04 28 } //10
		$a_03_1 = {45 33 c0 33 c9 49 f7 e4 48 d1 ea 48 8d 04 52 41 8d 51 ?? 4c 2b e0 48 8d 44 24 ?? 41 8b fc 48 89 44 24 ?? 48 c1 e7 ?? 48 03 fb } //5
		$a_80_2 = {5c 57 65 72 46 61 75 6c 74 2e 65 78 65 } //\WerFault.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1) >=16
 
}