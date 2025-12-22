
rule Trojan_Win64_Mimikatz_AHB_MTB{
	meta:
		description = "Trojan:Win64/Mimikatz.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 89 6c 24 68 c6 44 24 3f 00 c6 44 24 3e 00 48 c7 44 24 50 00 00 00 00 c7 04 24 00 00 00 00 48 8d 54 24 50 48 89 54 24 08 } //20
		$a_03_1 = {0f b6 34 10 4c 8d 42 01 4c 8d 8a ?? ?? ?? ?? 49 0f af f1 48 01 f1 4c 89 c2 48 39 d3 7f } //30
		$a_00_2 = {73 70 72 65 61 64 2e 43 72 79 70 74 6f 68 69 6a 61 63 6b } //10 spread.Cryptohijack
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*30+(#a_00_2  & 1)*10) >=60
 
}