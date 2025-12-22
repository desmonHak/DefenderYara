
rule Trojan_Win64_Lazy_AR_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 59 52 33 41 58 4c 55 79 30 42 58 33 30 4f 51 4e 66 67 53 75 6b 6c 6a 56 35 } //1 jYR3AXLUy0BX30OQNfgSukljV5
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Lazy_AR_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 40 88 44 24 23 0f b6 05 46 5a 04 00 34 41 88 44 24 24 0f b6 05 3a 5a 04 00 34 42 88 44 24 25 0f b6 05 2e 5a 04 00 34 43 88 44 24 26 0f b6 05 22 5a 04 00 34 44 88 44 24 27 33 c0 66 66 66 0f 1f 84 00 00 00 00 00 } //10
		$a_01_1 = {8d 48 3d 30 4c 04 20 48 ff c0 48 83 f8 08 72 f0 c6 44 24 29 00 48 8d 44 24 20 49 c7 c0 ff ff ff ff 49 ff c0 42 80 3c 00 00 75 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}