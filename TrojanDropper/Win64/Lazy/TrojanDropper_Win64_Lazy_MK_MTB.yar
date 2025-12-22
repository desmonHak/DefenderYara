
rule TrojanDropper_Win64_Lazy_MK_MTB{
	meta:
		description = "TrojanDropper:Win64/Lazy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b 4c 24 0c 48 8d 54 24 20 41 b8 30 00 00 00 48 01 c1 48 8b 05 c2 93 0c 00 48 89 4c 30 18 } //15
		$a_01_1 = {0f b6 43 40 83 63 44 fe 83 e0 f0 83 c8 05 88 43 40 f0 83 05 69 b0 0b 00 01 48 8b 4b 30 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}