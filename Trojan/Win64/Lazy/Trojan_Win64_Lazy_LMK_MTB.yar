
rule Trojan_Win64_Lazy_LMK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 4f fe 44 8a 47 ff 8a c1 44 8a 1f 8a d1 c0 e8 07 02 d2 0f b6 c0 6b c0 1b 40 8a 77 01 88 4c 24 70 40 02 f6 41 8a c8 44 88 44 24 78 02 c9 44 88 5c 24 68 32 d0 89 44 24 0c 8a c2 } //20
		$a_01_1 = {32 42 01 32 44 24 78 32 44 24 68 88 42 fe 8a c1 40 32 c6 40 32 ce 41 32 c7 41 32 cf 32 04 24 32 44 24 02 32 44 24 01 32 44 24 78 32 44 24 68 32 0c 24 02 c0 32 4c 24 02 41 32 c1 32 4c 24 01 41 32 c2 40 32 c7 40 32 c5 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}