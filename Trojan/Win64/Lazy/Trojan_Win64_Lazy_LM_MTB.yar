
rule Trojan_Win64_Lazy_LM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 63 94 24 b8 08 00 00 89 c1 c1 f9 1f 48 69 d2 70 03 00 00 48 03 ?? ?? ?? ?? ?? c1 e9 1b 01 c8 83 e0 1f 29 c8 83 c0 01 c1 e0 0a 89 42 5c } //20
		$a_03_1 = {43 0f b6 0c 2c 85 c0 0f 95 c0 0f b6 c0 09 c6 84 c9 75 ?? 41 8d 55 fa 31 c0 83 fa 18 77 ?? 8d 04 2b 01 f8 01 f0 83 f8 01 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}