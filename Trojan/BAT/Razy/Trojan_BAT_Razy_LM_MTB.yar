
rule Trojan_BAT_Razy_LM_MTB{
	meta:
		description = "Trojan:BAT/Razy.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 5e b3 24 70 28 04 00 00 0a 2d ?? 28 05 00 00 0a 72 92 b3 24 70 28 06 00 00 0a 0b 16 0c 2b ?? 06 08 8f 08 00 00 01 25 71 08 00 00 01 [0-05] 61 d2 81 08 00 00 01 08 17 58 0c 08 06 8e } //20
		$a_03_1 = {70 28 03 00 00 0a 0a 72 5e b3 24 70 28 04 00 00 0a 2d ?? 28 05 00 00 0a 72 92 b3 24 70 28 06 00 00 0a 0b 16 0c 2b ?? 06 08 8f 08 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}