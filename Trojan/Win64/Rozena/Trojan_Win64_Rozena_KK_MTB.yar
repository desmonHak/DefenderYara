
rule Trojan_Win64_Rozena_KK_MTB{
	meta:
		description = "Trojan:Win64/Rozena.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 c0 0d 66 19 00 8d ?? ?? ?? ?? ?? 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 } //20
		$a_01_1 = {10 00 00 41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 41 ff d2 48 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}