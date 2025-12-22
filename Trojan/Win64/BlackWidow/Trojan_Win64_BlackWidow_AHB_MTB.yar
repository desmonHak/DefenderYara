
rule Trojan_Win64_BlackWidow_AHB_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6f c8 66 0f fd da 66 0f fd cb 66 0f 6f c3 66 0f 6f c1 66 0f fd cc 66 0f 38 1d c1 } //20
		$a_01_1 = {48 ff c1 66 0f 6f cd 66 0f 38 30 c1 66 0f 6f cb 66 0f 6f d1 66 0f fd cf } //30
		$a_01_2 = {34 52 53 56 66 33 61 79 37 28 6f 50 64 52 32 75 } //10 4RSVf3ay7(oPdR2u
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30+(#a_01_2  & 1)*10) >=60
 
}