
rule Trojan_Win64_BlackWidow_VOT_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.VOT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6f c1 66 0f 6f c8 66 0f f9 d0 45 8a 14 10 66 0f 38 1d f0 } //3
		$a_01_1 = {66 0f 6c d1 66 0f 6f d0 44 30 14 0f 66 0f fd c2 66 0f 38 1d c1 } //4
		$a_01_2 = {66 0f 38 1d e0 66 0f 6c c2 48 ff c1 66 0f fd c1 } //5
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*5) >=12
 
}