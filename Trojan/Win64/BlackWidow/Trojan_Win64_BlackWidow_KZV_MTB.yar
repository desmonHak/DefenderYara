
rule Trojan_Win64_BlackWidow_KZV_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.KZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 0f fd da 49 f7 f0 66 0f f9 d0 66 0f 6f cb 66 0f 38 1d c1 } //2
		$a_01_1 = {66 0f 6f cd 66 0f 6d c1 45 8a 14 11 66 0f fd cb 66 0f 6a ca } //3
		$a_01_2 = {66 0f 6a ca 66 0f 69 d0 44 30 14 0f 66 0f 6d cc } //4
		$a_01_3 = {66 0f fd c2 48 ff c1 66 0f 6c ca } //5
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4+(#a_01_3  & 1)*5) >=14
 
}