
rule Trojan_Win64_BlackWidow_KKV_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.KKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6c ca 66 0f 6d c1 49 f7 f3 66 0f fd cc 66 0f 6f d8 } //3
		$a_01_1 = {66 0f 38 1d f0 45 8a 14 11 66 0f dd e6 66 0f 6d cf } //4
		$a_01_2 = {66 0f 6c d7 44 30 14 0f 66 0f fd da 66 0f 6d cc 66 0f fd c1 } //5
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*5) >=12
 
}