
rule Trojan_Win64_BlackWidow_RVT_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.RVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6d cb 66 0f fd da 45 8a 14 11 66 0f 6f c8 66 0f 6a ca } //2
		$a_01_1 = {66 0f 6f c8 66 0f 6a ca 44 30 14 0f 66 0f dd e6 66 0f 6d cf } //3
		$a_01_2 = {66 0f 61 ca 48 ff c1 66 0f 38 30 c1 66 0f 6f d0 } //5
		$a_01_3 = {66 0f fd c2 66 0f 6f c1 48 81 f9 d3 95 01 00 0f 86 bb f3 ff ff } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*5+(#a_01_3  & 1)*4) >=14
 
}