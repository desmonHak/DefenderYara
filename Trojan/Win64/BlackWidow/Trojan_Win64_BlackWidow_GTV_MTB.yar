
rule Trojan_Win64_BlackWidow_GTV_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f f9 d8 66 0f 6f c1 66 0f 6a ca 66 0f 6c d3 } //5
		$a_01_1 = {66 0f f9 d0 66 0f 6f c1 66 0f fd da 66 0f f9 cb 66 0f 6c d1 66 0f f9 fd 66 0f 6c e3 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}