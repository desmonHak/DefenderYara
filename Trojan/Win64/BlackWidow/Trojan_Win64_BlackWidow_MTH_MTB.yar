
rule Trojan_Win64_BlackWidow_MTH_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 0f 62 c2 66 0f 69 d0 44 30 14 0f 66 0f 6d c1 } //1
		$a_01_1 = {66 0f 69 d0 44 30 14 0f 66 0f 6d c1 } //1
		$a_01_2 = {66 0f 6f c8 48 ff c1 66 0f 6c d1 } //1
		$a_01_3 = {66 0f dd e6 48 89 c8 66 0f f9 e0 } //1
		$a_01_4 = {66 0f 6f cb 48 81 f9 5e a3 03 00 0f 86 63 f7 ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}