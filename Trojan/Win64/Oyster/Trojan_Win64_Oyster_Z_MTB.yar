
rule Trojan_Win64_Oyster_Z_MTB{
	meta:
		description = "Trojan:Win64/Oyster.Z!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 b8 44 89 f8 41 ff c7 44 88 } //1
		$a_01_1 = {48 b8 0f b6 07 41 c1 e2 08 ff } //1
		$a_01_2 = {49 bf 0f b6 07 41 c1 e2 08 41 } //1
		$a_01_3 = {48 b8 89 d0 66 c1 e8 05 8d 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}