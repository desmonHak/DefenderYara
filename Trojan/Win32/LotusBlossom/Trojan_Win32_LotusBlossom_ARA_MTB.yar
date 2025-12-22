
rule Trojan_Win32_LotusBlossom_ARA_MTB{
	meta:
		description = "Trojan:Win32/LotusBlossom.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff d7 25 7f 00 00 80 79 05 48 83 c8 80 40 30 44 34 10 46 81 fe 88 04 00 00 72 e5 } //5
		$a_01_1 = {ff 15 2c a3 00 10 } //2
		$a_01_2 = {ff 15 50 51 00 10 } //2
		$a_01_3 = {25 7f 00 00 80 79 05 48 83 c8 80 40 30 84 3d 68 fa ff ff 47 3b fe 72 e2 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3) >=5
 
}