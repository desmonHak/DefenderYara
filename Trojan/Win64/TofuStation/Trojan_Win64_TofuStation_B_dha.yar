
rule Trojan_Win64_TofuStation_B_dha{
	meta:
		description = "Trojan:Win64/TofuStation.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {c2 83 22 f1 b1 41 67 0e 20 fc 5b 81 f4 27 5a 2f 6f } //1
		$a_01_1 = {fa d4 d7 aa 95 9b 70 0f 25 06 b3 1e 4e 46 86 f4 ba } //1
		$a_01_2 = {08 82 bf 4d fa cb a4 33 63 5b e2 3d bf 19 e3 9c 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}