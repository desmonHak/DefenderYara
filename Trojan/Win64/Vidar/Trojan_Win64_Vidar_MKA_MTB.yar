
rule Trojan_Win64_Vidar_MKA_MTB{
	meta:
		description = "Trojan:Win64/Vidar.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {d2 dc d0 cf a0 ca d1 d6 19 cb c6 91 15 bf 4f 01 e3 7c 81 e3 ff c4 fb b1 71 a4 47 8b a9 02 } //15
		$a_01_1 = {2e 69 64 61 74 61 20 20 00 10 00 00 00 90 0d } //10
		$a_01_2 = {40 00 00 e0 2e 72 73 72 63 00 00 00 a8 03 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}