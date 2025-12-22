
rule Trojan_Win64_Vidar_GRX_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 c3 25 3a d5 74 41 ff cb 41 81 eb 35 3e 63 67 45 29 de 41 81 eb a7 f8 f2 77 41 01 d3 41 81 c3 a7 f8 f2 77 41 56 81 34 24 13 d3 7d 47 58 35 13 } //5
		$a_01_1 = {60 81 f9 0b 41 29 de 41 81 c6 60 81 f9 0b 41 b8 30 d8 de 3f 41 81 e8 2a 54 df e3 45 89 c5 41 c1 e5 05 41 c1 ed 08 41 f7 dd 41 81 ed 93 45 20 f0 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}