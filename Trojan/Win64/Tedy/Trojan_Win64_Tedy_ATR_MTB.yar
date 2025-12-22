
rule Trojan_Win64_Tedy_ATR_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {23 00 0b 02 0e 2c 00 4e 10 00 00 6c 1a 00 } //10
		$a_01_1 = {4c 88 c4 01 00 90 2b 01 00 8a c4 01 00 0a } //5
		$a_01_2 = {20 f0 02 00 06 00 00 00 94 c4 01 } //3
		$a_01_3 = {44 e3 16 01 00 90 14 00 } //2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=20
 
}