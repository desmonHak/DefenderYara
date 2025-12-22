
rule Trojan_Win64_Mikey_BAF_MTB{
	meta:
		description = "Trojan:Win64/Mikey.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {f0 01 00 00 f0 2f 00 00 36 01 } //10
		$a_01_1 = {2e 72 73 72 63 00 00 00 00 20 00 00 00 e0 31 00 00 12 } //10
		$a_01_2 = {d0 29 00 00 00 32 00 00 fc 02 } //10
		$a_03_3 = {40 00 00 e0 2e 64 61 74 61 00 00 00 00 ?? 10 00 00 d0 5b } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_03_3  & 1)*10) >=40
 
}