
rule Trojan_Win64_Stealer_NS_MTB{
	meta:
		description = "Trojan:Win64/Stealer.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 16 45 31 d2 4c 89 c6 49 89 d1 eb dc 0f b6 48 06 0f b7 40 04 35 65 b1 00 00 } //3
		$a_01_1 = {88 4a 06 66 89 42 04 4c 8d ac 24 f8 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win64_Stealer_NS_MTB_2{
	meta:
		description = "Trojan:Win64/Stealer.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 da e8 9b bf ff ff 41 83 f8 01 0f 94 c0 eb 02 31 c0 c7 45 c8 03 00 00 00 88 45 cc 48 8d 55 c8 48 89 f9 ff 56 20 8b 45 c8 48 8b 4d f8 87 01 a8 04 } //2
		$a_01_1 = {28 48 8d 6a 40 48 8d 4d f0 e8 88 40 ff ff 90 48 83 c4 28 5e 5d c3 48 89 54 24 10 55 56 48 83 ec 28 48 8d 6a 40 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}