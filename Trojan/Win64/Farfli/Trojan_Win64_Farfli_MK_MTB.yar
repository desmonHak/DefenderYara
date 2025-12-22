
rule Trojan_Win64_Farfli_MK_MTB{
	meta:
		description = "Trojan:Win64/Farfli.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 05 13 fa ff ff 45 33 c9 48 89 44 24 28 33 d2 33 c9 89 44 24 20 ff 15 ?? ?? 01 00 83 ca ff 48 8b c8 ff 15 ?? ?? 01 00 b9 2c 01 00 00 ff 15 ?? ?? 01 00 32 c0 48 83 c4 38 } //10
		$a_81_1 = {54 43 50 45 79 65 } //5 TCPEye
		$a_81_2 = {73 5f 62 69 6e } //3 s_bin
		$a_81_3 = {25 34 64 2e 25 32 64 2e 25 32 64 2d 25 32 64 3a 25 32 64 3a 25 32 64 } //2 %4d.%2d.%2d-%2d:%2d:%2d
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*3+(#a_81_3  & 1)*2) >=20
 
}