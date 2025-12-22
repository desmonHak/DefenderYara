
rule Trojan_Win32_Zusy_ARR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {87 2c 24 5c 89 14 24 57 89 0c 24 8b 14 24 83 ec } //10
		$a_01_1 = {47 30 16 b0 83 41 5d } //7
		$a_03_2 = {ab 3b cd 5b c7 30 dd 65 c0 72 ?? ?? 4c 11 b4 59 } //3
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*7+(#a_03_2  & 1)*3) >=20
 
}
rule Trojan_Win32_Zusy_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 43 da 33 06 4d 6c 3c 45 } //15
		$a_03_1 = {dc 36 02 ec 98 6b c1 ?? ee d3 ce 32 4a fc } //5
		$a_01_2 = {33 3c 24 31 3c 24 33 3c 24 5c 8d 44 24 24 } //15
		$a_03_3 = {67 32 15 66 e7 ?? ?? ?? d6 ed 53 ab } //5
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*5+(#a_01_2  & 1)*15+(#a_03_3  & 1)*5) >=20
 
}