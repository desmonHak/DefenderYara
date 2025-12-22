
rule Trojan_Win64_DBadur_SXD_MTB{
	meta:
		description = "Trojan:Win64/DBadur.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 63 6f 63 6b ?? ?? ?? 58 ca 99 00 00 ?? 54 00 } //2
		$a_03_1 = {0b 02 0e 2b 00 ?? 3f 00 00 3a b4 } //2
		$a_01_2 = {49 44 41 54 78 da ec 7d 05 7c a4 69 9d 74 77 66 e2 9e 74 3a 69 77 } //3
		$a_01_3 = {c5 9b de f4 26 79 7f 6c 6c 4c 31 34 34 a4 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=10
 
}