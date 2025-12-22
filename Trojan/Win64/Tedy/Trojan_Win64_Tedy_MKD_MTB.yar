
rule Trojan_Win64_Tedy_MKD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 28 44 24 ?? 0f 57 00 0f 29 44 24 ?? 0f 28 44 24 ?? 0f 57 40 10 31 f6 0f 29 44 24 ?? 0f 57 c0 0f 29 04 24 89 74 24 } //15
		$a_03_1 = {31 c9 89 5c ?? 24 89 d8 89 54 24 ?? 01 d0 0f 92 c1 89 c3 83 c3 ?? 83 d1 00 ba fe ff ff ff 39 da } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}