
rule Trojan_Win64_Lazy_MKC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 05 d1 87 01 00 48 89 87 b8 00 00 00 48 8b 05 c3 87 01 00 48 89 44 24 30 f0 83 00 01 48 8b 5c 24 30 b9 0d } //15
		$a_01_1 = {c7 81 c8 00 00 00 01 00 00 00 c6 81 74 01 00 00 43 c6 81 f7 01 00 00 43 48 8d 05 24 7a 01 00 48 89 81 b8 00 00 00 b9 0d } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}