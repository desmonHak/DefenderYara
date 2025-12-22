
rule Trojan_Win32_Lazy_MKA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 f1 01 34 01 08 d1 20 c5 30 e0 80 f1 01 08 e8 08 d9 88 c4 } //15
		$a_03_1 = {0f 94 c5 0f 95 c4 83 fa 0a 0f 9c 04 24 83 fa ?? 88 e8 88 64 24 10 88 6c 24 14 0f 9f c1 30 e0 20 e8 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}