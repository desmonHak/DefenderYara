
rule Trojan_Win64_Cerbu_MK_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 ff c9 41 b8 ?? ?? ?? ?? 4a 8d 04 8f 42 8b 0c 10 42 0f b6 04 11 48 8d 51 01 49 03 d2 84 c0 } //15
		$a_01_1 = {0f be ca 0f b6 10 48 8d 40 01 41 33 c8 44 69 c1 43 01 00 00 84 d2 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}