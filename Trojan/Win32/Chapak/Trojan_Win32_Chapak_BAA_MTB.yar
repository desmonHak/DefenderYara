
rule Trojan_Win32_Chapak_BAA_MTB{
	meta:
		description = "Trojan:Win32/Chapak.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c6 c1 e0 04 03 45 e8 8d 0c 33 33 d0 33 d1 6a 00 2b fa 81 c3 } //2
		$a_01_1 = {8b 45 08 89 38 89 70 04 83 c0 08 ff 4d f8 89 45 08 0f 85 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}