
rule Trojan_Win32_Fragtor_GVD_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 5c 24 18 8d 04 0b 8b 4c 24 10 35 00 00 00 80 8a 44 04 28 88 04 31 41 89 4c 24 10 83 f9 14 0f 82 78 ff ff ff } //2
		$a_01_1 = {8b 86 b8 00 00 00 8b 96 b4 00 00 00 8d 48 01 3b d1 75 10 fe c0 30 86 be 00 00 00 ff 86 b4 00 00 00 eb dd } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}