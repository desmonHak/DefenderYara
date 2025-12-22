
rule Trojan_Win64_OysterLoader_GVD_MTB{
	meta:
		description = "Trojan:Win64/OysterLoader.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 b8 eb 1b 48 8b 4d 20 8b 55 } //2
		$a_01_1 = {48 b8 48 83 c4 20 5d c3 90 90 } //1
		$a_01_2 = {48 b8 ab 3d 79 d4 62 62 65 4f } //2
		$a_01_3 = {48 b9 07 ad e1 25 e8 4c 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}