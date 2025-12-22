
rule Trojan_Win64_Babuk_NB_MTB{
	meta:
		description = "Trojan:Win64/Babuk.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 41 3b 11 41 8d 40 01 0f b7 51 02 41 0f 44 c0 48 83 c1 02 49 83 c1 02 44 8b c0 66 83 fa 3d 75 df } //2
		$a_01_1 = {48 63 85 b8 00 00 00 46 88 2c 20 8b 85 b8 00 00 00 ff c0 89 85 b8 00 00 00 48 63 85 b8 00 00 00 49 3b c0 72 db } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}