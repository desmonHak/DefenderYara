
rule Trojan_Win64_XLoader_GVC_MTB{
	meta:
		description = "Trojan:Win64/XLoader.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b f0 8b cb 0f b6 44 0d 10 40 0f b6 d6 2b c2 05 00 01 00 00 0f b6 c0 88 44 0d 10 ff c3 3b fb 7f d8 } //2
		$a_01_1 = {0f b7 c1 8b c8 c1 f9 02 33 c8 8b d0 c1 fa 03 33 ca 8b d0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}