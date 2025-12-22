
rule Trojan_Win64_NukeSped_GVB_MTB{
	meta:
		description = "Trojan:Win64/NukeSped.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 ff c9 24 3f c1 ea 06 0c 80 41 88 00 49 ff c8 85 c9 7f ea 43 0a 94 8b 78 4a 06 00 41 88 10 44 0f b6 04 24 45 8b c8 41 8b c8 49 c1 e9 03 83 e1 07 41 0f b6 14 29 0f ab ca 41 88 14 29 49 8b c2 eb 2d } //2
		$a_01_1 = {48 8b 43 08 0f b6 14 07 8b ca 83 e2 07 48 c1 e9 03 0f b6 04 29 0f ab d0 88 04 29 49 8d 42 01 48 8b 4c 24 08 48 33 cc } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}