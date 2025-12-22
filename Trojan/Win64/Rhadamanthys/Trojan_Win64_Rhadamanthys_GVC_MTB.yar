
rule Trojan_Win64_Rhadamanthys_GVC_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 43 8d 14 26 3b d0 0f 83 83 05 00 00 44 0f b6 44 15 10 41 8b d4 45 0f b6 54 17 10 45 33 c2 41 8b d4 45 88 44 15 10 41 ff c4 44 3b e7 7c d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}