
rule Trojan_Win64_Midie_GVC_MTB{
	meta:
		description = "Trojan:Win64/Midie.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 8d 14 29 41 3b d6 73 22 42 8d 14 29 48 8d 54 13 10 83 f9 40 73 14 44 8b c1 47 0f b6 44 04 10 44 30 02 ff c1 3b c8 7c d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}