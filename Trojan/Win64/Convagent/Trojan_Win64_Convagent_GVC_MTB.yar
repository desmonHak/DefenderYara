
rule Trojan_Win64_Convagent_GVC_MTB{
	meta:
		description = "Trojan:Win64/Convagent.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 8d 04 29 3b 43 08 73 28 8b d0 4c 8b 03 41 3b c7 73 1e 41 0f b6 04 16 44 8b d1 46 0f b6 54 16 10 41 33 c2 41 88 04 10 ff c1 41 3b cc 7c d1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}