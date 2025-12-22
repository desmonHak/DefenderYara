
rule Trojan_Win64_DonutLoader_GTD_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f af c9 41 f6 c1 01 41 0f 94 c1 43 83 3c 20 0a 0f 9c c1 44 08 c9 41 89 c8 41 80 f0 01 45 0f b6 c0 49 c1 e0 05 49 8b 54 10 70 4c 01 f2 66 66 66 2e 0f 1f 84 00 00 00 00 00 31 f6 ff e2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}