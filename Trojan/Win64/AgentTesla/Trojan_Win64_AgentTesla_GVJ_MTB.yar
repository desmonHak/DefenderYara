
rule Trojan_Win64_AgentTesla_GVJ_MTB{
	meta:
		description = "Trojan:Win64/AgentTesla.GVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 8b d8 44 33 5c 24 40 41 8b cb 8b 44 24 38 89 44 24 40 44 8b 54 24 3c 41 ff ca 89 4c 24 44 79 bb } //2
		$a_01_1 = {45 0f b6 5c 10 10 44 03 d8 41 8b c3 41 33 c1 ff c2 44 3b d2 7f ea } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}