
rule Trojan_Win64_AgentTesla_GVL_MTB{
	meta:
		description = "Trojan:Win64/AgentTesla.GVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8d 04 17 44 3b c5 0f 83 88 00 00 00 45 8b d0 46 0f b6 4c 13 10 44 8b da 48 8b 4c 24 20 46 0f b6 5c 19 10 45 33 cb 45 3b 47 08 73 68 47 88 4c 17 10 ff c2 3b d0 7c c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}