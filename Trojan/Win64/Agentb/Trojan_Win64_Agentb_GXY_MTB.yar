
rule Trojan_Win64_Agentb_GXY_MTB{
	meta:
		description = "Trojan:Win64/Agentb.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 32 14 1b 41 f7 f9 41 d2 ca 41 31 f2 83 c6 07 46 88 14 1b } //5
		$a_01_1 = {89 c8 99 41 f7 f9 48 63 d2 41 0f b6 04 10 41 30 04 0a 48 83 c1 01 49 39 cb 75 e5 c3 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}