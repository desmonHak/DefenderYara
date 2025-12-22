
rule Trojan_Win64_Zusy_KAM_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f af c3 c1 c8 05 8b d0 33 d1 8b cf 33 fe 41 8b f2 d3 ca 8b c8 } //20
		$a_01_1 = {41 c1 c8 05 41 0f af d3 41 8b c8 c1 ca 05 d3 c0 8b ca 33 c2 41 d3 c1 45 33 c8 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}