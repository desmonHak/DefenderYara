
rule Trojan_Win64_Vidar_YNF_MTB{
	meta:
		description = "Trojan:Win64/Vidar.YNF!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 8a 04 38 4c 8b 7d d0 41 32 07 4c 8b 7d e0 } //11
	condition:
		((#a_01_0  & 1)*11) >=11
 
}