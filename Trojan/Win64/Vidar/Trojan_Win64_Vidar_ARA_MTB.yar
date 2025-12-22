
rule Trojan_Win64_Vidar_ARA_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 08 ff c2 83 e1 0f 4a 0f be 84 11 e0 54 01 00 42 8a 8c 11 f0 54 01 00 4c 2b c0 41 8b 40 fc d3 e8 4c 89 47 08 89 47 18 41 0f b6 08 83 e1 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}