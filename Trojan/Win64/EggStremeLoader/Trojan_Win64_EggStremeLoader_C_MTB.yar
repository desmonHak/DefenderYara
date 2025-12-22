
rule Trojan_Win64_EggStremeLoader_C_MTB{
	meta:
		description = "Trojan:Win64/EggStremeLoader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 ca 8a 04 31 41 88 04 30 44 88 0c 31 41 0f b6 0c 30 49 03 c9 0f b6 c1 8a 0c 30 41 30 0c 24 4d 03 e3 4d 2b d3 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}