
rule Trojan_Win64_Zusy_SLWF_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SLWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 74 24 28 45 33 c9 45 33 c0 c7 44 24 20 00 01 00 84 48 8b d3 48 8b c8 ff 15 ?? ?? 04 00 48 8b d8 48 85 c0 75 10 48 8b cf ff 15 ?? ?? 04 00 33 c0 e9 fd 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}