
rule Trojan_Win64_CobaltStrike_SSG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 31 04 09 49 83 c1 04 8b 83 ?? 00 00 00 01 83 ?? 00 00 00 8b 43 10 29 83 ?? 00 00 00 8b 83 ?? 00 00 00 05 ba c5 1a 00 31 83 b4 00 00 00 49 81 f9 f4 e1 01 00 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}