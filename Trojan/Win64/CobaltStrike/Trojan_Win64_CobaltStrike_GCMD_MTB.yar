
rule Trojan_Win64_CobaltStrike_GCMD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GCMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c1 0f b6 4c 84 ?? 41 30 08 49 ff c0 49 83 eb 01 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}