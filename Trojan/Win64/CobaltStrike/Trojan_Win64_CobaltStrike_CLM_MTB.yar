
rule Trojan_Win64_CobaltStrike_CLM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 0f b6 04 10 45 31 c1 44 88 0c 3e 48 8d 57 ?? 48 89 f0 48 39 d3 7e ?? 4c 8b 05 ?? ?? ?? ?? 44 0f b6 0c 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}