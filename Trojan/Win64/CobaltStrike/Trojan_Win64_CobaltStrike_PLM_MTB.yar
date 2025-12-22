
rule Trojan_Win64_CobaltStrike_PLM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 48 8b 55 ?? 8b 45 ?? 48 01 d0 44 89 ca 31 ca 88 10 83 45 fc 01 8b 45 ?? 39 45 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}