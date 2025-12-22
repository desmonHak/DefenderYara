
rule Trojan_Win64_CobaltStrike_EF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 44 0f b6 00 48 8b 45 f8 83 e0 03 0f b6 4c 05 f4 48 8b 55 10 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 72 c4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}