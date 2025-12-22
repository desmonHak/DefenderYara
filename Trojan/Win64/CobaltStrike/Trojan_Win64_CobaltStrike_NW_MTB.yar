
rule Trojan_Win64_CobaltStrike_NW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 15 3a 1c 00 00 89 d2 41 89 c0 48 8d 05 2e 1a 00 00 48 89 c1 e8 66 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}