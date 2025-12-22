
rule Trojan_Win64_CobaltStrike_PSW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 1a 00 00 00 48 89 d3 f3 ab 48 8d 7c 24 50 b9 06 00 00 00 31 d2 f3 ab } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}