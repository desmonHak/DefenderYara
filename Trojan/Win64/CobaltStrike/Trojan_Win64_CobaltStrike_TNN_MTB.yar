
rule Trojan_Win64_CobaltStrike_TNN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 06 32 1f 88 1c 06 40 47 29 d7 81 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}