
rule Trojan_Win64_Radthief_ARDT_MTB{
	meta:
		description = "Trojan:Win64/Radthief.ARDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 74 24 ?? 48 89 c7 48 b8 9e ef a7 c6 4b 37 89 41 49 89 d0 48 f7 e9 48 c1 fa 07 48 69 d2 f4 01 00 00 49 89 c9 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}