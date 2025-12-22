
rule Trojan_Win32_Radthief_LM_MTB{
	meta:
		description = "Trojan:Win32/Radthief.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 1e 33 d0 69 c2 65 89 07 6c 03 c1 89 44 8c 04 41 81 f9 70 02 00 00 72 ?? 8b 84 24 94 13 00 00 8d 0c 24 56 8b b4 24 94 13 00 00 35 00 00 00 80 81 f6 00 00 00 80 c7 44 24 04 70 02 00 00 2b c6 83 f8 ff } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}