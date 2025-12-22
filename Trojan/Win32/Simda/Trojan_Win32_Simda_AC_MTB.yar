
rule Trojan_Win32_Simda_AC_MTB{
	meta:
		description = "Trojan:Win32/Simda.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 ee 01 00 00 00 81 c7 01 00 00 00 81 eb 01 00 00 00 8b d7 43 8b c2 29 05 78 86 41 00 48 03 05 43 85 41 00 d1 c8 48 d1 c0 2b c6 8b d0 81 ea } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}