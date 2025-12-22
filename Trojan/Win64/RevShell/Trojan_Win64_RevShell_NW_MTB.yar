
rule Trojan_Win64_RevShell_NW_MTB{
	meta:
		description = "Trojan:Win64/RevShell.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 45 a0 48 8d 15 d9 36 00 00 48 89 c1 e8 06 18 00 00 48 85 c0 75 30 48 8d 45 a0 48 8d 15 c6 36 00 00 48 89 c1 e8 ee 17 00 00 48 85 c0 75 18 48 8d 45 a0 48 8d 15 b5 36 00 00 48 89 c1 e8 d6 17 00 00 48 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}