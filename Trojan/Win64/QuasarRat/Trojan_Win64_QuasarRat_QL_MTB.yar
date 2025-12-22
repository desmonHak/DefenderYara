
rule Trojan_Win64_QuasarRat_QL_MTB{
	meta:
		description = "Trojan:Win64/QuasarRat.QL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 40 48 89 48 08 48 c7 40 10 00 30 00 00 48 c7 40 18 40 00 00 00 48 89 c3 b9 04 00 00 00 48 89 cf 48 8b 44 24 78 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}