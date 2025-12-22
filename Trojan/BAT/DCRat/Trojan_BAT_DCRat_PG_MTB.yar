
rule Trojan_BAT_DCRat_PG_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 05 11 13 58 91 11 04 11 13 91 fe 01 16 fe 01 13 14 11 14 2c 06 00 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}