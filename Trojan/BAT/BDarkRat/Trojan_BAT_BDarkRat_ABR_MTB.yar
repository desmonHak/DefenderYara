
rule Trojan_BAT_BDarkRat_ABR_MTB{
	meta:
		description = "Trojan:BAT/BDarkRat.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 16 02 06 8f ?? 00 00 01 25 47 7e ?? 00 00 04 d2 61 d2 52 06 17 58 0a 06 02 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}