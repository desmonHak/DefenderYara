
rule Trojan_BAT_QuasarRat_DKC_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.DKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 7e 5f 00 00 04 2c 07 7e 5f 00 00 04 2b 16 7e 5e 00 00 04 fe 06 e7 00 00 06 73 e7 00 00 0a 25 80 5f 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}