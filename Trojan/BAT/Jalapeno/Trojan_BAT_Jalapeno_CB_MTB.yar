
rule Trojan_BAT_Jalapeno_CB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 04 1f 19 62 61 13 04 11 0d 20 ee 09 c6 24 5a 20 c8 2c 31 c8 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}