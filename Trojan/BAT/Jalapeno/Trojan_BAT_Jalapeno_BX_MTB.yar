
rule Trojan_BAT_Jalapeno_BX_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 59 7e 23 00 00 04 1f 66 95 5f 7e 23 00 00 04 1f 1a 95 61 59 80 17 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}