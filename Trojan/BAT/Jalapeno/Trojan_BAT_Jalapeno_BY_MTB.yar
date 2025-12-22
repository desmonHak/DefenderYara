
rule Trojan_BAT_Jalapeno_BY_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 1a 8d 0b 00 00 01 0b 06 07 16 1a 6f 1d 00 00 0a 26 07 16 28 1c 00 00 0a 0c 06 16 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}