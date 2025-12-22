
rule Trojan_BAT_Jalapeno_SLDV_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SLDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 13 04 02 7b 3a 00 00 04 17 19 6f 76 00 00 0a 6c 13 05 02 7b 39 00 00 04 73 ae 00 00 06 25 02 7b 3a 00 00 04 16 02 28 73 00 00 0a 0c 12 02 28 77 00 00 0a 6f 76 00 00 0a 6b 02 7b 3a 00 00 04 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}